package gateway

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/Exonical/sigil/backend/gen/sigil/agent/v1"
	backendv1 "github.com/Exonical/sigil/backend/gen/sigil/backend/v1"
	"github.com/Exonical/sigil/backend/internal/audit"
	"github.com/Exonical/sigil/backend/internal/authn"
	"github.com/Exonical/sigil/backend/internal/config"
	"github.com/Exonical/sigil/backend/internal/db"
	"github.com/Exonical/sigil/backend/internal/signing"
	"github.com/Exonical/sigil/backend/internal/testdb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestGatewayMTLSOIDCGrantAndPolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	store := openGatewayTestStore(t)
	issuer := newGatewayTestIssuer(t)
	pki := newTestPKI(t)
	adminClientCert := pki.issueClient(t, "station-admin")
	userClientCert := pki.issueClient(t, "station-user")
	unregisteredClientCert := pki.issueClient(t, "station-unregistered")

	if err := addTestStation(ctx, store, "station-admin", "station", adminClientCert.Leaf); err != nil {
		t.Fatal(err)
	}
	if err := addTestStation(ctx, store, "station-user", "user", userClientCert.Leaf); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `
		INSERT INTO tokens(vendor, model, serial, status, last_station_id)
		VALUES('Yubico', 'YubiKey Test', '39192733', 'unassigned', 'station-admin')
	`); err != nil {
		t.Fatal(err)
	}
	keyPEM, _, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signingKeyPath := filepath.Join(t.TempDir(), "grant-private.pem")
	if err := os.WriteFile(signingKeyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := signing.NewFileSigner("gateway-test-key", signingKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := authn.New(ctx, authn.Config{
		Issuer: issuer.server.URL, Audience: "sigil-backend", GroupsClaim: "groups",
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		OIDC:   config.OIDC{RoleGroups: config.RoleGroups{Admin: []string{"admins"}}},
		Grants: config.Grants{LifetimeSeconds: 120},
	}
	service := New(store, authenticator, signer, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	tlsFiles := pki.writeServerFiles(t)
	server, err := NewGRPCServer(tlsFiles, service)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
		select {
		case err := <-serveErr:
			if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				t.Errorf("gateway server: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("gateway server did not stop")
		}
	})

	adminConn := dialGateway(t, listener.Addr().String(), pki.roots, &adminClientCert)
	defer adminConn.Close()
	adminClient := backendv1.NewAgentGatewayClient(adminConn)
	adminToken := issuer.token(t, "alice", []string{"admins"}, time.Now().Add(time.Hour))
	request := &backendv1.RequestGrantRequest{
		AccessToken:  adminToken,
		Operation:    agentv1.Operation_PIV_GENERATE_KEY,
		TokenVendor:  "Yubico",
		TokenSerial:  "39192733",
		CallerOsUser: "S-1-5-21-test",
		PivSlot:      0x9a,
	}
	response, err := adminClient.RequestGrant(ctx, request)
	if err != nil {
		t.Fatalf("authorized grant request: %v", err)
	}
	grant := new(agentv1.OperationGrant)
	if err := proto.Unmarshal(response.Grant.Grant, grant); err != nil {
		t.Fatal(err)
	}
	if grant.Version != 1 ||
		grant.Operation != agentv1.Operation_PIV_GENERATE_KEY ||
		grant.Subject != issuer.server.URL+"|alice" ||
		grant.StationId != "station-admin" ||
		grant.TokenSerial != "39192733" ||
		grant.CallerOsUser != request.CallerOsUser ||
		grant.PivSlot != request.PivSlot ||
		grant.ExpiresAtUnix-grant.NotBeforeUnix != 120 {
		t.Fatalf("unexpected grant fields: %+v", grant)
	}
	verifyGrantSignature(t, signerPublicKey(t, keyPEM), response.Grant)

	missingTokenRequest := &backendv1.RequestGrantRequest{
		AccessToken:  adminToken,
		Operation:    request.Operation,
		TokenVendor:  request.TokenVendor,
		TokenSerial:  "unknown-token",
		CallerOsUser: request.CallerOsUser,
		PivSlot:      request.PivSlot,
	}
	_, err = adminClient.RequestGrant(ctx, missingTokenRequest)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unknown token status = %v, want PermissionDenied", status.Code(err))
	}
	var missingTokenAuditCount int
	if err := store.Pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_events
		WHERE action='RequestGrant' AND outcome='denied'
		  AND detail->>'reason'='token is not in inventory'
	`).Scan(&missingTokenAuditCount); err != nil {
		t.Fatal(err)
	}
	if missingTokenAuditCount != 1 {
		t.Fatalf("unknown-token audit events=%d, want 1", missingTokenAuditCount)
	}

	_, err = adminClient.ReportTokens(ctx, &backendv1.ReportTokensRequest{
		Tokens: []*backendv1.ObservedToken{
			{Vendor: "Yubico", Model: "valid in batch", Serial: "report-valid-001"},
			{Vendor: "Yubico", Model: "invalid in batch", Serial: "  "},
		},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid report status = %v, want InvalidArgument", status.Code(err))
	}
	var insertedCount int
	if err := store.Pool.QueryRow(ctx, `
		SELECT count(*) FROM tokens WHERE serial IN ('report-valid-001', '  ')
	`).Scan(&insertedCount); err != nil {
		t.Fatal(err)
	}
	if insertedCount != 0 {
		t.Fatalf("invalid report inserted %d token(s)", insertedCount)
	}
	var deniedReports, detailedDenials int
	if err := store.Pool.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE detail - 'reason' <> '{}'::jsonb)
		FROM audit_events
		WHERE action='ReportTokens' AND outcome='denied'
		  AND detail->>'reason'='token vendor and serial are required'
	`).Scan(&deniedReports, &detailedDenials); err != nil {
		t.Fatal(err)
	}
	if deniedReports != 1 || detailedDenials != 0 {
		t.Fatalf("invalid report audits=%d detailed=%d, want one reason-only event", deniedReports, detailedDenials)
	}

	unregisteredConn := dialGateway(t, listener.Addr().String(), pki.roots, &unregisteredClientCert)
	unregisteredClient := backendv1.NewAgentGatewayClient(unregisteredConn)
	_, err = unregisteredClient.RequestGrant(ctx, request)
	_ = unregisteredConn.Close()
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unregistered station status = %v, want Unauthenticated", status.Code(err))
	}

	noCertificateConn, dialErr := dialGatewayWithoutCertificate(t, listener.Addr().String(), pki.roots)
	if dialErr == nil {
		_, callErr := backendv1.NewAgentGatewayClient(noCertificateConn).RequestGrant(ctx, request)
		_ = noCertificateConn.Close()
		if callErr == nil {
			t.Fatal("grant request without a client certificate unexpectedly succeeded")
		}
	}

	userConn := dialGateway(t, listener.Addr().String(), pki.roots, &userClientCert)
	defer userConn.Close()
	userClient := backendv1.NewAgentGatewayClient(userConn)
	userToken := issuer.token(t, "bob", []string{"users"}, time.Now().Add(time.Hour))
	deniedRequest := &backendv1.RequestGrantRequest{
		AccessToken:  userToken,
		Operation:    request.Operation,
		TokenVendor:  request.TokenVendor,
		TokenSerial:  request.TokenSerial,
		CallerOsUser: request.CallerOsUser,
		PivSlot:      request.PivSlot,
	}
	_, err = userClient.RequestGrant(ctx, deniedRequest)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("policy denial status = %v, want PermissionDenied", status.Code(err))
	}
	var deniedCount int
	if err := store.Pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_events
		WHERE action='RequestGrant' AND outcome='denied'
		  AND detail->>'reason'='user is not authorized for this operation on this token'
	`).Scan(&deniedCount); err != nil {
		t.Fatal(err)
	}
	if deniedCount != 1 {
		t.Fatalf("policy-denial audit events=%d, want 1", deniedCount)
	}
	if err := audit.Verify(ctx, store.Pool); err != nil {
		t.Fatal(err)
	}
}

func openGatewayTestStore(t *testing.T) *db.Store {
	t.Helper()
	store, cleanup, err := testdb.Open(context.Background())
	if errors.Is(err, testdb.ErrNotConfigured) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	return store
}

func addTestStation(ctx context.Context, store *db.Store, id, mode string, certificate *x509.Certificate) error {
	spki, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(spki)
	tx, err := store.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	if err := store.AddStation(ctx, tx, db.Station{ID: id, DisplayName: id, Mode: mode}, hash[:]); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

func dialGateway(t *testing.T, address string, roots *x509.CertPool, certificate *tls.Certificate) *grpc.ClientConn {
	t.Helper()
	connection, err := grpc.NewClient(
		address,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion:   tls.VersionTLS13,
			ServerName:   "localhost",
			RootCAs:      roots,
			Certificates: []tls.Certificate{*certificate},
		})),
	)
	if err != nil {
		t.Fatalf("dial mTLS gateway: %v", err)
	}
	return connection
}

func dialGatewayWithoutCertificate(t *testing.T, address string, roots *x509.CertPool) (*grpc.ClientConn, error) {
	t.Helper()
	return grpc.NewClient(
		address,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS13,
			ServerName: "localhost",
			RootCAs:    roots,
		})),
	)
}

type testPKI struct {
	ca      *x509.Certificate
	caKey   *rsa.PrivateKey
	roots   *x509.CertPool
	counter int64
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Sigil test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return &testPKI{ca: ca, caKey: caKey, roots: roots, counter: 2}
}

func (p *testPKI) issueClient(t *testing.T, commonName string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := p.issueLeaf(commonName, key, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
}

func (p *testPKI) writeServerFiles(t *testing.T) config.TLS {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := p.issueLeaf("localhost", key, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certPath := filepath.Join(directory, "server.crt")
	keyPath := filepath.Join(directory, "server.key")
	caPath := filepath.Join(directory, "client-ca.crt")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.ca.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	return config.TLS{CertFile: certPath, KeyFile: keyPath, ClientCAFile: caPath}
}

func (p *testPKI) issueLeaf(commonName string, key *ecdsa.PrivateKey, usages []x509.ExtKeyUsage, dnsNames []string) (*x509.Certificate, error) {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(p.counter),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  usages,
		DNSNames:     dnsNames,
	}
	p.counter++
	der, err := x509.CreateCertificate(rand.Reader, template, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

type oidcTestIssuer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
}

func newGatewayTestIssuer(t *testing.T) *oidcTestIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &oidcTestIssuer{key: key}
	issuer.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                issuer.server.URL,
				"jwks_uri":                              issuer.server.URL + "/jwks",
				"authorization_endpoint":                issuer.server.URL + "/authorize",
				"token_endpoint":                        issuer.server.URL + "/token",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]string{{
					"kty": "RSA",
					"use": "sig",
					"alg": "RS256",
					"kid": "test-key",
					"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(issuer.server.Close)
	return issuer
}

func (i *oidcTestIssuer) token(t *testing.T, subject string, groups []string, expiry time.Time) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "test-key"})
	payload, _ := json.Marshal(map[string]any{
		"iss":    i.server.URL,
		"aud":    "sigil-backend",
		"sub":    subject,
		"email":  subject + "@example.test",
		"name":   subject,
		"groups": groups,
		"iat":    time.Now().Add(-time.Minute).Unix(),
		"exp":    expiry.Unix(),
	})
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func verifyGrantSignature(t *testing.T, key *ecdsa.PublicKey, signed *agentv1.SignedGrant) {
	t.Helper()
	var signature struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(signed.Signature, &signature)
	if err != nil || len(rest) != 0 || signature.R == nil || signature.S == nil {
		t.Fatalf("invalid grant DER signature: %v", err)
	}
	digest := sha256.Sum256(signed.Grant)
	if !ecdsa.Verify(key, digest[:], signature.R, signature.S) {
		t.Fatal("grant signature did not verify")
	}
}

func signerPublicKey(t *testing.T, privatePEM []byte) *ecdsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode(privatePEM)
	if block == nil {
		t.Fatal("generated signing key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("generated signing key is not ECDSA")
	}
	return &key.PublicKey
}

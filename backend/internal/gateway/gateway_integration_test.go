package gateway

import (
	"bytes"
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
	"strings"
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
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const managedTestSerial = "managed-token-1"

func TestGatewayMTLSOIDCGrantAndPolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	store := openGatewayTestStore(t)
	issuer := newGatewayTestIssuer(t)
	pki := newTestPKI(t)
	adminClientCert := pki.issueClient(t, "ignored-admin-cn", []string{"station-admin.example.test"})
	userClientCert := pki.issueClient(t, "ignored-user-cn", []string{"station-user.example.test"})
	unregisteredClientCert := pki.issueClient(t, "station-unregistered", []string{"unregistered.example.test"})

	if err := addTestStation(ctx, store, "station-admin", "station-admin.example.test", "station"); err != nil {
		t.Fatal(err)
	}
	if err := addTestStation(ctx, store, "station-user", "station-user.example.test", "user"); err != nil {
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
		Operation:    agentv1.Operation_PIV_SET_RETRIES,
		TokenVendor:  "Yubico",
		TokenSerial:  "39192733",
		CallerOsUser: "S-1-5-21-test",
		PivSlot:      0,
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
		grant.Operation != agentv1.Operation_PIV_SET_RETRIES ||
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

func TestAuthenticatedStationUsesOnlyUniqueActiveDNSSANs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	store := openGatewayTestStore(t)
	pki := newTestPKI(t)
	service := &Server{store: store}

	validCert := pki.issueClient(t, "ignored-common-name", []string{"VALID.example.test"})
	if err := addTestStation(ctx, store, "station-valid", "valid.example.test", "station"); err != nil {
		t.Fatal(err)
	}
	station, actorID, err := service.authenticatedStation(contextForPeerCertificate(validCert.Leaf))
	if err != nil {
		t.Fatalf("SAN-matched station authentication: %v", err)
	}
	if station.ID != "station-valid" || len(actorID) != sha256.Size*2 {
		t.Fatalf("unexpected station identity: station=%+v actor=%q", station, actorID)
	}

	for _, stationInfo := range []struct {
		id      string
		dnsName string
	}{
		{id: "station-a", dnsName: "a.example.test"},
		{id: "station-b", dnsName: "b.example.test"},
		{id: "station-disabled", dnsName: "disabled.example.test"},
		{id: "station-cn-only", dnsName: "cn-only.example.test"},
	} {
		if err := addTestStation(ctx, store, stationInfo.id, stationInfo.dnsName, "station"); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := store.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DisableStation(ctx, tx, "station-disabled"); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	ambiguousCert := pki.issueClient(t, "ignored-ambiguous-cn", []string{"a.example.test", "b.example.test"})
	disabledCert := pki.issueClient(t, "disabled.example.test", []string{"disabled.example.test"})
	cnOnlyCert := pki.issueClient(t, "cn-only.example.test", nil)
	for name, certificate := range map[string]tls.Certificate{
		"ambiguous DNS SANs": ambiguousCert,
		"disabled DNS SAN":   disabledCert,
		"CN-only":            cnOnlyCert,
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := service.authenticatedStation(contextForPeerCertificate(certificate.Leaf))
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("station authentication status = %v, want Unauthenticated", status.Code(err))
			}
		})
	}

	rows, err := store.Pool.Query(ctx, `
		SELECT detail::text
		FROM audit_events
		WHERE action='AuthenticateStation'
		ORDER BY seq
	`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var audited int
	for rows.Next() {
		var encoded string
		if err := rows.Scan(&encoded); err != nil {
			t.Fatal(err)
		}
		var detail map[string]any
		if err := json.Unmarshal([]byte(encoded), &detail); err != nil {
			t.Fatal(err)
		}
		serial, serialOK := detail["certificate_serial"].(string)
		spki, spkiOK := detail["spki_sha256"].(string)
		if !serialOK || serial == "" || !spkiOK || len(spki) != sha256.Size*2 {
			t.Fatalf("station audit omitted certificate evidence: %#v", detail)
		}
		audited++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if audited != 4 {
		t.Fatalf("station authentication audit rows = %d, want 4", audited)
	}
	if err := audit.Verify(ctx, store.Pool); err != nil {
		t.Fatal(err)
	}
}

func TestManagedEscrowRotationsAndStationAuditCursor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store := openGatewayTestStore(t)
	issuer := newGatewayTestIssuer(t)
	pki := newTestPKI(t)
	adminCertificate := pki.issueClient(t, "ignored-admin-cn", []string{"station-admin.example.test"})
	secondCertificate := pki.issueClient(t, "ignored-second-cn", []string{"station-second.example.test"})
	if err := addTestStation(ctx, store, "station-admin", "station-admin.example.test", "station"); err != nil {
		t.Fatal(err)
	}
	if err := addTestStation(ctx, store, "station-second", "station-second.example.test", "station"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `
		INSERT INTO tokens(vendor, model, serial, status, last_station_id)
		VALUES
			('Yubico', 'YubiKey Test', 'managed-token-1', 'unassigned', 'station-admin'),
			('Yubico', 'YubiKey Test', 'missing-escrow', 'unassigned', 'station-admin')
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
	signer, err := signing.NewFileSigner("managed-test-key", signingKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := authn.New(ctx, authn.Config{
		Issuer: issuer.server.URL, Audience: "sigil-backend", GroupsClaim: "groups",
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	var logOutput bytes.Buffer
	service := New(store, authenticator, signer, config.Config{
		OIDC:   config.OIDC{RoleGroups: config.RoleGroups{Admin: []string{"admins"}}},
		Grants: config.Grants{LifetimeSeconds: 120},
		Escrow: config.Escrow{KEKID: "test-kek", CurrentKey: bytes.Repeat([]byte{0x5c}, 32)},
	}, slog.New(slog.NewTextHandler(&logOutput, nil)))
	defer service.Close()

	grpcServer, err := NewGRPCServer(pki.writeServerFiles(t), service)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- grpcServer.Serve(listener) }()
	t.Cleanup(func() {
		grpcServer.Stop()
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

	adminConn := dialGateway(t, listener.Addr().String(), pki.roots, &adminCertificate)
	defer adminConn.Close()
	adminClient := backendv1.NewAgentGatewayClient(adminConn)
	secondConn := dialGateway(t, listener.Addr().String(), pki.roots, &secondCertificate)
	defer secondConn.Close()
	secondClient := backendv1.NewAgentGatewayClient(secondConn)
	adminToken := issuer.token(t, "managed-admin", []string{"admins"}, time.Now().Add(time.Hour))

	authorize := func(operation agentv1.Operation, serial string, slot uint32) (*backendv1.AuthorizeManagedOperationResponse, error) {
		return adminClient.AuthorizeManagedOperation(ctx, &backendv1.AuthorizeManagedOperationRequest{
			AccessToken: adminToken, Operation: operation, TokenVendor: "Yubico",
			TokenSerial: serial, CallerOsUser: "S-1-5-21-test", PivSlot: slot,
		})
	}
	complete := func(client backendv1.AgentGatewayClient, rotationID string, applied bool) error {
		_, err := client.CompleteRotation(ctx, &backendv1.CompleteRotationRequest{
			RotationId: rotationID, Applied: applied,
		})
		return err
	}

	initialized, err := authorize(agentv1.Operation_PIV_MANAGED_INITIALIZE, managedTestSerial, 0)
	if err != nil {
		t.Fatalf("managed initialization: %v", err)
	}
	if initialized.RotationId == "" || initialized.CurrentPuk != nil || initialized.CurrentManagementKey != nil {
		t.Fatalf("unexpected initialization material: rotation=%q", initialized.RotationId)
	}
	if initialized.NewPuk == nil || len(initialized.NewPuk.Value) != 8 || initialized.NewPuk.Algorithm != "" ||
		initialized.NewManagementKey == nil || len(initialized.NewManagementKey.Value) != 32 ||
		initialized.NewManagementKey.Algorithm != "aes256" {
		t.Fatal("managed initialization did not return both required secrets")
	}
	firstPUK := bytes.Clone(initialized.NewPuk.Value)
	firstManagementKey := bytes.Clone(initialized.NewManagementKey.Value)
	if err := complete(adminClient, initialized.RotationId, true); err != nil {
		t.Fatalf("complete initialization: %v", err)
	}
	for _, kind := range []string{managedPUK, managedManagementKey} {
		if state := escrowState(ctx, t, store, managedTestSerial, kind, initialized.RotationId); state != "active" {
			t.Fatalf("initialized %s state = %q, want active", kind, state)
		}
	}
	reinitialized, err := authorize(agentv1.Operation_PIV_MANAGED_INITIALIZE, managedTestSerial, 0)
	if err != nil {
		t.Fatalf("reinitialize managed token: %v", err)
	}
	if reinitialized.RotationId == "" || reinitialized.CurrentPuk != nil || reinitialized.CurrentManagementKey != nil ||
		reinitialized.NewPuk == nil || len(reinitialized.NewPuk.Value) != 8 ||
		reinitialized.NewManagementKey == nil || len(reinitialized.NewManagementKey.Value) != 32 {
		t.Fatal("reinitialization returned unexpected escrow material")
	}
	var encoded string
	var rotationDetail map[string]any
	if err := store.Pool.QueryRow(ctx, `
		SELECT detail::text
		FROM audit_events
		WHERE action='BeginRotation' AND target_id=$1 AND detail->>'rotation_id'=$2
	`, managedTestSerial, reinitialized.RotationId).Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(encoded), &rotationDetail); err != nil {
		t.Fatal(err)
	}
	previousActiveVersions, ok := rotationDetail["previous_active_versions"].(map[string]any)
	if !ok || previousActiveVersions[managedPUK] != float64(1) ||
		previousActiveVersions[managedManagementKey] != float64(1) {
		t.Fatalf("reinitialization audit omitted previous active versions: %#v", rotationDetail)
	}
	if err := complete(adminClient, reinitialized.RotationId, true); err != nil {
		t.Fatalf("complete reinitialization: %v", err)
	}
	for _, kind := range []string{managedPUK, managedManagementKey} {
		if state := escrowState(ctx, t, store, managedTestSerial, kind, initialized.RotationId); state != "superseded" {
			t.Fatalf("previous initialized %s state = %q, want superseded", kind, state)
		}
		if state := escrowState(ctx, t, store, managedTestSerial, kind, reinitialized.RotationId); state != "active" {
			t.Fatalf("reinitialized %s state = %q, want active", kind, state)
		}
	}
	initialPUK := bytes.Clone(reinitialized.NewPuk.Value)
	initialManagementKey := bytes.Clone(reinitialized.NewManagementKey.Value)
	_, err = adminClient.RequestGrant(ctx, &backendv1.RequestGrantRequest{
		AccessToken: adminToken, Operation: agentv1.Operation_PIV_GENERATE_KEY,
		TokenVendor: "Yubico", TokenSerial: managedTestSerial, CallerOsUser: "S-1-5-21-test",
		PivSlot: 0x9a,
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("grant-only managed operation status = %v, want FailedPrecondition", status.Code(err))
	}

	managedKeyGrant, err := authorize(agentv1.Operation_PIV_GENERATE_KEY, managedTestSerial, 0x9a)
	if err != nil {
		t.Fatalf("release current management key: %v", err)
	}
	if managedKeyGrant.RotationId != "" || managedKeyGrant.CurrentManagementKey == nil ||
		!bytes.Equal(managedKeyGrant.CurrentManagementKey.Value, initialManagementKey) {
		t.Fatal("managed operation did not release the active management key")
	}

	abandoned, err := authorize(agentv1.Operation_PIV_CHANGE_MANAGEMENT_KEY, managedTestSerial, 0)
	if err != nil {
		t.Fatalf("begin management-key rotation: %v", err)
	}
	if abandoned.CurrentManagementKey == nil || !bytes.Equal(abandoned.CurrentManagementKey.Value, initialManagementKey) ||
		abandoned.NewManagementKey == nil || bytes.Equal(abandoned.NewManagementKey.Value, initialManagementKey) {
		t.Fatal("management-key rotation did not return active and new keys")
	}
	abandonedValue := bytes.Clone(abandoned.NewManagementKey.Value)
	if err := complete(adminClient, abandoned.RotationId, false); err != nil {
		t.Fatalf("abandon management-key rotation: %v", err)
	}
	if state := escrowState(ctx, t, store, managedTestSerial, managedManagementKey, abandoned.RotationId); state != "abandoned" {
		t.Fatalf("abandoned rotation state = %q", state)
	}
	afterAbandon, err := authorize(agentv1.Operation_PIV_GENERATE_KEY, managedTestSerial, 0x9a)
	if err != nil {
		t.Fatalf("release active key after abandonment: %v", err)
	}
	if !bytes.Equal(afterAbandon.CurrentManagementKey.Value, initialManagementKey) {
		t.Fatal("abandoned rotation replaced the active management key")
	}

	oldPending, err := authorize(agentv1.Operation_PIV_CHANGE_MANAGEMENT_KEY, managedTestSerial, 0)
	if err != nil {
		t.Fatalf("begin first pending rotation: %v", err)
	}
	newPending, err := authorize(agentv1.Operation_PIV_CHANGE_MANAGEMENT_KEY, managedTestSerial, 0)
	if err != nil {
		t.Fatalf("begin second pending rotation: %v", err)
	}
	if state := escrowState(ctx, t, store, managedTestSerial, managedManagementKey, oldPending.RotationId); state != "unconfirmed" {
		t.Fatalf("previous pending rotation state = %q, want unconfirmed", state)
	}
	if state := escrowState(ctx, t, store, managedTestSerial, managedManagementKey, newPending.RotationId); state != "pending" {
		t.Fatalf("new pending rotation state = %q, want pending", state)
	}
	if err := complete(adminClient, oldPending.RotationId, true); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("complete unconfirmed rotation status = %v, want FailedPrecondition", status.Code(err))
	}

	service.now = func() time.Time { return time.Now().Add(16 * time.Minute) }
	if err := complete(adminClient, newPending.RotationId, true); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("complete expired rotation status = %v, want FailedPrecondition", status.Code(err))
	}
	if state := escrowState(ctx, t, store, managedTestSerial, managedManagementKey, newPending.RotationId); state != "unconfirmed" {
		t.Fatalf("expired rotation state = %q, want unconfirmed", state)
	}
	service.now = time.Now

	pukRotation, err := authorize(agentv1.Operation_PIV_CHANGE_PUK, managedTestSerial, 0)
	if err != nil {
		t.Fatalf("begin PUK rotation: %v", err)
	}
	if err := complete(secondClient, pukRotation.RotationId, false); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("other station completion status = %v, want PermissionDenied", status.Code(err))
	}
	if err := complete(adminClient, pukRotation.RotationId, false); err != nil {
		t.Fatalf("abandon PUK rotation from originating station: %v", err)
	}
	if err := complete(adminClient, pukRotation.RotationId, false); err != nil {
		t.Fatalf("repeat completed rotation: %v", err)
	}
	afterPukAbandon, err := authorize(agentv1.Operation_PIV_UNBLOCK_PIN, managedTestSerial, 0)
	if err != nil {
		t.Fatalf("release active PUK after abandonment: %v", err)
	}
	if afterPukAbandon.CurrentPuk == nil || !bytes.Equal(afterPukAbandon.CurrentPuk.Value, initialPUK) {
		t.Fatal("abandoned PUK rotation replaced the active PUK")
	}

	_, err = authorize(agentv1.Operation_PIV_GENERATE_KEY, "missing-escrow", 0x9a)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(status.Convert(err).Message(), "token is not managed by Sigil") {
		t.Fatalf("missing active escrow status = %v", status.Code(err))
	}
	_, err = authorize(agentv1.Operation_PIV_SET_RETRIES, managedTestSerial, 0)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("managed PIV_SET_RETRIES status = %v, want InvalidArgument", status.Code(err))
	}

	auditEvents := []*backendv1.AgentAuditEvent{
		{
			Sequence: 1, OccurredAtUnixMs: time.Now().UnixMilli(), Rpc: "GetPivInfo",
			Operation: "PIV_INSPECT", DeviceId: "windows-pcsc:reader", TokenSerial: managedTestSerial,
			CallerOsUser: "S-1-5-21-test", CallerSessionId: 1, Outcome: "success",
		},
		{
			Sequence: 2, OccurredAtUnixMs: time.Now().UnixMilli(), Rpc: "GeneratePivKey",
			Operation: "PIV_GENERATE_KEY", DeviceId: "windows-pcsc:reader", TokenSerial: managedTestSerial,
			CallerOsUser: "S-1-5-21-test", CallerSessionId: 1, Outcome: "error", Code: "CARD_STATUS",
			GrantId: "audit-test-grant-id", RotationId: "audit-test-rotation-id",
		},
	}
	reported, err := adminClient.ReportAudit(ctx, &backendv1.ReportAuditRequest{Events: auditEvents})
	if err != nil {
		t.Fatalf("report agent audit events: %v", err)
	}
	if reported.AcceptedThrough != 2 {
		t.Fatalf("accepted audit sequence = %d, want 2", reported.AcceptedThrough)
	}
	duplicate, err := adminClient.ReportAudit(ctx, &backendv1.ReportAuditRequest{Events: auditEvents})
	if err != nil {
		t.Fatalf("report duplicate agent audit events: %v", err)
	}
	if duplicate.AcceptedThrough != 2 {
		t.Fatalf("duplicate accepted sequence = %d, want 2", duplicate.AcceptedThrough)
	}
	var importedAuditCount int
	if err := store.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action LIKE 'Agent.%'`).Scan(&importedAuditCount); err != nil {
		t.Fatal(err)
	}
	if importedAuditCount != 2 {
		t.Fatalf("agent audit rows = %d, want 2", importedAuditCount)
	}
	if err := audit.Verify(ctx, store.Pool); err != nil {
		t.Fatal(err)
	}
	var managedAuditHasIds bool

	var details []string
	rows, err := store.Pool.Query(ctx, `SELECT detail::text FROM audit_events`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	secretValues := [][]byte{
		firstPUK, firstManagementKey, initialPUK, initialManagementKey, abandonedValue,
		initialized.NewPuk.Value, initialized.NewManagementKey.Value,
		reinitialized.NewPuk.Value, reinitialized.NewManagementKey.Value,
		abandoned.NewManagementKey.Value, oldPending.NewManagementKey.Value,
		newPending.NewManagementKey.Value, pukRotation.NewPuk.Value,
	}
	for _, detail := range details {
		if strings.Contains(detail, "audit-test-grant-id") && strings.Contains(detail, "audit-test-rotation-id") {
			managedAuditHasIds = true
		}
		for _, secret := range secretValues {
			if bytes.Contains([]byte(detail), secret) {
				t.Fatal("audit details contain a secret value")
			}
		}
	}
	if !managedAuditHasIds {
		t.Fatal("reported managed audit event is missing its grant and rotation IDs")
	}
	for _, secret := range secretValues {
		if bytes.Contains(logOutput.Bytes(), secret) {
			t.Fatal("server logs contain a secret value")
		}
	}
}

func contextForPeerCertificate(certificate *x509.Certificate) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{certificate},
		}},
	})
}

func escrowState(ctx context.Context, t *testing.T, store *db.Store, serial, kind, grantID string) string {
	t.Helper()
	var state string
	if err := store.Pool.QueryRow(ctx, `
		SELECT escrowed_secrets.state
		FROM escrowed_secrets
		JOIN tokens ON tokens.id=escrowed_secrets.token_id
		WHERE tokens.serial=$1 AND escrowed_secrets.kind=$2 AND escrowed_secrets.grant_id=$3
	`, serial, kind, grantID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
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

func addTestStation(ctx context.Context, store *db.Store, id, dnsName, mode string) error {
	tx, err := store.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	if err := store.AddStation(ctx, tx, db.Station{
		ID: id, DNSName: dnsName, DisplayName: id, Mode: mode,
	}); err != nil {
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

func (p *testPKI) issueClient(t *testing.T, commonName string, dnsNames []string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := p.issueLeaf(commonName, key, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, dnsNames)
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

package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func newP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func makeCSR(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "ignored by the backend"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// fakeStepCA verifies the provisioner token exactly as step-ca does for JWK provisioners and issues a
// leaf for the CSR's public key with the subject and SANs from the token.
type fakeStepCA struct {
	t           *testing.T
	provisioner *ecdsa.PublicKey
	caKey       *ecdsa.PrivateKey
	caCert      *x509.Certificate
	audience    string
	provider    string
	lastSANs    []string
	lastSubject string
}

func (f *fakeStepCA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CSR string `json:"csr"`
		OTT string `json:"ott"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	token, err := jwt.ParseSigned(body.OTT, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		http.Error(w, "bad token", http.StatusUnauthorized)
		return
	}
	var claims struct {
		jwt.Claims
		SANs []string `json:"sans"`
	}
	if err := token.Claims(f.provisioner, &claims); err != nil {
		http.Error(w, "token signature rejected", http.StatusUnauthorized)
		return
	}
	if err := claims.ValidateWithLeeway(jwt.Expected{Issuer: f.provider, AnyAudience: jwt.Audience{f.audience}, Time: time.Now()}, time.Minute); err != nil {
		http.Error(w, "token claims rejected", http.StatusUnauthorized)
		return
	}
	f.lastSubject, f.lastSANs = claims.Subject, claims.SANs
	block, _ := pem.Decode([]byte(body.CSR))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		http.Error(w, "bad csr", http.StatusBadRequest)
		return
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: claims.Subject},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	for _, san := range claims.SANs {
		if strings.Contains(san, "@") {
			template.EmailAddresses = append(template.EmailAddresses, san)
		} else {
			template.DNSNames = append(template.DNSNames, san)
		}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, template, f.caCert, csr.PublicKey, f.caKey)
	if err != nil {
		http.Error(w, "sign failed", http.StatusInternalServerError)
		return
	}
	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.caCert.Raw})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"crt":       string(leaf),
		"ca":        string(ca),
		"certChain": []string{string(leaf), string(ca)},
	})
}

type fixture struct {
	server      *httptest.Server
	fake        *fakeStepCA
	provisioner *ecdsa.PrivateKey
	rootPEM     []byte
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	caKey := newP256(t)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	provisioner := newP256(t)
	fake := &fakeStepCA{t: t, provisioner: &provisioner.PublicKey, caKey: caKey, caCert: caCert, provider: "sigil-backend"}
	// Each fixture gets its own TLS identity; httptest's built-in certificate is shared by all servers.
	tlsKey := newP256(t)
	tlsTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour * 24),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	tlsDER, err := x509.CreateCertificate(rand.Reader, tlsTemplate, tlsTemplate, &tlsKey.PublicKey, tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(fake)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{tlsDER}, PrivateKey: tlsKey}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	fake.audience = server.URL + "/1.0/sign"
	return fixture{server: server, fake: fake, provisioner: provisioner, rootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsDER})}
}
func (f fixture) client(t *testing.T, key *ecdsa.PrivateKey) *Step {
	t.Helper()
	client, err := NewStep(StepConfig{
		URL:         f.server.URL,
		RootPEM:     f.rootPEM,
		Provisioner: "sigil-backend",
		Key:         jose.JSONWebKey{Key: key, KeyID: "kid-1", Algorithm: string(jose.ES256)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestStepSignIssuesTheCertificateForTheTokenSubjectAndSANs(t *testing.T) {
	f := newFixture(t)
	subjectKey := newP256(t)
	client := f.client(t, f.provisioner)
	chain, err := client.Sign(context.Background(), makeCSR(t, subjectKey), SignRequest{
		Subject:        "alice",
		DNSNames:       []string{"alice.example.test"},
		EmailAddresses: []string{"alice@example.test"},
		NotAfter:       time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "alice" {
		t.Fatalf("subject CN = %q, want the token subject", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 1 || len(leaf.EmailAddresses) != 1 {
		t.Fatalf("SANs = %v %v", leaf.DNSNames, leaf.EmailAddresses)
	}
	if !leaf.PublicKey.(*ecdsa.PublicKey).Equal(&subjectKey.PublicKey) {
		t.Fatal("issued certificate does not carry the CSR public key")
	}
	if len(chain) != 2 {
		t.Fatalf("chain length = %d, want leaf and CA", len(chain))
	}
}

func TestStepSignRejectsAnUntrustedProvisionerKey(t *testing.T) {
	f := newFixture(t)
	client := f.client(t, newP256(t))
	if _, err := client.Sign(context.Background(), makeCSR(t, newP256(t)), SignRequest{Subject: "alice", NotAfter: time.Now().Add(time.Hour)}); err == nil {
		t.Fatal("a token signed by the wrong provisioner key must be rejected")
	}
}

func TestStepSignRejectsAnInvalidCSRBeforeCallingTheCA(t *testing.T) {
	f := newFixture(t)
	client := f.client(t, f.provisioner)
	csr := makeCSR(t, newP256(t))
	csr[len(csr)-1] ^= 0xff
	if _, err := client.Sign(context.Background(), csr, SignRequest{Subject: "alice", NotAfter: time.Now().Add(time.Hour)}); err == nil {
		t.Fatal("a CSR with an invalid signature must be rejected")
	}
	if f.fake.lastSubject != "" {
		t.Fatal("the CA must not be called for an invalid CSR")
	}
}

func TestStepClientTrustsOnlyTheConfiguredRoot(t *testing.T) {
	f := newFixture(t)
	other := newFixture(t)
	client, err := NewStep(StepConfig{
		URL:         f.server.URL,
		RootPEM:     other.rootPEM,
		Provisioner: "sigil-backend",
		Key:         jose.JSONWebKey{Key: f.provisioner, KeyID: "kid-1", Algorithm: string(jose.ES256)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Sign(context.Background(), makeCSR(t, newP256(t)), SignRequest{Subject: "alice", NotAfter: time.Now().Add(time.Hour)}); err == nil {
		t.Fatal("an untrusted CA endpoint must be rejected")
	}
}

func TestLoadProvisionerKeyDecryptsWithThePasswordOnly(t *testing.T) {
	key := newP256(t)
	jwk := jose.JSONWebKey{Key: key, KeyID: "kid-1", Algorithm: string(jose.ES256)}
	plaintext, err := jwk.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("correct horse battery staple")
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{
		Algorithm:  jose.PBES2_HS256_A128KW,
		Key:        password,
		PBES2Count: 1000,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	object, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	encoded := object.FullSerialize()
	loaded, err := LoadProvisionerKey([]byte(encoded), password)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.KeyID != "kid-1" {
		t.Fatalf("kid = %q", loaded.KeyID)
	}
	if _, err := LoadProvisionerKey([]byte(encoded), []byte("wrong")); err == nil {
		t.Fatal("a wrong password must not decrypt the key")
	}
}

package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
)

var (
	oidSCEPMessageType    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 2}
	oidSCEPPKIStatus      = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 3}
	oidSCEPFailInfo       = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 4}
	oidSCEPSenderNonce    = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 5}
	oidSCEPRecipientNonce = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 6}
	oidSCEPTransactionID  = asn1.ObjectIdentifier{2, 16, 840, 1, 113733, 1, 9, 7}
	oidExtensionRequest   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
	oidSubjectAltName     = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidECDSAWithSHA256    = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

type scepCSRAttribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

type scepCSRInfo struct {
	Version    int
	Subject    asn1.RawValue
	PublicKey  asn1.RawValue
	Attributes []scepCSRAttribute `asn1:"tag:0"`
}

type scepCSRDER struct {
	Info      asn1.RawValue
	Algorithm pkix.AlgorithmIdentifier
	Signature asn1.BitString
}

// scepCSR builds an ECDSA P-256 CSR with the common name, an optional email SAN, and an optional challengePassword.
func scepCSR(t *testing.T, key *ecdsa.PrivateKey, commonName, email, challenge string) []byte {
	t.Helper()
	subject, err := asn1.Marshal(pkix.Name{CommonName: commonName}.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var attributes []scepCSRAttribute
	if email != "" {
		san, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 1, Bytes: []byte(email)}})
		if err != nil {
			t.Fatal(err)
		}
		extensions, err := asn1.Marshal([]pkix.Extension{{Id: oidSubjectAltName, Value: san}})
		if err != nil {
			t.Fatal(err)
		}
		attributes = append(attributes, scepCSRAttribute{Type: oidExtensionRequest, Values: []asn1.RawValue{{FullBytes: extensions}}})
	}
	if challenge != "" {
		password, err := asn1.Marshal(challenge)
		if err != nil {
			t.Fatal(err)
		}
		attributes = append(attributes, scepCSRAttribute{Type: oidChallengePassword, Values: []asn1.RawValue{{FullBytes: password}}})
	}
	info, err := asn1.Marshal(scepCSRInfo{
		Subject:    asn1.RawValue{FullBytes: subject},
		PublicKey:  asn1.RawValue{FullBytes: spki},
		Attributes: attributes,
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(info)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	csr, err := asn1.Marshal(scepCSRDER{
		Info:      asn1.RawValue{FullBytes: info},
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256},
		Signature: asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// scepTestPKI is a CA hierarchy shaped like step-ca's SCEP setup: an EC intermediate issues an RSA decrypter that
// decrypts PKCSReq and signs CertRep. The RA is a separate RSA certificate that is not issued by the CA.
type scepTestPKI struct {
	root, intermediate, decrypter, ra *x509.Certificate
	rootKey, intermediateKey          *ecdsa.PrivateKey
	decrypterKey, raKey               *rsa.PrivateKey
	serverKey                         *ecdsa.PrivateKey
	server                            *x509.Certificate
}

func newSCEPTestPKI(t *testing.T) *scepTestPKI {
	t.Helper()
	now := time.Now()
	p := &scepTestPKI{rootKey: newP256(t), intermediateKey: newP256(t), serverKey: newP256(t)}
	var err error
	if p.decrypterKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		t.Fatal(err)
	}
	if p.raKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{
		Subject: pkix.Name{CommonName: "SCEP Test Root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	p.root = scepCertificate(t, root, root, p.rootKey, p.rootKey.Public())
	intermediate := &x509.Certificate{
		Subject: pkix.Name{CommonName: "SCEP Test Intermediate"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(5 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	p.intermediate = scepCertificate(t, intermediate, p.root, p.rootKey, p.intermediateKey.Public())
	decrypter := &x509.Certificate{
		Subject: pkix.Name{CommonName: "SCEP Test Decrypter"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	p.decrypter = scepCertificate(t, decrypter, p.intermediate, p.intermediateKey, p.decrypterKey.Public())
	ra := &x509.Certificate{
		Subject: pkix.Name{CommonName: "SCEP Test RA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	p.ra = scepCertificate(t, ra, ra, p.raKey, p.raKey.Public())
	server := &x509.Certificate{
		Subject: pkix.Name{CommonName: "127.0.0.1"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	p.server = scepCertificate(t, server, p.root, p.rootKey, p.serverKey.Public())
	return p
}

func (p *scepTestPKI) rootPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.root.Raw})
}

// issueLeaf issues an end-entity certificate for the CSR's key, signed by the intermediate.
func (p *scepTestPKI) issueLeaf(t *testing.T, csr *x509.CertificateRequest) *x509.Certificate {
	t.Helper()
	now := time.Now()
	template := &x509.Certificate{
		Subject: pkix.Name{CommonName: csr.Subject.CommonName}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(720 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, EmailAddresses: csr.EmailAddresses,
	}
	return scepCertificate(t, template, p.intermediate, p.intermediateKey, csr.PublicKey)
}

func scepCertificate(t *testing.T, template, parent *x509.Certificate, signer crypto.Signer, pub any) *x509.Certificate {
	t.Helper()
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	template.SerialNumber = serial
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// scepCertRep builds a CertRep the way a CA would, with explicit fields so that tests can break one at a time.
// A nil envelope recipient produces a CertRep without an encrypted body, as FAILURE and PENDING do.
func scepCertRep(t *testing.T, signer *x509.Certificate, signerKey crypto.PrivateKey, status scep.PKIStatus, transactionID scep.TransactionID, recipientNonce scep.RecipientNonce, recipient *x509.Certificate, certs []*x509.Certificate) []byte {
	t.Helper()
	var signed *pkcs7.SignedData
	var err error
	if recipient != nil {
		degenerate, err := scep.DegenerateCertificates(certs)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := pkcs7.Encrypt(degenerate, []*x509.Certificate{recipient})
		if err != nil {
			t.Fatal(err)
		}
		signed, err = pkcs7.NewSignedData(envelope)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		signed, err = pkcs7.NewSignedData(nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	senderNonce := make([]byte, 16)
	if _, err := rand.Read(senderNonce); err != nil {
		t.Fatal(err)
	}
	if err := signed.AddSigner(signer, signerKey, pkcs7.SignerInfoConfig{ExtraSignedAttributes: []pkcs7.Attribute{
		{Type: oidSCEPTransactionID, Value: transactionID},
		{Type: oidSCEPMessageType, Value: scep.CertRep},
		{Type: oidSCEPPKIStatus, Value: status},
		{Type: oidSCEPFailInfo, Value: scep.BadRequest},
		{Type: oidSCEPSenderNonce, Value: scep.SenderNonce(senderNonce)},
		{Type: oidSCEPRecipientNonce, Value: recipientNonce},
	}}); err != nil {
		t.Fatal(err)
	}
	der, err := signed.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// scepFixture is a SCEP server backed by scepTestPKI. Each PKIOperation is answered by respond.
type scepFixture struct {
	pki     *scepTestPKI
	server  *httptest.Server
	caCert  []byte
	respond func(msg *scep.PKIMessage) []byte

	mu       sync.Mutex
	requests int
}

func newSCEPFixture(t *testing.T, pki *scepTestPKI) *scepFixture {
	t.Helper()
	degenerate, err := scep.DegenerateCertificates([]*x509.Certificate{pki.decrypter, pki.intermediate})
	if err != nil {
		t.Fatal(err)
	}
	f := &scepFixture{pki: pki, caCert: degenerate}
	f.respond = func(msg *scep.PKIMessage) []byte {
		leaf := pki.issueLeaf(t, msg.CSRReqMessage.CSR)
		reply, err := msg.Success(pki.decrypter, pki.decrypterKey, leaf)
		if err != nil {
			return nil
		}
		return reply.Raw
	}
	f.server = httptest.NewUnstartedServer(f)
	f.server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{pki.server.Raw}, PrivateKey: pki.serverKey}}}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	return f
}

func (f *scepFixture) url() string {
	return f.server.URL + "/scep/sigil-scep"
}

func (f *scepFixture) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

func (f *scepFixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests++
	f.mu.Unlock()
	switch r.URL.Query().Get("operation") {
	case "GetCACaps":
		_, _ = io.WriteString(w, "Renewal\nSHA-256\nAES\nPOSTPKIOperation\n")
	case "GetCACert":
		_, _ = w.Write(f.caCert)
	case "PKIOperation":
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		msg, err := scep.ParsePKIMessage(body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := msg.DecryptPKIEnvelope(f.pki.decrypter, f.pki.decrypterKey); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		reply := f.respond(msg)
		if reply == nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-pki-message")
		_, _ = w.Write(reply)
	default:
		http.NotFound(w, r)
	}
}

func scepClient(t *testing.T, pki *scepTestPKI, url string) *SCEP {
	t.Helper()
	client, err := NewSCEP(SCEPConfig{
		URL:     url,
		RootPEM: pki.rootPEM(),
		RACert:  pki.ra,
		RAKey:   pki.raKey,
		Now:     time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func scepRequest(subject string, emails ...string) SignRequest {
	now := time.Now()
	return SignRequest{Subject: subject, EmailAddresses: emails, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(720 * time.Hour)}
}

func TestSCEPSignReturnsTheLeafAndTheIssuingChain(t *testing.T) {
	pki := newSCEPTestPKI(t)
	fixture := newSCEPFixture(t, pki)
	client := scepClient(t, pki, fixture.url())
	key := newP256(t)

	chain, err := client.Sign(context.Background(), scepCSR(t, key, "alice", "alice@example.test", ""), scepRequest("alice", "alice@example.test"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "alice" || len(leaf.EmailAddresses) != 1 || leaf.EmailAddresses[0] != "alice@example.test" {
		t.Fatalf("leaf subject=%q emails=%v", leaf.Subject.CommonName, leaf.EmailAddresses)
	}
	if !bytes.Equal(leaf.RawSubjectPublicKeyInfo, mustSPKI(t, key)) {
		t.Fatal("leaf key is not the CSR key")
	}
	if len(chain) != 2 || !bytes.Equal(chain[1], pki.intermediate.Raw) {
		t.Fatalf("issuing chain must be the intermediate only; got %d certificates", len(chain))
	}
}

func TestSCEPSignAcceptsAP256CSRAndKeepsTheRequestPlain(t *testing.T) {
	pki := newSCEPTestPKI(t)
	fixture := newSCEPFixture(t, pki)
	client := scepClient(t, pki, fixture.url())
	if _, err := client.Sign(context.Background(), scepCSR(t, newP256(t), "bob", "", ""), scepRequest("bob")); err != nil {
		t.Fatalf("P-256 CSR without SANs must be accepted: %v", err)
	}
}

func TestSCEPSignReportsAFailureWithItsFailInfo(t *testing.T) {
	pki := newSCEPTestPKI(t)
	fixture := newSCEPFixture(t, pki)
	fixture.respond = func(msg *scep.PKIMessage) []byte {
		reply, err := msg.Fail(pki.decrypter, pki.decrypterKey, scep.BadRequest)
		if err != nil {
			return nil
		}
		return reply.Raw
	}
	client := scepClient(t, pki, fixture.url())
	_, err := client.Sign(context.Background(), scepCSR(t, newP256(t), "alice", "", ""), scepRequest("alice"))
	if err == nil || !strings.Contains(err.Error(), "CA rejected the SCEP request") || !strings.Contains(err.Error(), scep.BadRequest.String()) {
		t.Fatalf("FAILURE error = %v", err)
	}
}

func TestSCEPSignRejectsPendingAsUnsupported(t *testing.T) {
	pki := newSCEPTestPKI(t)
	fixture := newSCEPFixture(t, pki)
	fixture.respond = func(msg *scep.PKIMessage) []byte {
		return scepCertRep(t, pki.decrypter, pki.decrypterKey, scep.PENDING, msg.TransactionID, scep.RecipientNonce(msg.SenderNonce), nil, nil)
	}
	client := scepClient(t, pki, fixture.url())
	_, err := client.Sign(context.Background(), scepCSR(t, newP256(t), "alice", "", ""), scepRequest("alice"))
	if err == nil || !strings.Contains(err.Error(), "manual approval (PENDING) is not supported") {
		t.Fatalf("PENDING error = %v", err)
	}
}

func TestSCEPSignRejectsACertRepFromAnUntrustedSigner(t *testing.T) {
	pki := newSCEPTestPKI(t)
	fixture := newSCEPFixture(t, pki)
	mallory := newP256(t)
	mallorySelf := &x509.Certificate{Subject: pkix.Name{CommonName: "Mallory"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	malloryCert := scepCertificate(t, mallorySelf, mallorySelf, mallory, mallory.Public())
	fixture.respond = func(msg *scep.PKIMessage) []byte {
		return scepCertRep(t, malloryCert, mallory, scep.FAILURE, msg.TransactionID, scep.RecipientNonce(msg.SenderNonce), nil, nil)
	}
	client := scepClient(t, pki, fixture.url())
	_, err := client.Sign(context.Background(), scepCSR(t, newP256(t), "alice", "", ""), scepRequest("alice"))
	if err == nil || !strings.Contains(err.Error(), "not signed by a certificate that chains to the configured root") {
		t.Fatalf("untrusted signer error = %v", err)
	}
}

func TestSCEPSignRejectsARecipientNonceThatDoesNotMatch(t *testing.T) {
	pki := newSCEPTestPKI(t)
	fixture := newSCEPFixture(t, pki)
	fixture.respond = func(msg *scep.PKIMessage) []byte {
		return scepCertRep(t, pki.decrypter, pki.decrypterKey, scep.PENDING, msg.TransactionID, scep.RecipientNonce("not-our-nonce"), nil, nil)
	}
	client := scepClient(t, pki, fixture.url())
	_, err := client.Sign(context.Background(), scepCSR(t, newP256(t), "alice", "", ""), scepRequest("alice"))
	if err == nil || !strings.Contains(err.Error(), "recipient nonce does not match") {
		t.Fatalf("nonce error = %v", err)
	}
}

func TestSCEPSignRejectsATransactionIDThatDoesNotMatch(t *testing.T) {
	pki := newSCEPTestPKI(t)
	fixture := newSCEPFixture(t, pki)
	fixture.respond = func(msg *scep.PKIMessage) []byte {
		return scepCertRep(t, pki.decrypter, pki.decrypterKey, scep.PENDING, "someone-else", scep.RecipientNonce(msg.SenderNonce), nil, nil)
	}
	client := scepClient(t, pki, fixture.url())
	_, err := client.Sign(context.Background(), scepCSR(t, newP256(t), "alice", "", ""), scepRequest("alice"))
	if err == nil || !strings.Contains(err.Error(), "transaction ID does not match") {
		t.Fatalf("transaction error = %v", err)
	}
}

func TestSCEPSignRejectsACertificateForAnotherKey(t *testing.T) {
	pki := newSCEPTestPKI(t)
	fixture := newSCEPFixture(t, pki)
	other := newP256(t)
	fixture.respond = func(msg *scep.PKIMessage) []byte {
		wrong := pki.issueLeaf(t, mustParseCSR(t, scepCSR(t, other, "alice", "", "")))
		return scepCertRep(t, pki.decrypter, pki.decrypterKey, scep.SUCCESS, msg.TransactionID, scep.RecipientNonce(msg.SenderNonce), pki.ra, []*x509.Certificate{wrong})
	}
	client := scepClient(t, pki, fixture.url())
	_, err := client.Sign(context.Background(), scepCSR(t, newP256(t), "alice", "", ""), scepRequest("alice"))
	if err == nil || !strings.Contains(err.Error(), "no certificate for the requested key") {
		t.Fatalf("wrong key error = %v", err)
	}
}

func TestSCEPSignRejectsACACertificateThatDoesNotChainToTheRoot(t *testing.T) {
	pki := newSCEPTestPKI(t)
	fixture := newSCEPFixture(t, pki)
	other := newSCEPTestPKI(t)
	degenerate, err := scep.DegenerateCertificates([]*x509.Certificate{other.intermediate})
	if err != nil {
		t.Fatal(err)
	}
	fixture.caCert = degenerate
	client := scepClient(t, pki, fixture.url())
	_, err = client.Sign(context.Background(), scepCSR(t, newP256(t), "alice", "", ""), scepRequest("alice"))
	if err == nil || !strings.Contains(err.Error(), "does not chain to the configured root") {
		t.Fatalf("CA certificate error = %v", err)
	}
}

func TestSCEPSignChecksTheRequestBeforeAnyHTTPCall(t *testing.T) {
	pki := newSCEPTestPKI(t)
	fixture := newSCEPFixture(t, pki)
	client := scepClient(t, pki, fixture.url())
	key := newP256(t)
	cases := []struct {
		name    string
		csr     []byte
		request SignRequest
	}{
		{"common name", scepCSR(t, key, "mallory", "", ""), scepRequest("alice")},
		{"missing email", scepCSR(t, key, "alice", "", ""), scepRequest("alice", "alice@example.test")},
		{"extra email", scepCSR(t, key, "alice", "alice@example.test", ""), scepRequest("alice")},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := client.Sign(context.Background(), test.csr, test.request); err == nil {
				t.Fatal("mismatched CSR must be rejected")
			}
		})
	}
	if n := fixture.requestCount(); n != 0 {
		t.Fatalf("%d HTTP requests were made for rejected CSRs", n)
	}
}

func TestSCEPRevokeIsUnsupportedWithoutARevoker(t *testing.T) {
	pki := newSCEPTestPKI(t)
	client := scepClient(t, pki, "https://127.0.0.1:9/scep/sigil-scep")
	if err := client.Revoke(context.Background(), "01", 0, ""); err != ErrRevocationUnsupported {
		t.Fatalf("Revoke = %v, want ErrRevocationUnsupported", err)
	}
}

func TestNewSCEPRejectsAnRAKeyThatDoesNotMatchItsCertificate(t *testing.T) {
	pki := newSCEPTestPKI(t)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSCEP(SCEPConfig{URL: "https://127.0.0.1/scep/sigil-scep", RootPEM: pki.rootPEM(), RACert: pki.ra, RAKey: otherKey}); err == nil {
		t.Fatal("an RA key that does not match its certificate must be rejected")
	}
	if _, err := NewSCEP(SCEPConfig{URL: "http://127.0.0.1/scep/sigil-scep", RootPEM: pki.rootPEM(), RACert: pki.ra, RAKey: pki.raKey}); err == nil {
		t.Fatal("a plain http SCEP URL must be rejected")
	}
}

func mustSPKI(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func mustParseCSR(t *testing.T, der []byte) *x509.CertificateRequest {
	t.Helper()
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

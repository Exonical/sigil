package ca

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/smallstep/pkcs7"
	"github.com/smallstep/scep"
)

const maxSCEPResponse = 1 << 20

// ErrRevocationUnsupported is returned by a SCEP CA that has no revocation path.
var ErrRevocationUnsupported = errors.New("revocation is not supported by this certificate authority")

func init() {
	// smallstep/pkcs7 keeps its digest and content-encryption defaults in package variables. The SCEP client needs
	// SHA-256 for PKCSReq and AES-256-CBC for its envelope, so both are set once for the process before any request.
	if err := pkcs7.SetDefaultDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256); err != nil {
		panic(err)
	}
	pkcs7.ContentEncryptionAlgorithm = pkcs7.EncryptionAlgorithmAES256CBC
}

// SCEPConfig configures a SCEP (RFC 8894) client for a step-ca SCEP provisioner. The backend is the registration
// authority: it runs every enrollment check itself and then asks the CA to sign.
type SCEPConfig struct {
	// URL is the full provisioner endpoint, for example https://ca.example:9000/scep/sigil-scep.
	URL     string
	RootPEM []byte
	// RACert and RAKey sign PKCSReq and decrypt CertRep. They are not issuing CA certificates.
	RACert *x509.Certificate
	RAKey  *rsa.PrivateKey
	// Revoker is used for revocation, because SCEP has no revocation operation of its own.
	Revoker CA
	Now     func() time.Time
}

// SCEP signs through a SCEP provisioner. The CSR must already contain the subject and SANs that the backend approved,
// because SCEP cannot carry overrides. Validity is set by the provisioner's claims, not by the request.
type SCEP struct {
	cfg    SCEPConfig
	roots  *x509.CertPool
	client *http.Client
}

// NewSCEP validates the configuration and builds a client that trusts only the configured root.
func NewSCEP(cfg SCEPConfig) (*SCEP, error) {
	base, err := url.Parse(cfg.URL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return nil, errors.New("SCEP URL must be an https URL")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cfg.RootPEM) {
		return nil, errors.New("SCEP root file contains no certificates")
	}
	if cfg.RACert == nil || cfg.RAKey == nil {
		return nil, errors.New("SCEP registration authority certificate and key are required")
	}
	raKey, ok := cfg.RACert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("SCEP registration authority certificate must be RSA")
	}
	if !raKey.Equal(&cfg.RAKey.PublicKey) {
		return nil, errors.New("SCEP registration authority key does not match its certificate")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &SCEP{
		cfg:   cfg,
		roots: roots,
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
		},
	}, nil
}

// LoadSCEPRegistrationAuthority reads the RA certificate and its RSA key from PEM files.
func LoadSCEPRegistrationAuthority(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, errors.New("read SCEP registration authority certificate")
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, errors.New("SCEP registration authority certificate is not a PEM certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, errors.New("SCEP registration authority certificate is not valid DER")
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, errors.New("read SCEP registration authority key")
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, errors.New("SCEP registration authority key is not PEM")
	}
	var key *rsa.PrivateKey
	if parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err == nil {
		rsaKey, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, errors.New("SCEP registration authority key must be RSA")
		}
		key = rsaKey
	} else if key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err != nil {
		return nil, nil, errors.New("SCEP registration authority key must be an RSA private key")
	}
	return cert, key, nil
}

// Roots returns the root certificates that issued certificates must chain to.
func (s *SCEP) Roots() *x509.CertPool {
	return s.roots
}

// Revoke delegates to the configured revoker. Without one, revocation is reported as unsupported.
func (s *SCEP) Revoke(ctx context.Context, serialHex string, reasonCode int, reason string) error {
	if s.cfg.Revoker == nil {
		return ErrRevocationUnsupported
	}
	return s.cfg.Revoker.Revoke(ctx, serialHex, reasonCode, reason)
}

// Sign requests a certificate for the CSR with a PKCSReq. The request must carry the CSR's own subject and SANs,
// which must match the approved values exactly.
func (s *SCEP) Sign(ctx context.Context, csrDER []byte, request SignRequest) ([][]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, errors.New("certificate request is not valid DER")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.New("certificate request signature is invalid")
	}
	if csr.Subject.CommonName != request.Subject {
		return nil, errors.New("certificate request subject does not match the approved subject")
	}
	if !sameStrings(csr.EmailAddresses, request.EmailAddresses) || !sameStrings(csr.DNSNames, request.DNSNames) {
		return nil, errors.New("certificate request SANs do not match the approved SANs")
	}
	caCerts, err := s.caCertificates(ctx)
	if err != nil {
		return nil, err
	}
	recipient, err := scepRecipient(caCerts)
	if err != nil {
		return nil, err
	}
	message, err := scep.NewCSRRequest(csr, &scep.PKIMessage{
		MessageType: scep.PKCSReq,
		SignerCert:  s.cfg.RACert,
		SignerKey:   s.cfg.RAKey,
		Recipients:  []*x509.Certificate{recipient},
	})
	if err != nil {
		return nil, errors.New("could not build the SCEP request")
	}
	body, err := s.pkiOperation(ctx, message.Raw)
	if err != nil {
		return nil, err
	}
	reply, err := scep.ParsePKIMessage(body, scep.WithCACerts(caCerts))
	if err != nil {
		return nil, errors.New("SCEP response is not signed by a certificate that chains to the configured root")
	}
	if reply.MessageType != scep.CertRep {
		return nil, fmt.Errorf("SCEP response has unexpected message type %q", reply.MessageType)
	}
	if reply.TransactionID != message.TransactionID {
		return nil, errors.New("SCEP response transaction ID does not match the request")
	}
	if reply.CertRepMessage == nil || !bytes.Equal(reply.RecipientNonce, message.SenderNonce) {
		return nil, errors.New("SCEP response recipient nonce does not match the request")
	}
	switch reply.PKIStatus {
	case scep.SUCCESS:
	case scep.FAILURE:
		return nil, fmt.Errorf("CA rejected the SCEP request: %s", reply.FailInfo.String())
	case scep.PENDING:
		return nil, errors.New("CA returned PENDING: manual approval (PENDING) is not supported")
	default:
		return nil, errors.New("SCEP response has an unknown status")
	}
	certs, err := s.decryptCertificates(body)
	if err != nil {
		return nil, err
	}
	var leaf *x509.Certificate
	for _, cert := range certs {
		if bytes.Equal(cert.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) {
			leaf = cert
			break
		}
	}
	if leaf == nil {
		return nil, errors.New("CA response contains no certificate for the requested key")
	}
	chain := [][]byte{leaf.Raw}
	for _, cert := range caCerts {
		if !bytes.Equal(cert.Raw, recipient.Raw) {
			chain = append(chain, cert.Raw)
		}
	}
	return chain, nil
}

// caCertificates checks the CA's capabilities and fetches its certificates. Every certificate must chain to the root.
func (s *SCEP) caCertificates(ctx context.Context) ([]*x509.Certificate, error) {
	capabilities, err := s.get(ctx, "GetCACaps")
	if err != nil {
		return nil, err
	}
	supported := make(map[string]bool)
	for _, line := range strings.Split(string(capabilities), "\n") {
		supported[strings.TrimSpace(line)] = true
	}
	for _, required := range []string{"POSTPKIOperation", "SHA-256", "AES"} {
		if !supported[required] {
			return nil, fmt.Errorf("SCEP CA does not advertise %s", required)
		}
	}
	data, err := s.get(ctx, "GetCACert")
	if err != nil {
		return nil, err
	}
	certs, err := parseCACertificates(data)
	if err != nil {
		return nil, err
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs {
		intermediates.AddCert(cert)
	}
	for _, cert := range certs {
		if _, err := cert.Verify(x509.VerifyOptions{
			Roots:         s.roots,
			Intermediates: intermediates,
			CurrentTime:   s.cfg.Now(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			return nil, errors.New("CA certificate does not chain to the configured root")
		}
	}
	return certs, nil
}

// parseCACertificates accepts a single DER certificate or a degenerate PKCS#7 bundle.
func parseCACertificates(data []byte) ([]*x509.Certificate, error) {
	if cert, err := x509.ParseCertificate(data); err == nil {
		return []*x509.Certificate{cert}, nil
	}
	certs, err := scep.CACerts(data)
	if err != nil || len(certs) == 0 {
		return nil, errors.New("CA certificates response is malformed")
	}
	return certs, nil
}

// scepRecipient returns the RSA certificate that the request is encrypted to: the one with keyEncipherment.
func scepRecipient(certs []*x509.Certificate) (*x509.Certificate, error) {
	for _, cert := range certs {
		if _, ok := cert.PublicKey.(*rsa.PublicKey); ok && cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
			return cert, nil
		}
	}
	return nil, errors.New("SCEP CA certificates include no RSA key-encipherment recipient")
}

// decryptCertificates decrypts the CertRep envelope with the RA key and returns the certificates it carries.
func (s *SCEP) decryptCertificates(body []byte) ([]*x509.Certificate, error) {
	outer, err := pkcs7.Parse(body)
	if err != nil {
		return nil, errors.New("SCEP response envelope is malformed")
	}
	enveloped, err := pkcs7.Parse(outer.Content)
	if err != nil {
		return nil, errors.New("SCEP response envelope is malformed")
	}
	plaintext, err := enveloped.Decrypt(s.cfg.RACert, s.cfg.RAKey)
	if err != nil {
		return nil, errors.New("SCEP response cannot be decrypted with the registration authority key")
	}
	certs, err := scep.CACerts(plaintext)
	if err != nil || len(certs) == 0 {
		return nil, errors.New("SCEP response carries no certificates")
	}
	return certs, nil
}

func (s *SCEP) operationURL(operation string) (string, error) {
	endpoint, err := url.Parse(s.cfg.URL)
	if err != nil {
		return "", errors.New("SCEP URL is invalid")
	}
	query := endpoint.Query()
	query.Set("operation", operation)
	endpoint.RawQuery = query.Encode()
	return endpoint.String(), nil
}

func (s *SCEP) get(ctx context.Context, operation string) ([]byte, error) {
	endpoint, err := s.operationURL(operation)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errors.New("could not build the SCEP request")
	}
	return s.do(req)
}

func (s *SCEP) pkiOperation(ctx context.Context, message []byte) ([]byte, error) {
	endpoint, err := s.operationURL("PKIOperation")
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(message))
	if err != nil {
		return nil, errors.New("could not build the SCEP request")
	}
	req.Header.Set("Content-Type", "application/x-pki-message")
	return s.do(req)
}

func (s *SCEP) do(req *http.Request) ([]byte, error) {
	response, err := s.client.Do(req)
	if err != nil {
		return nil, errors.New("SCEP CA is unavailable")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxSCEPResponse+1))
	if err != nil {
		return nil, errors.New("could not read the SCEP response")
	}
	if len(data) > maxSCEPResponse {
		return nil, errors.New("SCEP response is larger than 1 MiB")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("SCEP CA returned HTTP %d", response.StatusCode)
	}
	return data, nil
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

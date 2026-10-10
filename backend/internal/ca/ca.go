// Package ca signs certificate requests with an external certificate authority.
//
// The backend is the only component that talks to the CA, so CA credentials never leave the backend.
// The CA interface is deliberately small so that other issuers can be added later.
package ca

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// SignRequest describes the certificate the CA must issue for a CSR. The CSR's own subject is ignored.
type SignRequest struct {
	Subject        string
	DNSNames       []string
	EmailAddresses []string
	NotBefore      time.Time
	NotAfter       time.Time
}

// CA signs a certificate request and returns the DER chain, leaf first.
type CA interface {
	Sign(ctx context.Context, csrDER []byte, request SignRequest) ([][]byte, error)
}

// StepConfig configures a Smallstep step-ca client.
type StepConfig struct {
	URL         string
	RootPEM     []byte
	Provisioner string
	Key         jose.JSONWebKey
	Now         func() time.Time
}

// Step signs through step-ca's /1.0/sign endpoint using a one-time JWK provisioner token.
type Step struct {
	cfg    StepConfig
	client *http.Client
	signer jose.Signer
}

// NewStep validates the configuration and builds a client that trusts only the configured root.
func NewStep(cfg StepConfig) (*Step, error) {
	base, err := url.Parse(cfg.URL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return nil, errors.New("step-ca URL must be an https URL")
	}
	if cfg.Provisioner == "" {
		return nil, errors.New("step-ca provisioner name is required")
	}
	if cfg.Key.Key == nil || cfg.Key.IsPublic() {
		return nil, errors.New("step-ca provisioner key is required")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cfg.RootPEM) {
		return nil, errors.New("step-ca root file contains no certificates")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	algorithm := jose.SignatureAlgorithm(cfg.Key.Algorithm)
	if algorithm == "" {
		algorithm = jose.ES256
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: cfg.Key.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", cfg.Key.KeyID))
	if err != nil {
		return nil, fmt.Errorf("create provisioner token signer: %w", err)
	}
	return &Step{
		cfg: cfg,
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
		},
		signer: signer,
	}, nil
}

type signClaims struct {
	jwt.Claims
	SANs []string `json:"sans,omitempty"`
}

// Sign issues a certificate for the CSR. The provisioner token authorizes exactly this subject and SANs.
func (s *Step) Sign(ctx context.Context, csrDER []byte, request SignRequest) ([][]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, errors.New("certificate request is not valid DER")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, errors.New("certificate request signature is invalid")
	}
	if request.Subject == "" {
		return nil, errors.New("subject is required")
	}
	now := s.cfg.Now()
	audience := strings.TrimSuffix(s.cfg.URL, "/") + "/1.0/sign"
	sans := append(append([]string(nil), request.DNSNames...), request.EmailAddresses...)
	token, err := jwt.Signed(s.signer).Claims(signClaims{
		Claims: jwt.Claims{
			Issuer:    s.cfg.Provisioner,
			Subject:   request.Subject,
			Audience:  jwt.Audience{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)),
			Expiry:    jwt.NewNumericDate(now.Add(5 * time.Minute)),
			ID:        randomID(),
		},
		SANs: sans,
	}).Serialize()
	if err != nil {
		return nil, fmt.Errorf("create provisioner token: %w", err)
	}
	body, err := json.Marshal(map[string]any{
		"csr":       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		"ott":       token,
		"notBefore": request.NotBefore.UTC().Format(time.RFC3339),
		"notAfter":  request.NotAfter.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return nil, fmt.Errorf("encode sign request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, audience, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create sign request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := s.client.Do(req)
	if err != nil {
		return nil, errors.New("step-ca is unavailable")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, errors.New("could not read step-ca response")
	}
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		var failure struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &failure)
		return nil, fmt.Errorf("step-ca rejected the request with HTTP %d: %s", response.StatusCode, failure.Message)
	}
	var reply struct {
		Certificate string   `json:"crt"`
		Chain       []string `json:"certChain"`
	}
	if err := json.Unmarshal(data, &reply); err != nil {
		return nil, errors.New("step-ca response is not valid JSON")
	}
	pems := reply.Chain
	if len(pems) == 0 {
		pems = []string{reply.Certificate}
	}
	chain := make([][]byte, 0, len(pems))
	for _, value := range pems {
		block, _ := pem.Decode([]byte(value))
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("step-ca returned a malformed certificate")
		}
		chain = append(chain, block.Bytes)
	}
	if len(chain) == 0 {
		return nil, errors.New("step-ca returned no certificate")
	}
	return chain, nil
}

// LoadProvisionerKey decrypts a password-protected JWK (JWE JSON or compact serialization).
func LoadProvisionerKey(encrypted []byte, password []byte) (jose.JSONWebKey, error) {
	object, err := jose.ParseEncrypted(string(encrypted),
		[]jose.KeyAlgorithm{jose.PBES2_HS256_A128KW, jose.PBES2_HS384_A192KW, jose.PBES2_HS512_A256KW},
		[]jose.ContentEncryption{jose.A256GCM, jose.A128CBC_HS256, jose.A192CBC_HS384, jose.A256CBC_HS512})
	if err != nil {
		return jose.JSONWebKey{}, errors.New("provisioner key is not an encrypted JWK")
	}
	plaintext, err := object.Decrypt(password)
	if err != nil {
		return jose.JSONWebKey{}, errors.New("provisioner key password is incorrect")
	}
	var key jose.JSONWebKey
	if err := json.Unmarshal(plaintext, &key); err != nil {
		return jose.JSONWebKey{}, errors.New("provisioner key is not a JWK")
	}
	if !key.Valid() || key.IsPublic() {
		return jose.JSONWebKey{}, errors.New("provisioner key must be a private key")
	}
	return key, nil
}

func randomID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}

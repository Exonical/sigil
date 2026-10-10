package authn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
)

var ErrUserStore = errors.New("OIDC user store unavailable")

type UserStore interface {
	UpsertUser(ctx context.Context, issuer, subject, email, displayName string) (string, error)
}

type Config struct {
	Issuer      string
	CAFile      string
	Audience    string
	GroupsClaim string
}

type Principal struct {
	UserID      string
	Issuer      string
	Subject     string
	Email       string
	DisplayName string
	Groups      []string
}

type Authenticator struct {
	issuer      string
	groupsClaim string
	verifier    *oidc.IDTokenVerifier
	users       UserStore
}

func New(ctx context.Context, cfg Config, users UserStore) (*Authenticator, error) {
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("OIDC issuer and audience are required")
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	if cfg.CAFile != "" {
		caPEM, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, errors.New("could not read configured OIDC CA file")
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("configured OIDC CA file contains no certificates")
		}
		transport, ok := http.DefaultTransport.(*http.Transport)
		if ok {
			transport = transport.Clone()
		} else {
			transport = &http.Transport{}
		}
		tlsConfig := transport.TLSClientConfig
		if tlsConfig == nil {
			tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		} else {
			tlsConfig = tlsConfig.Clone()
		}
		tlsConfig.RootCAs = roots
		transport.TLSClientConfig = tlsConfig
		ctx = oidc.ClientContext(ctx, &http.Client{Transport: transport})
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, errors.New("could not discover configured OIDC issuer")
	}
	return &Authenticator{
		issuer:      cfg.Issuer,
		groupsClaim: cfg.GroupsClaim,
		verifier:    provider.Verifier(&oidc.Config{ClientID: cfg.Audience}),
		users:       users,
	}, nil
}

func (a *Authenticator) Authenticate(ctx context.Context, accessToken string) (Principal, error) {
	if accessToken == "" {
		return Principal{}, errors.New("OIDC access token is required")
	}
	token, err := a.verifier.Verify(ctx, accessToken)
	if err != nil {
		return Principal{}, errors.New("OIDC access token is invalid")
	}
	if token.Subject == "" {
		return Principal{}, errors.New("OIDC subject is missing")
	}
	var claims struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := token.Claims(&claims); err != nil {
		return Principal{}, fmt.Errorf("decode OIDC user claims: %w", err)
	}
	var raw map[string]json.RawMessage
	if err := token.Claims(&raw); err != nil {
		return Principal{}, fmt.Errorf("decode OIDC groups claim: %w", err)
	}
	var groups []string
	if encoded, ok := raw[a.groupsClaim]; ok && string(encoded) != "null" {
		if err := json.Unmarshal(encoded, &groups); err != nil {
			return Principal{}, errors.New("OIDC groups claim is not a string list")
		}
	}
	userID, err := a.users.UpsertUser(ctx, a.issuer, token.Subject, claims.Email, claims.Name)
	if err != nil {
		return Principal{}, fmt.Errorf("%w: %v", ErrUserStore, err)
	}
	return Principal{
		UserID:      userID,
		Issuer:      a.issuer,
		Subject:     token.Subject,
		Email:       claims.Email,
		DisplayName: claims.Name,
		Groups:      groups,
	}, nil
}

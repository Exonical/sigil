package authn

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type memoryUsers struct {
	records int
}

func (m *memoryUsers) UpsertUser(_ context.Context, issuer, subject, _, _ string) (string, error) {
	m.records++
	return issuer + "|" + subject, nil
}

type testIssuer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &testIssuer{key: key}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                fixture.server.URL,
				"jwks_uri":                              fixture.server.URL + "/keys",
				"authorization_endpoint":                fixture.server.URL + "/authorize",
				"token_endpoint":                        fixture.server.URL + "/token",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/keys":
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
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (i *testIssuer) token(t *testing.T, issuer string, audience any, subject string, expiry time.Time, key *rsa.PrivateKey) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{
		"iss":    issuer,
		"aud":    audience,
		"sub":    subject,
		"email":  "alice@example.test",
		"name":   "Alice",
		"groups": []string{"provisioners"},
		"iat":    time.Now().Add(-time.Minute).Unix(),
		"exp":    expiry.Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestOIDCAuthenticationValidatesAccessTokensAndUpsertsUsers(t *testing.T) {
	issuer := newTestIssuer(t)
	users := &memoryUsers{}
	authenticator, err := New(context.Background(), Config{
		Issuer:      issuer.server.URL,
		Audience:    "sigil-api",
		GroupsClaim: "groups",
	}, users)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		token     string
		wantError bool
	}{
		{
			name:  "valid",
			token: issuer.token(t, issuer.server.URL, "sigil-api", "alice", now.Add(time.Hour), issuer.key),
		},
		{
			name:      "wrong audience",
			token:     issuer.token(t, issuer.server.URL, "other-api", "alice", now.Add(time.Hour), issuer.key),
			wantError: true,
		},
		{
			name:      "wrong issuer",
			token:     issuer.token(t, "https://wrong-issuer.example", "sigil-api", "alice", now.Add(time.Hour), issuer.key),
			wantError: true,
		},
		{
			name:      "expired",
			token:     issuer.token(t, issuer.server.URL, "sigil-api", "alice", now.Add(-time.Minute), issuer.key),
			wantError: true,
		},
		{
			name:      "bad signature",
			token:     issuer.token(t, issuer.server.URL, "sigil-api", "alice", now.Add(time.Hour), otherKey),
			wantError: true,
		},
		{
			name:      "missing subject",
			token:     issuer.token(t, issuer.server.URL, "sigil-api", "", now.Add(time.Hour), issuer.key),
			wantError: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := users.records
			principal, err := authenticator.Authenticate(context.Background(), test.token)
			if test.wantError {
				if err == nil {
					t.Fatal("expected authentication error")
				}
				if users.records != before {
					t.Fatal("invalid token caused a user upsert")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if principal.UserID != issuer.server.URL+"|alice" ||
				principal.Email != "alice@example.test" ||
				principal.DisplayName != "Alice" ||
				len(principal.Groups) != 1 || principal.Groups[0] != "provisioners" {
				t.Fatalf("unexpected principal: %#v", principal)
			}
		})
	}
	if users.records != 1 {
		t.Fatalf("valid token upserts=%d, want 1", users.records)
	}
}

func TestOIDCMissingTokenIsRejected(t *testing.T) {
	issuer := newTestIssuer(t)
	authenticator, err := New(context.Background(), Config{Issuer: issuer.server.URL, Audience: "sigil-api"}, &memoryUsers{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authenticator.Authenticate(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("missing-token error = %v", err)
	}
}

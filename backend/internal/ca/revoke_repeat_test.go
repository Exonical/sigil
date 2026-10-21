package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func pemOf(server *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
}

func testProvisionerKey(t *testing.T) jose.JSONWebKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return jose.JSONWebKey{Key: key, KeyID: "kid-test", Algorithm: string(jose.ES256)}
}

// TestStepRevokeReportsAnAlreadyRevokedCertificate uses step-ca's exact response to a repeat revoke, captured
// from the dev CA on 2026-10-10.
func TestStepRevokeReportsAnAlreadyRevokedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"status":400,"message":"The request could not be completed: certificate with serial number '202119814302308913045336172291102687708' is already revoked."}`))
	}))
	defer server.Close()
	client, err := NewStep(StepConfig{
		URL:         server.URL,
		RootPEM:     pemOf(server),
		Provisioner: "sigil-backend",
		Key:         testProvisionerKey(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = client.Revoke(context.Background(), "980edc3ac7281735298e580b33b541dc", 5, "cessation of operation")
	if !errors.Is(err, ErrAlreadyRevoked) {
		t.Fatalf("repeat revoke error = %v, want ErrAlreadyRevoked", err)
	}
}

func TestStepRevokeKeepsOtherBadRequestsAsFailures(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"status":400,"message":"certificate with serial number '1' was not found"}`))
	}))
	defer server.Close()
	client, err := NewStep(StepConfig{URL: server.URL, RootPEM: pemOf(server), Provisioner: "sigil-backend", Key: testProvisionerKey(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Revoke(context.Background(), "1", 5, ""); err == nil || errors.Is(err, ErrAlreadyRevoked) {
		t.Fatalf("an unknown serial must stay a failure, got %v", err)
	}
}

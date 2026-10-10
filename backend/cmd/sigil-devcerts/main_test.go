package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestAuthentikLocalhostIdentityIsValidAndReused(t *testing.T) {
	outputDirectory := t.TempDir()
	certificatePath, err := writeAuthentikLocalhostIdentity(outputDirectory)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(filepath.Dir(certificatePath), "privkey.pem")
	certificatePEM, err := os.ReadFile(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	certificateBlock, _ := pem.Decode(certificatePEM)
	if certificateBlock == nil {
		t.Fatal("localhost certificate is not PEM encoded")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if certificate.PublicKeyAlgorithm != x509.ECDSA {
		t.Fatalf("public key algorithm = %v, want ECDSA", certificate.PublicKeyAlgorithm)
	}
	privateBlock, _ := pem.Decode(keyPEM)
	if privateBlock == nil {
		t.Fatal("localhost private key is not PEM encoded")
	}
	privateKeyValue, err := x509.ParsePKCS8PrivateKey(privateBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, ok := privateKeyValue.(*ecdsa.PrivateKey)
	if !ok || privateKey.Curve.Params().Name != elliptic.P256().Params().Name {
		t.Fatal("localhost private key is not ECDSA P-256")
	}
	if !slices.Contains(certificate.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Fatal("localhost certificate lacks the server-auth extended key usage")
	}
	for _, hostname := range []string{"localhost", "127.0.0.1", "::1"} {
		if err := certificate.VerifyHostname(hostname); err != nil {
			t.Errorf("certificate does not cover %s: %v", hostname, err)
		}
	}
	if certificate.NotAfter.Before(time.Now().AddDate(0, 11, 0)) {
		t.Fatal("localhost certificate does not have close to one year of validity")
	}

	if _, err := writeAuthentikLocalhostIdentity(outputDirectory); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(certificatePath); err != nil || !slices.Equal(got, certificatePEM) {
		t.Errorf("valid certificate was regenerated: %v", err)
	}
	if got, err := os.ReadFile(keyPath); err != nil || !slices.Equal(got, keyPEM) {
		t.Errorf("valid private key was regenerated: %v", err)
	}
}

func TestAuthentikLocalhostIdentityRegeneratesInvalidPair(t *testing.T) {
	outputDirectory := t.TempDir()
	certificatePath, err := writeAuthentikLocalhostIdentity(outputDirectory)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(filepath.Dir(certificatePath), "privkey.pem")
	if err := os.WriteFile(keyPath, []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := writeAuthentikLocalhostIdentity(outputDirectory); err != nil {
		t.Fatal(err)
	}
	if err := validateAuthentikLocalhostIdentity(certificatePath, keyPath, time.Now()); err != nil {
		t.Fatalf("regenerated identity is invalid: %v", err)
	}
}

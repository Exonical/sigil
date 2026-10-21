package db_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/Exonical/sigil/backend/internal/db"
	"github.com/Exonical/sigil/backend/internal/testdb"
)

// TestCertificateStoresTheVerifiedAttestation checks that the attestation travels with the certificate row, and
// that a certificate without one leaves the columns NULL.
func TestCertificateStoresTheVerifiedAttestation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	store, cleanup, err := testdb.Open(ctx)
	if err != nil {
		if errors.Is(err, testdb.ErrNotConfigured) {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	defer cleanup()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	spki := sha256.Sum256([]byte("attestation-store-station"))
	if _, err := store.Pool.Exec(ctx, `
		INSERT INTO stations(id, display_name, mode, cert_spki_sha256, status, dns_name)
		VALUES('station-attest', 'Attestation station', 'station', $1, 'active', 'station-attest.example.test')
	`, spki[:]); err != nil {
		t.Fatal(err)
	}
	userID, err := store.UpsertUser(ctx, "https://idp.example/", "subject-attest", "attest-user", "attest@example.test", "Attest User")
	if err != nil {
		t.Fatal(err)
	}
	var tokenID string
	if err := store.Pool.QueryRow(ctx, `
		INSERT INTO tokens(vendor, serial, status, assigned_user_id, last_station_id)
		VALUES('Yubico', 'attest-0001', 'active', $1::uuid, 'station-attest')
		RETURNING id::text
	`, userID).Scan(&tokenID); err != nil {
		t.Fatal(err)
	}

	issue := func(serial string, attestation []byte) {
		t.Helper()
		tx, err := store.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := store.InsertCertificate(ctx, tx, db.CertificateRecord{
			TokenID: tokenID, Slot: "9a", Profile: "piv-authentication", UserID: userID,
			SerialNumber: serial, Subject: "CN=attest-user", NotBefore: time.Now().Add(-time.Hour),
			NotAfter: time.Now().Add(time.Hour), IssuedByStation: "station-attest", DER: []byte{1, 2},
			AttestationDER: attestation, AttestationIntermediateDER: intermediateFor(attestation),
			AttestedFirmware: map[bool]string{true: "5.7.4", false: ""}[attestation != nil],
			AttestationRoot:  map[bool]string{true: "Yubico Attestation Root 1", false: ""}[attestation != nil],
		}); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}

	issue("c-with", []byte("attestation-der"))
	issue("c-without", nil)

	var attestation, intermediate []byte
	var firmware, root *string
	if err := store.Pool.QueryRow(ctx, `
		SELECT attestation_der, attestation_intermediate_der, attested_firmware, attestation_root
		FROM certificates WHERE serial_number = 'c-with'
	`).Scan(&attestation, &intermediate, &firmware, &root); err != nil {
		t.Fatal(err)
	}
	if string(attestation) != "attestation-der" || string(intermediate) != "f9" {
		t.Fatalf("stored attestation = %q / %q", attestation, intermediate)
	}
	if firmware == nil || *firmware != "5.7.4" || root == nil || *root != "Yubico Attestation Root 1" {
		t.Fatalf("stored firmware/root = %v / %v", firmware, root)
	}

	if err := store.Pool.QueryRow(ctx, `
		SELECT attestation_der, attestation_intermediate_der, attested_firmware, attestation_root
		FROM certificates WHERE serial_number = 'c-without'
	`).Scan(&attestation, &intermediate, &firmware, &root); err != nil {
		t.Fatal(err)
	}
	if attestation != nil || intermediate != nil || firmware != nil || root != nil {
		t.Fatal("a certificate without an attestation must leave the columns NULL")
	}
}

func intermediateFor(attestation []byte) []byte {
	if attestation == nil {
		return nil
	}
	return []byte("f9")
}

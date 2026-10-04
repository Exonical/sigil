package inventory

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	backendv1 "github.com/Exonical/sigil/backend/gen/sigil/backend/v1"
	"github.com/Exonical/sigil/backend/internal/audit"
	"github.com/Exonical/sigil/backend/internal/testdb"
)

func TestReportedTokensUpsertWithoutReactivatingLostTokens(t *testing.T) {
	store, cleanup, err := testdb.Open(context.Background())
	if errors.Is(err, testdb.ErrNotConfigured) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	ctx := context.Background()
	for _, station := range []string{"station-a", "station-b"} {
		hash := sha256.Sum256([]byte(station))
		if _, err := store.Pool.Exec(ctx, `
			INSERT INTO stations(id, display_name, mode, cert_spki_sha256, status)
			VALUES($1, $1, 'station', $2, 'active')
		`, station, hash[:]); err != nil {
			t.Fatal(err)
		}
	}
	repository := New(store)
	token := &backendv1.ObservedToken{
		Vendor: " Yubico ", Model: " YubiKey Test ", Serial: " 39192733 ",
		Firmware: " 5.7.4 ", FormFactor: " USB-C ", Connection: " usb_smart_card ",
	}
	if err := repository.Report(ctx, "station-a", []*backendv1.ObservedToken{token}); err != nil {
		t.Fatal(err)
	}
	var firstSeen string
	if err := store.Pool.QueryRow(ctx, `
		SELECT first_seen_at::text FROM tokens WHERE vendor='Yubico' AND serial='39192733'
	`).Scan(&firstSeen); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `
		UPDATE tokens SET status='lost' WHERE vendor='Yubico' AND serial='39192733'
	`); err != nil {
		t.Fatal(err)
	}
	updated := &backendv1.ObservedToken{
		Vendor: " Yubico ", Model: " YubiKey Updated ", Serial: " 39192733 ",
		Firmware: " 5.8.0 ", FormFactor: " USB-C ", Connection: " nfc ",
	}
	if err := repository.Report(ctx, "station-b", []*backendv1.ObservedToken{updated}); err != nil {
		t.Fatal(err)
	}
	var model, firmware, formFactor, statusValue, lastStation string
	var secondFirstSeen string
	if err := store.Pool.QueryRow(ctx, `
		SELECT model, firmware, form_factor, status, last_station_id, first_seen_at::text
		FROM tokens WHERE vendor='Yubico' AND serial='39192733'
	`).Scan(&model, &firmware, &formFactor, &statusValue, &lastStation, &secondFirstSeen); err != nil {
		t.Fatal(err)
	}
	if model != "YubiKey Updated" || firmware != "5.8.0" || formFactor != "USB-C" || statusValue != "lost" || lastStation != "station-b" || secondFirstSeen != firstSeen {
		t.Fatalf("unexpected upsert: model=%q firmware=%q form_factor=%q status=%q station=%q first_seen=%q", model, firmware, formFactor, statusValue, lastStation, secondFirstSeen)
	}
	if err := audit.Verify(ctx, store.Pool); err != nil {
		t.Fatal(err)
	}
}

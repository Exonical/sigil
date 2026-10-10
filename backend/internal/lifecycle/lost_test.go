package lifecycle

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/Exonical/sigil/backend/internal/ca"
	"github.com/Exonical/sigil/backend/internal/db"
	"github.com/Exonical/sigil/backend/internal/testdb"
)

// fakeCA records revocations and can refuse specific serials.
type fakeCA struct {
	mu      sync.Mutex
	revoked map[string]int
	refuse  map[string]bool
	already map[string]bool
	reasons map[string]int
}

func newFakeCA() *fakeCA {
	return &fakeCA{revoked: map[string]int{}, refuse: map[string]bool{}, already: map[string]bool{}, reasons: map[string]int{}}
}

func (f *fakeCA) Sign(context.Context, []byte, ca.SignRequest) ([][]byte, error) {
	return nil, errors.New("not used by the lost-key job")
}

func (f *fakeCA) Revoke(_ context.Context, serial string, reasonCode int, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.already[serial] {
		return ca.ErrAlreadyRevoked
	}
	if f.refuse[serial] {
		return errors.New("fake CA refused the revocation")
	}
	f.revoked[serial]++
	f.reasons[serial] = reasonCode
	return nil
}

func (f *fakeCA) count(serial string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.revoked[serial]
}

type lifecycleFixture struct {
	ctx     context.Context
	store   *db.Store
	userID  string
	station string
	now     time.Time
}

func newLifecycleFixture(t *testing.T) lifecycleFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	store, cleanup, err := testdb.Open(ctx)
	if err != nil {
		if errors.Is(err, testdb.ErrNotConfigured) {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	spki := sha256.Sum256([]byte("lifecycle-station"))
	if _, err := store.Pool.Exec(ctx, `
		INSERT INTO stations(id, display_name, mode, cert_spki_sha256, status, dns_name)
		VALUES('station-life', 'Lifecycle station', 'station', $1, 'active', 'station-life.example.test')
	`, spki[:]); err != nil {
		t.Fatal(err)
	}
	userID, err := store.UpsertUser(ctx, "https://idp.example/", "subject-life", "life-user", "life@example.test", "Life User")
	if err != nil {
		t.Fatal(err)
	}
	return lifecycleFixture{ctx: ctx, store: store, userID: userID, station: "station-life", now: time.Now()}
}

// addToken inserts a token and one active certificate for it. lostAgo zero means the token is not lost.
func (f lifecycleFixture) addToken(t *testing.T, serial, status string, lostAgo time.Duration) string {
	t.Helper()
	var lostAt *time.Time
	if lostAgo > 0 {
		value := f.now.Add(-lostAgo)
		lostAt = &value
	}
	var tokenID string
	if err := f.store.Pool.QueryRow(f.ctx, `
		INSERT INTO tokens(vendor, serial, status, assigned_user_id, last_station_id, lost_at)
		VALUES('Yubico', $1, $2, $3::uuid, $4, $5)
		RETURNING id::text
	`, serial, status, f.userID, f.station, lostAt).Scan(&tokenID); err != nil {
		t.Fatal(err)
	}
	tx, err := f.store.Pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.InsertCertificate(f.ctx, tx, db.CertificateRecord{
		TokenID: tokenID, Slot: "9a", Profile: "piv-authentication", UserID: f.userID,
		SerialNumber: "cert-" + serial, Subject: "CN=life-user",
		NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(time.Hour * 24),
		IssuedByStation: f.station, DER: []byte{1, 2, 3},
	}); err != nil {
		_ = tx.Rollback(f.ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	return tokenID
}

func (f lifecycleFixture) certificateStatus(t *testing.T, serial string) string {
	t.Helper()
	var status string
	if err := f.store.Pool.QueryRow(f.ctx, `
		SELECT status FROM certificates WHERE serial_number = $1
	`, "cert-"+serial).Scan(&status); err != nil {
		t.Fatal(err)
	}
	return status
}

func (f lifecycleFixture) job(authority *fakeCA, grace time.Duration) *LostKeys {
	j := NewLostKeys(f.store, map[string]ca.CA{"dev-step": authority}, map[string]string{"piv-authentication": "dev-step"}, grace, slog.New(slog.NewTextHandler(io.Discard, nil)))
	j.now = func() time.Time { return f.now }
	return j
}

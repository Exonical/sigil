package audit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/sigil/backend/internal/db"
	"github.com/Exonical/sigil/backend/internal/testdb"
)

func TestCanonicalJSONIsStable(t *testing.T) {
	first, err := json.Marshal(map[string]any{"z": "last", "a": map[string]int{"y": 2, "b": 1}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(map[string]any{"a": map[string]int{"b": 1, "y": 2}, "z": "last"})
	if err != nil {
		t.Fatal(err)
	}
	firstCanonical, err := CanonicalJSON(first)
	if err != nil {
		t.Fatal(err)
	}
	secondCanonical, err := CanonicalJSON(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstCanonical) != string(secondCanonical) {
		t.Fatalf("canonical values differ: %s != %s", firstCanonical, secondCanonical)
	}
}

func TestAuditAppendVerifyAndImmutableTrigger(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	seq, err := appendTestEvent(ctx, store, "created")
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(ctx, store.Pool); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `UPDATE audit_events SET action='tampered' WHERE seq=$1`, seq); err == nil {
		t.Fatal("audit event UPDATE unexpectedly succeeded")
	}
}

func TestAuditVerifyFindsTamperingAfterTriggerIsDisabled(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	seq, err := appendTestEvent(ctx, store, "before")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := store.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `ALTER TABLE audit_events DISABLE TRIGGER audit_events_reject_update_delete`); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE audit_events SET action='tampered' WHERE seq=$1`, seq); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `ALTER TABLE audit_events ENABLE TRIGGER audit_events_reject_update_delete`); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	err = Verify(ctx, store.Pool)
	if err == nil || !strings.Contains(err.Error(), "seq 1") {
		t.Fatalf("verify error = %v, want first broken seq %d", err, seq)
	}
}

func openTestStore(t *testing.T) *db.Store {
	t.Helper()
	store, cleanup, err := testdb.Open(context.Background())
	if errors.Is(err, testdb.ErrNotConfigured) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	return store
}

func appendTestEvent(ctx context.Context, store *db.Store, action string) (int64, error) {
	tx, err := store.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	seq, err := Append(ctx, tx, Event{
		OccurredAt: time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.FixedZone("test", -7*60*60)),
		ActorType:  "system",
		ActorID:    "test",
		Action:     action,
		TargetType: "test",
		TargetID:   "row",
		Outcome:    "success",
		Detail:     map[string]any{"z": 2, "a": "value"},
	})
	if err != nil {
		_ = tx.Rollback(ctx)
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return seq, nil
}

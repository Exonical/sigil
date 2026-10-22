package gateway

import (
	"testing"

	"github.com/Exonical/sigil/backend/internal/db"
)

func TestRotationState(t *testing.T) {
	tests := []struct {
		name   string
		states []db.EscrowState
		want   rotationStatus
	}{
		{"pending", []db.EscrowState{db.EscrowPending, db.EscrowPending}, rotationPending},
		{"abandoned", []db.EscrowState{db.EscrowAbandoned}, rotationAbandoned},
		{"unconfirmed", []db.EscrowState{db.EscrowUnconfirmed, db.EscrowUnconfirmed}, rotationUnconfirmed},
		{"active", []db.EscrowState{db.EscrowActive}, rotationApplied},
		{"active and superseded", []db.EscrowState{db.EscrowSuperseded, db.EscrowActive}, rotationApplied},
		{"applied with pending", []db.EscrowState{db.EscrowActive, db.EscrowPending}, rotationMixed},
		{"pending with abandoned", []db.EscrowState{db.EscrowPending, db.EscrowAbandoned}, rotationMixed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			secrets := make([]db.EscrowSecret, len(test.states))
			for i, state := range test.states {
				secrets[i].State = state
			}
			if got := rotationState(secrets); got != test.want {
				t.Fatalf("rotationState() = %q, want %q", got, test.want)
			}
		})
	}
}

package grants

import (
	"testing"

	agentv1 "github.com/Exonical/sigil/backend/gen/sigil/agent/v1"
)

func TestValidatePIVSlot(t *testing.T) {
	tests := []struct {
		name      string
		operation agentv1.Operation
		slot      uint32
		wantError bool
	}{
		{"key generation requires slot", agentv1.Operation_PIV_GENERATE_KEY, 0x9a, false},
		{"certificate import requires slot", agentv1.Operation_PIV_IMPORT_CERTIFICATE, 0x9c, false},
		{"certificate deletion requires slot", agentv1.Operation_PIV_DELETE_CERTIFICATE, 0x9d, false},
		{"key deletion requires slot", agentv1.Operation_PIV_DELETE_KEY, 0x9a, false},
		{"unblock does not use a slot", agentv1.Operation_PIV_UNBLOCK_PIN, 0, false},
		{"missing operation slot", agentv1.Operation_PIV_GENERATE_KEY, 0, true},
		{"missing key deletion slot", agentv1.Operation_PIV_DELETE_KEY, 0, true},
		{"unexpected operation slot", agentv1.Operation_PIV_UNBLOCK_PIN, 0x9a, true},
		{"slot is wider than a PIV slot byte", agentv1.Operation_PIV_GENERATE_KEY, 256, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidatePIVSlot(test.operation, test.slot)
			if (err != nil) != test.wantError {
				t.Fatalf("ValidatePIVSlot error = %v, wantError=%v", err, test.wantError)
			}
		})
	}
}

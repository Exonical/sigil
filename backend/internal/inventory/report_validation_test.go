package inventory

import (
	"errors"
	"strings"
	"testing"

	backendv1 "github.com/Exonical/sigil/backend/gen/sigil/backend/v1"
	"github.com/Exonical/sigil/backend/internal/db"
)

func TestValidateReport(t *testing.T) {
	valid := func() *backendv1.ObservedToken {
		return &backendv1.ObservedToken{
			Vendor: "Yubico", Model: "YubiKey", Serial: "12345678",
			Firmware: "5.7.4", FormFactor: "USB-C", Connection: "usb_smart_card",
		}
	}
	tooMany := make([]*backendv1.ObservedToken, 65)
	for i := range tooMany {
		tooMany[i] = valid()
	}
	tests := []struct {
		name   string
		tokens []*backendv1.ObservedToken
	}{
		{name: "more than 64 tokens", tokens: tooMany},
		{name: "empty vendor after trimming", tokens: []*backendv1.ObservedToken{{Vendor: "  ", Serial: "123"}}},
		{name: "empty serial after trimming", tokens: []*backendv1.ObservedToken{{Vendor: "Yubico", Serial: "   "}}},
		{name: "serial exceeds 64 bytes", tokens: []*backendv1.ObservedToken{{Vendor: "Yubico", Serial: strings.Repeat("x", 65)}}},
		{name: "other field exceeds 128 bytes", tokens: []*backendv1.ObservedToken{{Vendor: "Yubico", Serial: "123", Model: strings.Repeat("x", 129)}}},
		{name: "control character is rejected", tokens: []*backendv1.ObservedToken{{Vendor: "Yubico", Serial: "123", Firmware: "secret\nvalue"}}},
		{name: "nil entry is rejected", tokens: []*backendv1.ObservedToken{nil}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ValidateReport(test.tokens)
			var validationErr *ValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("validation error = %v, want ValidationError", err)
			}
			if strings.Contains(validationErr.Error(), "secret") {
				t.Fatalf("validation error echoed a field value: %q", validationErr.Error())
			}
		})
	}

	trimmed, err := ValidateReport([]*backendv1.ObservedToken{{
		Vendor: "  Yubico ", Model: " Key  ", Serial: " 12345678 ",
		Firmware: " 5.7.4 ", FormFactor: " USB-C ", Connection: " usb_smart_card ",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(trimmed) != 1 {
		t.Fatalf("validated token count=%d, want 1", len(trimmed))
	}
	want := db.ObservedToken{
		Vendor: "Yubico", Model: "Key", Serial: "12345678",
		Firmware: "5.7.4", FormFactor: "USB-C", Connection: "usb_smart_card",
	}
	if trimmed[0] != want {
		t.Fatalf("normalized token=%+v, want %+v", trimmed[0], want)
	}
}

func TestValidateReportLimitsSerialByBytes(t *testing.T) {
	_, err := ValidateReport([]*backendv1.ObservedToken{{
		Vendor: "Yubico", Serial: strings.Repeat("é", 33),
	}})
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("multibyte serial error=%v, want byte limit rejection", err)
	}
}

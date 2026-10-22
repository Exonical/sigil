package inventory

import (
	"context"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	backendv1 "github.com/Exonical/sigil/backend/gen/sigil/backend/v1"
	"github.com/Exonical/sigil/backend/internal/audit"
	"github.com/Exonical/sigil/backend/internal/db"
)

type Repository struct {
	store *db.Store
}

type ValidationError struct {
	reason string
}

func (e *ValidationError) Error() string {
	return e.reason
}

func ValidateReport(tokens []*backendv1.ObservedToken) ([]db.ObservedToken, error) {
	if len(tokens) > 64 {
		return nil, &ValidationError{reason: "token report exceeds 64 entries"}
	}
	normalized := make([]db.ObservedToken, 0, len(tokens))
	for _, token := range tokens {
		if token == nil {
			return nil, &ValidationError{reason: "token report contains an empty entry"}
		}
		fields := []struct {
			value string
			limit int
		}{
			{value: token.Vendor, limit: 128},
			{value: token.Model, limit: 128},
			{value: token.Serial, limit: 64},
			{value: token.Firmware, limit: 128},
			{value: token.FormFactor, limit: 128},
			{value: token.Connection, limit: 128},
		}
		for _, field := range fields {
			if len(field.value) > field.limit {
				return nil, &ValidationError{reason: "token report field exceeds its byte limit"}
			}
			if !utf8.ValidString(field.value) {
				return nil, &ValidationError{reason: "token report contains invalid text"}
			}
			for _, character := range field.value {
				if unicode.IsControl(character) {
					return nil, &ValidationError{reason: "token report contains a control character"}
				}
			}
		}
		vendor := strings.TrimSpace(token.Vendor)
		serial := strings.TrimSpace(token.Serial)
		if vendor == "" || serial == "" {
			return nil, &ValidationError{reason: "token vendor and serial are required"}
		}
		normalized = append(normalized, db.ObservedToken{
			Vendor:     vendor,
			Model:      strings.TrimSpace(token.Model),
			Serial:     serial,
			Firmware:   strings.TrimSpace(token.Firmware),
			FormFactor: strings.TrimSpace(token.FormFactor),
			Connection: strings.TrimSpace(token.Connection),
		})
	}
	return normalized, nil
}

func New(store *db.Store) *Repository {
	return &Repository{store: store}
}

func (r *Repository) FindToken(ctx context.Context, vendor, serial string) (db.Token, error) {
	return r.store.TokenByVendorSerial(ctx, vendor, serial)
}

func (r *Repository) Report(ctx context.Context, stationID string, tokens []*backendv1.ObservedToken) error {
	normalized, err := ValidateReport(tokens)
	if err != nil {
		return err
	}
	tx, err := r.store.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin token inventory report: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, token := range normalized {
		if err := db.InsertObservedToken(ctx, tx, stationID, token); err != nil {
			return err
		}
		if _, err := audit.Append(ctx, tx, audit.Event{
			ActorType:  "station",
			ActorID:    stationID,
			Action:     "ReportTokens",
			TargetType: "token",
			TargetID:   token.Vendor + "|" + token.Serial,
			Outcome:    "success",
			Detail: map[string]any{
				"model":       token.Model,
				"firmware":    token.Firmware,
				"form_factor": token.FormFactor,
				"connection":  token.Connection,
			},
		}); err != nil {
			return err
		}
	}
	if len(tokens) == 0 {
		if _, err := audit.Append(ctx, tx, audit.Event{
			ActorType:  "station",
			ActorID:    stationID,
			Action:     "ReportTokens",
			TargetType: "inventory",
			TargetID:   stationID,
			Outcome:    "success",
			Detail:     map[string]any{"token_count": 0},
		}); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit token inventory report: %w", err)
	}
	return nil
}

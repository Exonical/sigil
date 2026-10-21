package grants

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	agentv1 "github.com/Exonical/sigil/backend/gen/sigil/agent/v1"
	"github.com/Exonical/sigil/backend/internal/audit"
	"github.com/Exonical/sigil/backend/internal/db"
	"github.com/Exonical/sigil/backend/internal/signing"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

type IssueRequest struct {
	Operation    agentv1.Operation
	UserID       string
	Subject      string
	StationID    string
	TokenSerial  string
	CallerOSUser string
	PIVSlot      uint32
	Lifetime     time.Duration
	Now          time.Time
	PolicyReason string
}

func Issue(ctx context.Context, pool *pgxpool.Pool, signer signing.Signer, request IssueRequest) (*agentv1.SignedGrant, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin grant transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	signed, err := IssueInTx(ctx, tx, signer, request, "RequestGrant")
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit grant transaction: %w", err)
	}
	committed = true
	return signed, nil
}

func IssueInTx(ctx context.Context, tx pgx.Tx, signer signing.Signer, request IssueRequest, auditAction string) (*agentv1.SignedGrant, error) {
	if signer == nil {
		return nil, errors.New("grant signer is not configured")
	}
	if request.Lifetime < 30*time.Second || request.Lifetime > 300*time.Second {
		return nil, errors.New("grant lifetime must be between 30 and 300 seconds")
	}
	if request.Operation == agentv1.Operation_OPERATION_UNSPECIFIED ||
		agentv1.Operation_name[int32(request.Operation)] == "" {
		return nil, errors.New("grant operation is invalid")
	}
	if err := ValidatePIVSlot(request.Operation, request.PIVSlot); err != nil {
		return nil, err
	}
	if request.StationID == "" || request.TokenSerial == "" || request.UserID == "" {
		return nil, errors.New("grant identity and token fields are required")
	}
	if request.Now.IsZero() {
		request.Now = time.Now()
	}
	if auditAction == "" {
		auditAction = "RequestGrant"
	}
	request.Now = request.Now.UTC().Truncate(time.Second)
	grantID, err := randomGrantID()
	if err != nil {
		return nil, err
	}
	grant := &agentv1.OperationGrant{
		Version:       1,
		GrantId:       grantID,
		Operation:     request.Operation,
		Subject:       request.Subject,
		StationId:     request.StationID,
		TokenSerial:   request.TokenSerial,
		CallerOsUser:  request.CallerOSUser,
		NotBeforeUnix: request.Now.Unix(),
		ExpiresAtUnix: request.Now.Add(request.Lifetime).Unix(),
		PivSlot:       request.PIVSlot,
	}
	grantBytes, err := (proto.MarshalOptions{Deterministic: true}).Marshal(grant)
	if err != nil {
		return nil, fmt.Errorf("marshal operation grant: %w", err)
	}
	signature, err := signer.Sign(grantBytes)
	if err != nil {
		return nil, fmt.Errorf("sign operation grant: %w", err)
	}
	signed := &agentv1.SignedGrant{
		Grant:     grantBytes,
		Signature: signature,
		KeyId:     signer.KeyID(),
	}
	if signed.KeyId == "" {
		return nil, errors.New("grant signer has no key ID")
	}

	operationName := agentv1.Operation_name[int32(request.Operation)]
	if err := db.InsertGrant(ctx, tx, db.GrantRecord{
		ID: grantID, Operation: operationName, UserID: request.UserID,
		StationID: request.StationID, TokenSerial: request.TokenSerial, PIVSlot: request.PIVSlot,
		CallerOSUser: request.CallerOSUser, NotBefore: grant.NotBeforeUnix,
		ExpiresAt: grant.ExpiresAtUnix, KeyID: signed.KeyId,
	}); err != nil {
		return nil, err
	}
	if _, err := audit.Append(ctx, tx, audit.Event{
		ActorType:  "user",
		ActorID:    request.UserID,
		Action:     auditAction,
		TargetType: "token",
		TargetID:   request.TokenSerial,
		Outcome:    "success",
		Detail: map[string]any{
			"grant_id":  grantID,
			"operation": operationName,
			"station":   request.StationID,
			"piv_slot":  request.PIVSlot,
			"reason":    request.PolicyReason,
			"key_id":    signed.KeyId,
		},
	}); err != nil {
		return nil, err
	}
	return signed, nil
}

func ValidatePIVSlot(operation agentv1.Operation, slot uint32) error {
	if slot > 255 {
		return errors.New("PIV slot must fit in one byte")
	}
	slotSpecific := operation == agentv1.Operation_PIV_GENERATE_KEY ||
		operation == agentv1.Operation_PIV_IMPORT_CERTIFICATE ||
		operation == agentv1.Operation_PIV_DELETE_CERTIFICATE ||
		operation == agentv1.Operation_PIV_DELETE_KEY
	if slotSpecific && slot == 0 {
		return errors.New("PIV operation requires a slot")
	}
	if !slotSpecific && slot != 0 {
		return errors.New("PIV operation does not accept a slot")
	}
	return nil
}

func randomGrantID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("generate grant ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(random[:]), nil
}

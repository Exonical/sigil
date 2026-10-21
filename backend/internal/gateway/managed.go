package gateway

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"time"

	agentv1 "github.com/Exonical/sigil/backend/gen/sigil/agent/v1"
	backendv1 "github.com/Exonical/sigil/backend/gen/sigil/backend/v1"
	"github.com/Exonical/sigil/backend/internal/audit"
	"github.com/Exonical/sigil/backend/internal/db"
	"github.com/Exonical/sigil/backend/internal/escrow"
	"github.com/Exonical/sigil/backend/internal/grants"
	"github.com/Exonical/sigil/backend/internal/policy"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	managedPUK           = "puk"
	managedManagementKey = "management_key"
	rotationMaxAge       = 15 * time.Minute
)

type managedSecretSpec struct {
	kind      string
	algorithm string
}

type managedPlan struct {
	current  []string
	new      []managedSecretSpec
	rotation bool
}

type releasedSecret struct {
	record db.EscrowSecret
	value  []byte
}

type pendingSecret struct {
	record              db.NewEscrowSecret
	unconfirmedVersions []int
}

func (s *Server) AuthorizeManagedOperation(
	ctx context.Context,
	request *backendv1.AuthorizeManagedOperationRequest,
) (*backendv1.AuthorizeManagedOperationResponse, error) {
	authorization, err := s.authorize(
		ctx,
		request.AccessToken,
		request.TokenVendor,
		request.TokenSerial,
		request.Operation,
		request.PivSlot,
		"AuthorizeManagedOperation",
	)
	if err != nil {
		return nil, err
	}
	operationName := agentv1.Operation_name[int32(request.Operation)]
	if request.Operation == agentv1.Operation_PIV_SET_RETRIES {
		reason := "PIV_SET_RETRIES is not supported in managed mode"
		if auditErr := s.auditEvent(ctx, "user", authorization.principal.UserID, "AuthorizeManagedOperation", "token", request.TokenSerial, "denied", reason); auditErr != nil {
			return nil, status.Error(codes.Internal, "could not record managed-operation decision")
		}
		return nil, status.Error(codes.InvalidArgument, reason)
	}
	plan, ok := planManagedOperation(request.Operation)
	if !ok {
		reason := "operation is not supported by managed escrow"
		if auditErr := s.auditEvent(ctx, "user", authorization.principal.UserID, "AuthorizeManagedOperation", "token", request.TokenSerial, "denied", reason); auditErr != nil {
			return nil, status.Error(codes.Internal, "could not record managed-operation decision")
		}
		return nil, status.Error(codes.InvalidArgument, reason)
	}
	if s.escrowErr != nil {
		if auditErr := s.auditEvent(ctx, "user", authorization.principal.UserID, "AuthorizeManagedOperation", "token", request.TokenSerial, "error", "escrow key configuration is invalid"); auditErr != nil {
			return nil, status.Error(codes.Internal, "could not record managed-operation decision")
		}
		return nil, status.Error(codes.Internal, "managed escrow is unavailable")
	}
	if s.escrow == nil {
		if auditErr := s.auditEvent(ctx, "user", authorization.principal.UserID, "AuthorizeManagedOperation", "token", request.TokenSerial, "error", "escrow is not configured"); auditErr != nil {
			return nil, status.Error(codes.Internal, "could not record managed-operation decision")
		}
		return nil, status.Error(codes.FailedPrecondition, "managed escrow is not configured")
	}

	tx, err := s.store.Pool.Begin(ctx)
	if err != nil {
		s.logger.Error("begin managed operation transaction failed", "error", err)
		return nil, status.Error(codes.Internal, "could not authorize managed operation")
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	reject := func(code codes.Code, outcome, reason string, detail map[string]any) error {
		if detail == nil {
			detail = map[string]any{}
		}
		detail["operation"] = operationName
		detail["reason"] = reason
		if err := appendAudit(ctx, tx, "user", authorization.principal.UserID, "AuthorizeManagedOperation", "token", request.TokenSerial, outcome, detail); err != nil {
			return status.Error(codes.Internal, "could not record managed-operation decision")
		}
		if err := tx.Commit(ctx); err != nil {
			return status.Error(codes.Internal, "could not record managed-operation decision")
		}
		committed = true
		return status.Error(code, reason)
	}

	token, err := db.LockToken(ctx, tx, request.TokenVendor, request.TokenSerial)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, reject(codes.PermissionDenied, "denied", "token is not in inventory", nil)
	}
	if err != nil {
		s.logger.Error("lock managed token failed", "error", err)
		return nil, status.Error(codes.Internal, "could not look up token inventory")
	}
	decision := s.policy.Authorize(policy.Request{
		Roles:                 rolesFor(authorization.principal.Groups, s.config.OIDC.RoleGroups),
		Station:               authorization.station,
		Token:                 &token,
		Operation:             request.Operation,
		UserID:                authorization.principal.UserID,
		SelfServiceOperations: s.config.Policy.SelfServiceOperations,
	})
	if !decision.Allowed {
		return nil, reject(codes.PermissionDenied, "denied", decision.Reason, map[string]any{"station": authorization.station.ID})
	}
	authorization.token = token
	authorization.decision = decision

	plaintexts := make([][]byte, 0, len(plan.current)+len(plan.new))
	defer func() {
		for _, value := range plaintexts {
			clear(value)
		}
	}()
	response := &backendv1.AuthorizeManagedOperationResponse{}
	defer func() {
		if committed {
			return
		}
		for _, secret := range []*backendv1.EscrowedSecret{
			response.CurrentManagementKey, response.CurrentPuk,
			response.NewManagementKey, response.NewPuk,
		} {
			if secret != nil {
				clear(secret.Value)
			}
		}
	}()
	released := make([]releasedSecret, 0, len(plan.current))
	for _, kind := range plan.current {
		record, err := db.ActiveEscrowSecret(ctx, tx, token.ID, kind)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, reject(codes.FailedPrecondition, "denied", "token is not managed by Sigil", map[string]any{"kind": kind})
		}
		if err != nil {
			s.logger.Error("read active escrow secret failed", "error", err)
			return nil, status.Error(codes.Internal, "could not read managed token secret")
		}
		value, err := s.escrow.Decrypt(escrow.Context{
			Vendor: token.Vendor, Serial: token.Serial, Kind: record.Kind,
			Algorithm: record.Algorithm, Version: record.Version,
		}, escrow.Envelope{
			KEKID: record.KEKID, DEKNonce: record.DEKNonce, WrappedDEK: record.WrappedDEK,
			Nonce: record.Nonce, Ciphertext: record.Ciphertext,
		})
		if err != nil {
			s.logger.Error("decrypt active escrow secret failed", "kind", kind, "version", record.Version)
			return nil, reject(codes.Internal, "error", "managed token secret could not be decrypted", map[string]any{
				"kind": kind, "version": record.Version,
			})
		}
		plaintexts = append(plaintexts, value)
		released = append(released, releasedSecret{record: record, value: value})
		setReleasedSecret(response, kind, value, record.Algorithm)
	}

	pending := make([]pendingSecret, 0, len(plan.new))
	previousActiveVersions := make(map[string]int)
	for _, specification := range plan.new {
		if request.Operation == agentv1.Operation_PIV_MANAGED_INITIALIZE {
			active, err := db.ActiveEscrowSecret(ctx, tx, token.ID, specification.kind)
			if err == nil {
				previousActiveVersions[specification.kind] = active.Version
			} else if !errors.Is(err, pgx.ErrNoRows) {
				s.logger.Error("check active escrow secret failed", "kind", specification.kind, "error", err)
				return nil, status.Error(codes.Internal, "could not read managed token state")
			}
		}
		unconfirmedVersions, err := db.MarkPendingEscrowUnconfirmed(ctx, tx, token.ID, specification.kind)
		if err != nil {
			s.logger.Error("mark previous escrow rotation unconfirmed failed", "kind", specification.kind, "error", err)
			return nil, status.Error(codes.Internal, "could not begin secret rotation")
		}
		version, err := db.NextEscrowVersion(ctx, tx, token.ID, specification.kind)
		if err != nil {
			s.logger.Error("allocate escrow secret version failed", "kind", specification.kind, "error", err)
			return nil, status.Error(codes.Internal, "could not begin secret rotation")
		}
		value, err := generateManagedSecret(specification)
		if err != nil {
			s.logger.Error("generate escrow secret failed", "kind", specification.kind, "error", err)
			return nil, status.Error(codes.Internal, "could not generate managed token secret")
		}
		plaintexts = append(plaintexts, value)
		context := escrow.Context{
			Vendor: token.Vendor, Serial: token.Serial, Kind: specification.kind,
			Algorithm: specification.algorithm, Version: version,
		}
		envelope, err := s.escrow.Encrypt(context, value)
		if err != nil {
			s.logger.Error("encrypt escrow secret failed", "kind", specification.kind, "version", version)
			return nil, status.Error(codes.Internal, "could not protect managed token secret")
		}
		pending = append(pending, pendingSecret{
			record: db.NewEscrowSecret{
				TokenID: token.ID, Kind: specification.kind, Algorithm: specification.algorithm,
				Version: version, KEKID: envelope.KEKID, DEKNonce: envelope.DEKNonce,
				WrappedDEK: envelope.WrappedDEK, Nonce: envelope.Nonce, Ciphertext: envelope.Ciphertext,
				StationID: authorization.station.ID,
			},
			unconfirmedVersions: unconfirmedVersions,
		})
		setNewSecret(response, specification.kind, value, specification.algorithm)
	}

	signed, err := grants.IssueInTx(ctx, tx, s.signer, grants.IssueRequest{
		Operation:    request.Operation,
		UserID:       authorization.principal.UserID,
		Subject:      authorization.principal.Issuer + "|" + authorization.principal.Subject,
		StationID:    authorization.station.ID,
		TokenSerial:  token.Serial,
		CallerOSUser: request.CallerOsUser,
		PIVSlot:      request.PivSlot,
		Lifetime:     timeSeconds(s.config.Grants.LifetimeSeconds),
		PolicyReason: decision.Reason,
	}, "AuthorizeManagedOperation")
	if err != nil {
		s.logger.Error("issue managed operation grant failed", "error", err)
		return nil, status.Error(codes.Internal, "could not issue managed-operation grant")
	}
	response.Grant = signed
	if plan.rotation {
		var operationGrant agentv1.OperationGrant
		if err := proto.Unmarshal(signed.Grant, &operationGrant); err != nil {
			return nil, status.Error(codes.Internal, "could not decode managed-operation grant")
		}
		response.RotationId = operationGrant.GrantId
	}
	for _, secret := range pending {
		secret.record.GrantID = response.RotationId
		if err := db.InsertEscrowSecret(ctx, tx, secret.record); err != nil {
			s.logger.Error("insert pending escrow secret failed", "kind", secret.record.Kind, "version", secret.record.Version, "error", err)
			return nil, status.Error(codes.Internal, "could not store pending managed token secret")
		}
	}
	for _, secret := range released {
		if err := appendAudit(ctx, tx, "user", authorization.principal.UserID, "ReleaseEscrow", "token", token.Serial, "success", map[string]any{
			"operation": operationName,
			"kind":      secret.record.Kind,
			"version":   secret.record.Version,
		}); err != nil {
			return nil, status.Error(codes.Internal, "could not record escrow release")
		}
	}
	if len(pending) != 0 {
		versions := make([]map[string]any, 0, len(pending))
		for _, secret := range pending {
			versions = append(versions, map[string]any{
				"kind":                     secret.record.Kind,
				"version":                  secret.record.Version,
				"unconfirmed_old_versions": secret.unconfirmedVersions,
			})
		}
		detail := map[string]any{
			"operation":   operationName,
			"rotation_id": response.RotationId,
			"secrets":     versions,
		}
		if request.Operation == agentv1.Operation_PIV_MANAGED_INITIALIZE {
			detail["previous_active_versions"] = previousActiveVersions
		}
		if err := appendAudit(ctx, tx, "user", authorization.principal.UserID, "BeginRotation", "token", token.Serial, "success", detail); err != nil {
			return nil, status.Error(codes.Internal, "could not record secret rotation")
		}
	}
	if err := tx.Commit(ctx); err != nil {
		s.logger.Error("commit managed operation failed", "error", err)
		return nil, status.Error(codes.Internal, "could not commit managed operation")
	}
	committed = true
	return response, nil
}

func (s *Server) CompleteRotation(
	ctx context.Context,
	request *backendv1.CompleteRotationRequest,
) (*backendv1.CompleteRotationResponse, error) {
	station, actorID, err := s.authenticatedStation(ctx)
	if err != nil {
		return nil, err
	}
	if request.RotationId == "" {
		if auditErr := s.auditEvent(ctx, "station", actorID, "CompleteRotation", "rotation", "", "denied", "rotation ID is required"); auditErr != nil {
			return nil, status.Error(codes.Internal, "could not record rotation completion")
		}
		return nil, status.Error(codes.InvalidArgument, "rotation ID is required")
	}
	tx, err := s.store.Pool.Begin(ctx)
	if err != nil {
		s.logger.Error("begin rotation completion failed", "error", err)
		return nil, status.Error(codes.Internal, "could not complete secret rotation")
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	finish := func(outcome, state string) (*backendv1.CompleteRotationResponse, error) {
		if err := appendAudit(ctx, tx, "station", station.ID, "CompleteRotation", "rotation", request.RotationId, outcome, map[string]any{
			"applied": request.Applied,
			"state":   state,
		}); err != nil {
			return nil, status.Error(codes.Internal, "could not record rotation completion")
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, status.Error(codes.Internal, "could not record rotation completion")
		}
		committed = true
		return &backendv1.CompleteRotationResponse{}, nil
	}
	reject := func(code codes.Code, outcome, reason string, state string) (*backendv1.CompleteRotationResponse, error) {
		if err := appendAudit(ctx, tx, "station", station.ID, "CompleteRotation", "rotation", request.RotationId, outcome, map[string]any{
			"applied": request.Applied,
			"reason":  reason,
			"state":   state,
		}); err != nil {
			return nil, status.Error(codes.Internal, "could not record rotation completion")
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, status.Error(codes.Internal, "could not record rotation completion")
		}
		committed = true
		return nil, status.Error(code, reason)
	}

	secrets, err := db.EscrowRotation(ctx, tx, request.RotationId)
	if err != nil {
		s.logger.Error("read escrow rotation failed", "error", err)
		return nil, status.Error(codes.Internal, "could not look up secret rotation")
	}
	if len(secrets) == 0 {
		return reject(codes.NotFound, "denied", "secret rotation was not found", "missing")
	}
	for _, secret := range secrets {
		if secret.StationID != station.ID {
			return reject(codes.PermissionDenied, "denied", "rotation belongs to a different station", secret.State)
		}
	}
	state := rotationState(secrets)
	if request.Applied && state == "applied" || !request.Applied && state == "abandoned" {
		return finish("success", state)
	}
	if state != "pending" {
		return reject(codes.FailedPrecondition, "denied", "secret rotation is no longer pending", state)
	}
	if request.Applied {
		now := s.now
		if now == nil {
			now = time.Now
		}
		expired := false
		for _, secret := range secrets {
			if now().Sub(secret.CreatedAt) > rotationMaxAge {
				expired = true
				break
			}
		}
		if expired {
			if err := db.UpdateEscrowRotationState(ctx, tx, request.RotationId, "pending", "unconfirmed"); err != nil {
				s.logger.Error("mark expired rotation unconfirmed failed", "error", err)
				return nil, status.Error(codes.Internal, "could not record rotation state")
			}
			return reject(codes.FailedPrecondition, "denied", "pending secret rotation is older than 15 minutes", "unconfirmed")
		}
		if err := db.ActivateEscrowRotation(ctx, tx, secrets); err != nil {
			s.logger.Error("activate escrow rotation failed", "error", err)
			return nil, status.Error(codes.Internal, "could not activate secret rotation")
		}
		return finish("success", "applied")
	}
	if err := db.UpdateEscrowRotationState(ctx, tx, request.RotationId, "pending", "abandoned"); err != nil {
		s.logger.Error("abandon escrow rotation failed", "error", err)
		return nil, status.Error(codes.Internal, "could not abandon secret rotation")
	}
	return finish("success", "abandoned")
}

func (s *Server) ReportAudit(
	ctx context.Context,
	request *backendv1.ReportAuditRequest,
) (*backendv1.ReportAuditResponse, error) {
	station, actorID, err := s.authenticatedStation(ctx)
	if err != nil {
		return nil, err
	}
	if len(request.Events) > 500 {
		if auditErr := s.auditEvent(ctx, "station", actorID, "ReportAudit", "station", station.ID, "denied", "audit batch exceeds 500 events"); auditErr != nil {
			return nil, status.Error(codes.Internal, "could not record audit batch decision")
		}
		return nil, status.Error(codes.InvalidArgument, "audit batch exceeds 500 events")
	}
	events := append([]*backendv1.AgentAuditEvent(nil), request.Events...)
	for _, event := range events {
		if event == nil || event.Sequence > uint64(1<<63-1) {
			if auditErr := s.auditEvent(ctx, "station", actorID, "ReportAudit", "station", station.ID, "denied", "audit batch contains an invalid event"); auditErr != nil {
				return nil, status.Error(codes.Internal, "could not record audit batch decision")
			}
			return nil, status.Error(codes.InvalidArgument, "audit batch contains an invalid event")
		}
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].Sequence < events[j].Sequence })
	tx, err := s.store.Pool.Begin(ctx)
	if err != nil {
		s.logger.Error("begin agent audit import failed", "error", err)
		return nil, status.Error(codes.Internal, "could not record agent audit events")
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	cursor, err := db.LockStationAuditCursor(ctx, tx, station.ID)
	if err != nil {
		s.logger.Error("lock station audit cursor failed", "error", err)
		return nil, status.Error(codes.Internal, "could not record agent audit events")
	}
	for _, event := range events {
		sequence := int64(event.Sequence)
		if sequence <= cursor {
			continue
		}
		rpcName := event.Rpc
		if rpcName == "" {
			rpcName = "Unknown"
		}
		detail := map[string]any{
			"sequence":            event.Sequence,
			"occurred_at_unix_ms": event.OccurredAtUnixMs,
			"rpc":                 event.Rpc,
			"operation":           event.Operation,
			"device_id":           event.DeviceId,
			"token_serial":        event.TokenSerial,
			"caller_os_user":      event.CallerOsUser,
			"caller_session_id":   event.CallerSessionId,
			"code":                event.Code,
			"grant_id":            event.GrantId,
			"rotation_id":         event.RotationId,
		}
		if err := appendAudit(ctx, tx, "station", station.ID, "Agent."+rpcName, "token", event.TokenSerial, agentAuditOutcome(event.Outcome), detail); err != nil {
			s.logger.Error("append agent audit event failed", "sequence", event.Sequence, "error", err)
			return nil, status.Error(codes.Internal, "could not record agent audit events")
		}
		cursor = sequence
	}
	if err := db.SetStationAuditCursor(ctx, tx, station.ID, cursor); err != nil {
		s.logger.Error("store station audit cursor failed", "error", err)
		return nil, status.Error(codes.Internal, "could not record agent audit events")
	}
	if err := tx.Commit(ctx); err != nil {
		s.logger.Error("commit agent audit import failed", "error", err)
		return nil, status.Error(codes.Internal, "could not record agent audit events")
	}
	committed = true
	return &backendv1.ReportAuditResponse{AcceptedThrough: uint64(cursor)}, nil
}

func planManagedOperation(operation agentv1.Operation) (managedPlan, bool) {
	switch operation {
	case agentv1.Operation_PIV_MANAGED_INITIALIZE:
		return managedPlan{
			new: []managedSecretSpec{
				{kind: managedPUK},
				{kind: managedManagementKey, algorithm: "aes256"},
			},
			rotation: true,
		}, true
	case agentv1.Operation_PIV_GENERATE_KEY,
		agentv1.Operation_PIV_IMPORT_CERTIFICATE,
		agentv1.Operation_PIV_DELETE_CERTIFICATE,
		agentv1.Operation_PIV_DELETE_KEY:
		return managedPlan{current: []string{managedManagementKey}}, true
	case agentv1.Operation_PIV_UNBLOCK_PIN:
		return managedPlan{current: []string{managedPUK}}, true
	case agentv1.Operation_PIV_CHANGE_MANAGEMENT_KEY:
		return managedPlan{
			current:  []string{managedManagementKey},
			new:      []managedSecretSpec{{kind: managedManagementKey, algorithm: "aes256"}},
			rotation: true,
		}, true
	case agentv1.Operation_PIV_CHANGE_PUK:
		return managedPlan{
			current:  []string{managedPUK},
			new:      []managedSecretSpec{{kind: managedPUK}},
			rotation: true,
		}, true
	default:
		return managedPlan{}, false
	}
}

func generateManagedSecret(spec managedSecretSpec) ([]byte, error) {
	switch spec.kind {
	case managedPUK:
		return escrow.GeneratePUK()
	case managedManagementKey:
		if spec.algorithm != "aes256" {
			return nil, errors.New("managed management-key algorithm is unsupported")
		}
		return escrow.GenerateManagementKey()
	default:
		return nil, errors.New("managed secret kind is unsupported")
	}
}

func setReleasedSecret(response *backendv1.AuthorizeManagedOperationResponse, kind string, value []byte, algorithm string) {
	secret := &backendv1.EscrowedSecret{Value: bytes.Clone(value), Algorithm: algorithm}
	switch kind {
	case managedPUK:
		response.CurrentPuk = secret
	case managedManagementKey:
		response.CurrentManagementKey = secret
	}
}

func setNewSecret(response *backendv1.AuthorizeManagedOperationResponse, kind string, value []byte, algorithm string) {
	secret := &backendv1.EscrowedSecret{Value: bytes.Clone(value), Algorithm: algorithm}
	switch kind {
	case managedPUK:
		response.NewPuk = secret
	case managedManagementKey:
		response.NewManagementKey = secret
	}
}

func rotationState(secrets []db.EscrowSecret) string {
	state := secrets[0].State
	if state == "active" || state == "superseded" {
		for _, secret := range secrets[1:] {
			if secret.State != "active" && secret.State != "superseded" {
				return "mixed"
			}
		}
		return "applied"
	}
	for _, secret := range secrets[1:] {
		if secret.State != state {
			return "mixed"
		}
	}
	return state
}

func agentAuditOutcome(outcome string) string {
	switch outcome {
	case "success":
		return "success"
	case "denied":
		return "denied"
	default:
		return "error"
	}
}

func appendAudit(ctx context.Context, tx pgx.Tx, actorType, actorID, action, targetType, targetID, outcome string, detail map[string]any) error {
	_, err := audit.Append(ctx, tx, audit.Event{
		ActorType: actorType, ActorID: actorID, Action: action,
		TargetType: targetType, TargetID: targetID, Outcome: outcome, Detail: detail,
	})
	return err
}

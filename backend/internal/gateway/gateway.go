package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	agentv1 "github.com/Exonical/sigil/backend/gen/sigil/agent/v1"
	backendv1 "github.com/Exonical/sigil/backend/gen/sigil/backend/v1"
	"github.com/Exonical/sigil/backend/internal/attestation"
	"github.com/Exonical/sigil/backend/internal/audit"
	"github.com/Exonical/sigil/backend/internal/authn"
	"github.com/Exonical/sigil/backend/internal/config"
	"github.com/Exonical/sigil/backend/internal/db"
	"github.com/Exonical/sigil/backend/internal/escrow"
	"github.com/Exonical/sigil/backend/internal/grants"
	"github.com/Exonical/sigil/backend/internal/inventory"
	"github.com/Exonical/sigil/backend/internal/policy"
	"github.com/Exonical/sigil/backend/internal/signing"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type Server struct {
	backendv1.UnimplementedAgentGatewayServer
	store     *db.Store
	inventory *inventory.Repository
	auth      *authn.Authenticator
	signer    signing.Signer
	config    config.Config
	policy    policy.Engine
	logger    *slog.Logger
	escrow    *escrow.Keyring
	escrowErr error
	now       func() time.Time
	issuers   issuanceSettings
}

func New(store *db.Store, authenticator *authn.Authenticator, signer signing.Signer, cfg config.Config, logger *slog.Logger) *Server {
	server := &Server{
		store:     store,
		inventory: inventory.New(store),
		auth:      authenticator,
		signer:    signer,
		config:    cfg,
		policy:    policy.LocalPolicy{},
		logger:    logger,
		now:       time.Now,
		issuers:   issuanceSettings{attest: attestation.Verify},
	}
	if cfg.Escrow.KEKID != "" {
		server.escrow, server.escrowErr = escrow.NewKeyring(
			cfg.Escrow.KEKID, cfg.Escrow.CurrentKey, cfg.Escrow.PreviousKeys,
		)
	}
	return server
}

func (s *Server) Close() {
	if s.escrow != nil {
		s.escrow.Close()
	}
}

func (s *Server) RequestGrant(ctx context.Context, request *backendv1.RequestGrantRequest) (*backendv1.RequestGrantResponse, error) {
	authorization, err := s.authorize(ctx, request.AccessToken, request.TokenVendor, request.TokenSerial,
		request.Operation, request.PivSlot, "RequestGrant")
	if err != nil {
		return nil, err
	}
	if _, managed := planManagedOperation(request.Operation); managed {
		reason := "operation requires managed escrow authorization"
		if auditErr := s.auditEvent(ctx, "user", authorization.principal.UserID, "RequestGrant", "token", request.TokenSerial, audit.OutcomeDenied, reason); auditErr != nil {
			return nil, status.Error(codes.Internal, "could not record grant decision")
		}
		return nil, status.Error(codes.FailedPrecondition, reason)
	}
	signed, err := grants.Issue(ctx, s.store.Pool, s.signer, grants.IssueRequest{
		Operation:    request.Operation,
		UserID:       authorization.principal.UserID,
		Subject:      authorization.principal.Issuer + "|" + authorization.principal.Subject,
		StationID:    authorization.station.ID,
		TokenSerial:  authorization.token.Serial,
		CallerOSUser: request.CallerOsUser,
		PIVSlot:      request.PivSlot,
		Lifetime:     timeSeconds(s.config.Grants.LifetimeSeconds),
		PolicyReason: authorization.decision.Reason,
	})
	if err != nil {
		if auditErr := s.auditEvent(ctx, "user", authorization.principal.UserID, "RequestGrant", "token", request.TokenSerial, audit.OutcomeError, "grant issuance failed"); auditErr != nil {
			s.logger.Error("audit grant issuance failure failed", "error", auditErr)
		}
		s.logger.Error("grant issuance failed", "error", err)
		return nil, status.Error(codes.Internal, "could not issue grant")
	}
	return &backendv1.RequestGrantResponse{Grant: signed}, nil
}

type authorization struct {
	station   db.Station
	principal authn.Principal
	token     db.Token
	decision  policy.Decision
}

func (s *Server) authorize(
	ctx context.Context,
	accessToken, tokenVendor, tokenSerial string,
	operation agentv1.Operation,
	pivSlot uint32,
	rpcName string,
) (authorization, error) {
	station, actorID, err := s.authenticatedStation(ctx)
	if err != nil {
		return authorization{}, err
	}
	principal, err := s.authenticatePrincipal(ctx, actorID, rpcName, tokenSerial, accessToken)
	if err != nil {
		return authorization{}, err
	}
	token, err := s.inventory.FindToken(ctx, tokenVendor, tokenSerial)
	if errors.Is(err, pgx.ErrNoRows) {
		if auditErr := s.auditEvent(ctx, "user", principal.UserID, rpcName, "token", tokenSerial, audit.OutcomeDenied, "token is not in inventory"); auditErr != nil {
			s.logger.Error("audit unknown token decision failed", "error", auditErr)
			return authorization{}, status.Error(codes.Internal, "could not record authorization decision")
		}
		return authorization{}, status.Error(codes.PermissionDenied, "token is not in inventory")
	}
	if err != nil {
		s.logger.Error("token lookup failed", "error", err)
		return authorization{}, status.Error(codes.Internal, "could not look up token inventory")
	}
	decision := s.policy.Authorize(policy.Request{
		Roles:                 rolesFor(principal.Groups, s.config.OIDC.RoleGroups),
		Station:               station,
		Token:                 &token,
		Operation:             operation,
		UserID:                principal.UserID,
		SelfServiceOperations: s.config.Policy.SelfServiceOperations,
	})
	if !decision.Allowed {
		if err := audit.AppendStandalone(ctx, s.store.Pool, audit.Event{
			ActorType:  "user",
			ActorID:    principal.UserID,
			Action:     rpcName,
			TargetType: "token",
			TargetID:   tokenSerial,
			Outcome:    string(audit.OutcomeDenied),
			Detail: map[string]any{
				"operation": agentv1.Operation_name[int32(operation)],
				"station":   station.ID,
				"reason":    decision.Reason,
			},
		}); err != nil {
			s.logger.Error("audit policy denial failed", "error", err)
			return authorization{}, status.Error(codes.Internal, "could not record policy decision")
		}
		return authorization{}, status.Error(codes.PermissionDenied, decision.Reason)
	}
	if err := grants.ValidatePIVSlot(operation, pivSlot); err != nil {
		if auditErr := s.auditEvent(ctx, "user", principal.UserID, rpcName, "token", tokenSerial, audit.OutcomeDenied, err.Error()); auditErr != nil {
			s.logger.Error("audit invalid grant request failed", "error", auditErr)
			return authorization{}, status.Error(codes.Internal, "could not record authorization decision")
		}
		return authorization{}, status.Error(codes.InvalidArgument, err.Error())
	}
	return authorization{
		station: station, principal: principal, token: token, decision: decision,
	}, nil
}

// authenticatePrincipal verifies the caller's OIDC access token. A rejection is audited against the station
// that relayed it; a user store failure is audited and logged as an error rather than a denial.
func (s *Server) authenticatePrincipal(ctx context.Context, actorID, rpcName, tokenSerial, accessToken string) (authn.Principal, error) {
	principal, err := s.auth.Authenticate(ctx, accessToken)
	if err == nil {
		return principal, nil
	}
	storeFailure := errors.Is(err, authn.ErrUserStore)
	outcome := audit.OutcomeDenied
	reason := "OIDC access token rejected"
	if storeFailure {
		outcome = audit.OutcomeError
		reason = "OIDC user persistence failed"
	}
	if auditErr := s.auditEvent(ctx, "station", actorID, rpcName, "token", tokenSerial, outcome, reason); auditErr != nil {
		s.logger.Error("audit OIDC rejection failed", "error", auditErr)
		return authn.Principal{}, status.Error(codes.Internal, "could not record authorization decision")
	}
	if storeFailure {
		s.logger.Error("OIDC user upsert failed", "error", err)
		return authn.Principal{}, status.Error(codes.Internal, "could not record authenticated user")
	}
	return authn.Principal{}, status.Error(codes.Unauthenticated, "OIDC access token is invalid")
}

func timeSeconds(seconds int64) time.Duration {
	return time.Duration(seconds) * time.Second
}

func (s *Server) ReportTokens(ctx context.Context, request *backendv1.ReportTokensRequest) (*backendv1.ReportTokensResponse, error) {
	station, actorID, err := s.authenticatedStation(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.inventory.Report(ctx, station.ID, request.Tokens); err != nil {
		var validationErr *inventory.ValidationError
		if errors.As(err, &validationErr) {
			if auditErr := s.auditEvent(ctx, "station", actorID, "ReportTokens", "inventory", station.ID, audit.OutcomeDenied, validationErr.Error()); auditErr != nil {
				s.logger.Error("audit invalid token report failed", "error", auditErr)
				return nil, status.Error(codes.Internal, "could not record token report decision")
			}
			return nil, status.Error(codes.InvalidArgument, validationErr.Error())
		}
		if auditErr := s.auditEvent(ctx, "station", actorID, "ReportTokens", "inventory", station.ID, audit.OutcomeError, "token report failed"); auditErr != nil {
			s.logger.Error("audit token report failure failed", "error", auditErr)
		}
		s.logger.Error("token report failed", "error", err)
		return nil, status.Error(codes.Internal, "could not record token inventory")
	}
	return &backendv1.ReportTokensResponse{}, nil
}

func (s *Server) authenticatedStation(ctx context.Context) (db.Station, string, error) {
	certificate, err := peerCertificate(ctx)
	if err != nil {
		return db.Station{}, "", status.Error(codes.Unauthenticated, "station client certificate is required")
	}
	spki, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return db.Station{}, "", status.Error(codes.Unauthenticated, "station certificate is invalid")
	}
	digest := sha256.Sum256(spki)
	actorID := fmt.Sprintf("%x", digest[:])
	serial := certificate.SerialNumber.Text(16)
	dnsNames := normalizeDNSNames(certificate.DNSNames)
	stations, err := s.store.ActiveStationsByDNSNames(ctx, dnsNames)
	if err != nil {
		s.logger.Error("station DNS lookup failed", "error", err)
		return db.Station{}, actorID, status.Error(codes.Internal, "could not verify station")
	}
	if len(stations) != 1 {
		reason := "station certificate has no registered active DNS SAN match"
		if len(stations) > 1 {
			reason = "station certificate DNS SANs match multiple active stations"
		}
		if auditErr := s.auditEventDetail(ctx, "station", actorID, "AuthenticateStation", "station", actorID, audit.OutcomeDenied, map[string]any{
			"reason":             reason,
			"certificate_serial": serial,
			"spki_sha256":        actorID,
			"dns_sans":           dnsNames,
		}); auditErr != nil {
			s.logger.Error("audit station rejection failed", "error", auditErr)
			return db.Station{}, actorID, status.Error(codes.Internal, "could not record station decision")
		}
		if len(stations) > 1 {
			return db.Station{}, actorID, status.Error(codes.Unauthenticated, "station identity is ambiguous")
		}
		return db.Station{}, actorID, status.Error(codes.Unauthenticated, "station is not registered or active")
	}
	station := stations[0]
	if auditErr := s.auditEventDetail(ctx, "station", actorID, "AuthenticateStation", "station", station.ID, audit.OutcomeSuccess, map[string]any{
		"station_dns_name":   station.DNSName,
		"certificate_serial": serial,
		"spki_sha256":        actorID,
		"dns_sans":           dnsNames,
	}); auditErr != nil {
		s.logger.Error("audit station authentication failed", "error", auditErr)
		return db.Station{}, actorID, status.Error(codes.Internal, "could not record station decision")
	}
	return station, actorID, nil
}

func normalizeDNSNames(names []string) []string {
	normalized := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
		if name != "" && !slices.Contains(normalized, name) {
			normalized = append(normalized, name)
		}
	}
	return normalized
}

func peerCertificate(ctx context.Context) (*x509.Certificate, error) {
	remote, ok := peer.FromContext(ctx)
	if !ok {
		return nil, errors.New("missing gRPC peer")
	}
	info, ok := remote.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.PeerCertificates) == 0 {
		return nil, errors.New("missing TLS client certificate")
	}
	return info.State.PeerCertificates[0], nil
}

func rolesFor(groups []string, mapping config.RoleGroups) []string {
	var roles []string
	if intersects(groups, mapping.Admin) {
		roles = append(roles, "admin")
	}
	if intersects(groups, mapping.Helpdesk) {
		roles = append(roles, "helpdesk")
	}
	return roles
}

func intersects(left, right []string) bool {
	for _, value := range left {
		if slices.Contains(right, value) {
			return true
		}
	}
	return false
}

func (s *Server) auditEvent(ctx context.Context, actorType, actorID, action, targetType, targetID string, outcome audit.Outcome, reason string) error {
	return s.auditEventDetail(ctx, actorType, actorID, action, targetType, targetID, outcome, map[string]any{"reason": reason})
}

func (s *Server) auditEventDetail(ctx context.Context, actorType, actorID, action, targetType, targetID string, outcome audit.Outcome, detail map[string]any) error {
	return audit.AppendStandalone(ctx, s.store.Pool, audit.Event{
		ActorType:  actorType,
		ActorID:    actorID,
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		Outcome:    string(outcome),
		Detail:     detail,
	})
}

func TLSConfig(cfg config.TLS) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, errors.New("could not load backend TLS identity")
	}
	clientCABytes, err := os.ReadFile(cfg.ClientCAFile)
	if err != nil {
		return nil, errors.New("could not read station client CA")
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientCABytes) {
		return nil, errors.New("station client CA file contains no certificates")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}, nil
}

func NewGRPCServer(cfg config.TLS, service *Server) (*grpc.Server, error) {
	tlsConfig, err := TLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	backendv1.RegisterAgentGatewayServer(server, service)
	return server, nil
}

func ListenAndServe(ctx context.Context, address string, server *grpc.Server) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen for gRPC: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		server.GracefulStop()
		err := <-done
		if errors.Is(err, grpc.ErrServerStopped) {
			return nil
		}
		return err
	}
}

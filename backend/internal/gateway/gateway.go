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
	"time"

	agentv1 "github.com/Exonical/sigil/backend/gen/sigil/agent/v1"
	backendv1 "github.com/Exonical/sigil/backend/gen/sigil/backend/v1"
	"github.com/Exonical/sigil/backend/internal/audit"
	"github.com/Exonical/sigil/backend/internal/authn"
	"github.com/Exonical/sigil/backend/internal/config"
	"github.com/Exonical/sigil/backend/internal/db"
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
}

func New(store *db.Store, authenticator *authn.Authenticator, signer signing.Signer, cfg config.Config, logger *slog.Logger) *Server {
	return &Server{
		store:     store,
		inventory: inventory.New(store),
		auth:      authenticator,
		signer:    signer,
		config:    cfg,
		policy:    policy.LocalPolicy{},
		logger:    logger,
	}
}

func (s *Server) RequestGrant(ctx context.Context, request *backendv1.RequestGrantRequest) (*backendv1.RequestGrantResponse, error) {
	station, actorID, err := s.authenticatedStation(ctx)
	if err != nil {
		return nil, err
	}
	principal, err := s.auth.Authenticate(ctx, request.AccessToken)
	if err != nil {
		outcome := "denied"
		reason := "OIDC access token rejected"
		if errors.Is(err, authn.ErrUserStore) {
			outcome = "error"
			reason = "OIDC user persistence failed"
		}
		if auditErr := s.auditEvent(ctx, "station", actorID, "RequestGrant", "token", request.TokenSerial, outcome, reason); auditErr != nil {
			s.logger.Error("audit OIDC rejection failed", "error", auditErr)
			return nil, status.Error(codes.Internal, "could not record grant decision")
		}
		if errors.Is(err, authn.ErrUserStore) {
			s.logger.Error("OIDC user upsert failed", "error", err)
			return nil, status.Error(codes.Internal, "could not record authenticated user")
		}
		return nil, status.Error(codes.Unauthenticated, "OIDC access token is invalid")
	}
	token, err := s.inventory.FindToken(ctx, request.TokenVendor, request.TokenSerial)
	if errors.Is(err, pgx.ErrNoRows) {
		if auditErr := s.auditEvent(ctx, "user", principal.UserID, "RequestGrant", "token", request.TokenSerial, "denied", "token is not in inventory"); auditErr != nil {
			s.logger.Error("audit unknown token decision failed", "error", auditErr)
			return nil, status.Error(codes.Internal, "could not record grant decision")
		}
		return nil, status.Error(codes.PermissionDenied, "token is not in inventory")
	}
	if err != nil {
		s.logger.Error("token lookup failed", "error", err)
		return nil, status.Error(codes.Internal, "could not look up token inventory")
	}
	decision := s.policy.Authorize(policy.Request{
		Roles:                 rolesFor(principal.Groups, s.config.OIDC.RoleGroups),
		Station:               station,
		Token:                 &token,
		Operation:             request.Operation,
		UserID:                principal.UserID,
		SelfServiceOperations: s.config.Policy.SelfServiceOperations,
	})
	if !decision.Allowed {
		if err := audit.AppendStandalone(ctx, s.store.Pool, audit.Event{
			ActorType:  "user",
			ActorID:    principal.UserID,
			Action:     "RequestGrant",
			TargetType: "token",
			TargetID:   request.TokenSerial,
			Outcome:    "denied",
			Detail: map[string]any{
				"operation": agentv1.Operation_name[int32(request.Operation)],
				"station":   station.ID,
				"reason":    decision.Reason,
			},
		}); err != nil {
			s.logger.Error("audit policy denial failed", "error", err)
			return nil, status.Error(codes.Internal, "could not record policy decision")
		}
		return nil, status.Error(codes.PermissionDenied, decision.Reason)
	}
	if err := grants.ValidatePIVSlot(request.Operation, request.PivSlot); err != nil {
		if auditErr := s.auditEvent(ctx, "user", principal.UserID, "RequestGrant", "token", request.TokenSerial, "denied", err.Error()); auditErr != nil {
			s.logger.Error("audit invalid grant request failed", "error", auditErr)
			return nil, status.Error(codes.Internal, "could not record grant decision")
		}
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	signed, err := grants.Issue(ctx, s.store.Pool, s.signer, grants.IssueRequest{
		Operation:    request.Operation,
		UserID:       principal.UserID,
		Subject:      principal.Issuer + "|" + principal.Subject,
		StationID:    station.ID,
		TokenSerial:  token.Serial,
		CallerOSUser: request.CallerOsUser,
		PIVSlot:      request.PivSlot,
		Lifetime:     timeSeconds(s.config.Grants.LifetimeSeconds),
		PolicyReason: decision.Reason,
	})
	if err != nil {
		if auditErr := s.auditEvent(ctx, "user", principal.UserID, "RequestGrant", "token", request.TokenSerial, "error", "grant issuance failed"); auditErr != nil {
			s.logger.Error("audit grant issuance failure failed", "error", auditErr)
		}
		s.logger.Error("grant issuance failed", "error", err)
		return nil, status.Error(codes.Internal, "could not issue grant")
	}
	return &backendv1.RequestGrantResponse{Grant: signed}, nil
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
			if auditErr := s.auditEvent(ctx, "station", actorID, "ReportTokens", "inventory", station.ID, "denied", validationErr.Error()); auditErr != nil {
				s.logger.Error("audit invalid token report failed", "error", auditErr)
				return nil, status.Error(codes.Internal, "could not record token report decision")
			}
			return nil, status.Error(codes.InvalidArgument, validationErr.Error())
		}
		if auditErr := s.auditEvent(ctx, "station", actorID, "ReportTokens", "inventory", station.ID, "error", "token report failed"); auditErr != nil {
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
	station, err := s.store.StationByCertificateHash(ctx, digest[:])
	if errors.Is(err, pgx.ErrNoRows) || err == nil && station.Status != "active" {
		if auditErr := s.auditEvent(ctx, "station", actorID, "AuthenticateStation", "station", actorID, "denied", "station certificate is not active"); auditErr != nil {
			s.logger.Error("audit station rejection failed", "error", auditErr)
			return db.Station{}, actorID, status.Error(codes.Internal, "could not record station decision")
		}
		return db.Station{}, actorID, status.Error(codes.Unauthenticated, "station is not registered or active")
	}
	if err != nil {
		s.logger.Error("station lookup failed", "error", err)
		return db.Station{}, actorID, status.Error(codes.Internal, "could not verify station")
	}
	return station, actorID, nil
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

func (s *Server) auditEvent(ctx context.Context, actorType, actorID, action, targetType, targetID, outcome, reason string) error {
	return audit.AppendStandalone(ctx, s.store.Pool, audit.Event{
		ActorType:  actorType,
		ActorID:    actorID,
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		Outcome:    outcome,
		Detail:     map[string]any{"reason": reason},
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

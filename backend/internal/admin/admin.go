// Package admin implements the Connect AdminService used by the admin web portal.
package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"connectrpc.com/connect"
	adminv1 "github.com/Exonical/sigil/backend/gen/sigil/admin/v1"
	"github.com/Exonical/sigil/backend/gen/sigil/admin/v1/adminv1connect"
	"github.com/Exonical/sigil/backend/internal/authn"
	"github.com/Exonical/sigil/backend/internal/config"
	"github.com/Exonical/sigil/backend/internal/db"
)

// Authenticator verifies an OIDC access token and upserts the user, as the agent gateway does.
type Authenticator interface {
	Authenticate(ctx context.Context, accessToken string) (authn.Principal, error)
}

// Service implements AdminService. Every RPC runs behind the bearer and role interceptor.
type Service struct {
	store         *db.Store
	authenticator Authenticator
	roles         config.RoleGroups
}

// NewService builds the admin service.
func NewService(store *db.Store, authenticator Authenticator, roles config.RoleGroups) *Service {
	return &Service{store: store, authenticator: authenticator, roles: roles}
}

// Handler returns the path and handler to mount for the Connect service.
func (s *Service) Handler() (string, http.Handler) {
	return adminv1connect.NewAdminServiceHandler(s, connect.WithInterceptors(s.authInterceptor()))
}

// ServicePrefix is the URL prefix of the Connect service.
const ServicePrefix = "/sigil.admin.v1.AdminService/"

type principalKey struct{}

type principal struct {
	userID string
	roles  []string
}

func (s *Service) authInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			token, ok := bearerToken(req.Header().Get("Authorization"))
			if !ok {
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("a bearer access token is required"))
			}
			user, err := s.authenticator.Authenticate(ctx, token)
			if err != nil {
				if errors.Is(err, authn.ErrUserStore) {
					return nil, connect.NewError(connect.CodeInternal, errors.New("could not record the authenticated user"))
				}
				return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("the access token is invalid"))
			}
			roles := rolesFor(user.Groups, s.roles)
			if !slices.Contains(roles, "admin") && !slices.Contains(roles, "helpdesk") {
				return nil, connect.NewError(connect.CodePermissionDenied, errors.New("the admin portal requires the admin or helpdesk role"))
			}
			ctx = context.WithValue(ctx, principalKey{}, principal{userID: user.UserID, roles: roles})
			return next(ctx, req)
		}
	}
}

// bearerToken extracts the token from an Authorization header value.
func bearerToken(header string) (string, bool) {
	const prefix = "bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(prefix):])
	return token, token != ""
}

func rolesFor(groups []string, mapping config.RoleGroups) []string {
	var roles []string
	if slices.ContainsFunc(groups, func(group string) bool { return slices.Contains(mapping.Admin, group) }) {
		roles = append(roles, "admin")
	}
	if slices.ContainsFunc(groups, func(group string) bool { return slices.Contains(mapping.Helpdesk, group) }) {
		roles = append(roles, "helpdesk")
	}
	return roles
}

// unimplemented is returned by RPCs that later slices implement.
func unimplemented(name string) error {
	return connect.NewError(connect.CodeUnimplemented, fmt.Errorf("%s is not implemented yet", name))
}

func (s *Service) AssignToken(context.Context, *connect.Request[adminv1.AssignTokenRequest]) (*connect.Response[adminv1.Empty], error) {
	return nil, unimplemented("AssignToken")
}

func (s *Service) UnassignToken(context.Context, *connect.Request[adminv1.TokenRef]) (*connect.Response[adminv1.Empty], error) {
	return nil, unimplemented("UnassignToken")
}

func (s *Service) SetNickname(context.Context, *connect.Request[adminv1.SetNicknameRequest]) (*connect.Response[adminv1.Empty], error) {
	return nil, unimplemented("SetNickname")
}

func (s *Service) ReportLost(context.Context, *connect.Request[adminv1.TokenRef]) (*connect.Response[adminv1.Empty], error) {
	return nil, unimplemented("ReportLost")
}

func (s *Service) MarkFound(context.Context, *connect.Request[adminv1.TokenRef]) (*connect.Response[adminv1.MarkFoundResponse], error) {
	return nil, unimplemented("MarkFound")
}

func (s *Service) DeleteKey(context.Context, *connect.Request[adminv1.DeleteKeyRequest]) (*connect.Response[adminv1.DeleteKeyResponse], error) {
	return nil, unimplemented("DeleteKey")
}

func (s *Service) ListCertificates(context.Context, *connect.Request[adminv1.ListCertificatesRequest]) (*connect.Response[adminv1.ListCertificatesResponse], error) {
	return nil, unimplemented("ListCertificates")
}

func (s *Service) RevokeCertificate(context.Context, *connect.Request[adminv1.RevokeCertificateRequest]) (*connect.Response[adminv1.Empty], error) {
	return nil, unimplemented("RevokeCertificate")
}

func (s *Service) ListStations(context.Context, *connect.Request[adminv1.Empty]) (*connect.Response[adminv1.ListStationsResponse], error) {
	return nil, unimplemented("ListStations")
}

func (s *Service) AddStation(context.Context, *connect.Request[adminv1.AddStationRequest]) (*connect.Response[adminv1.Empty], error) {
	return nil, unimplemented("AddStation")
}

func (s *Service) SetStationStatus(context.Context, *connect.Request[adminv1.SetStationStatusRequest]) (*connect.Response[adminv1.Empty], error) {
	return nil, unimplemented("SetStationStatus")
}

func (s *Service) ListUsers(context.Context, *connect.Request[adminv1.ListUsersRequest]) (*connect.Response[adminv1.ListUsersResponse], error) {
	return nil, unimplemented("ListUsers")
}

func (s *Service) ListAudit(context.Context, *connect.Request[adminv1.ListAuditRequest]) (*connect.Response[adminv1.ListAuditResponse], error) {
	return nil, unimplemented("ListAudit")
}

func (s *Service) VerifyAudit(context.Context, *connect.Request[adminv1.Empty]) (*connect.Response[adminv1.VerifyAuditResponse], error) {
	return nil, unimplemented("VerifyAudit")
}

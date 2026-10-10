// Package admin implements the Connect AdminService used by the admin web portal.
package admin

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"connectrpc.com/connect"
	"github.com/Exonical/sigil/backend/gen/sigil/admin/v1/adminv1connect"
	"github.com/Exonical/sigil/backend/internal/authn"
	"github.com/Exonical/sigil/backend/internal/ca"
	"github.com/Exonical/sigil/backend/internal/config"
	"github.com/Exonical/sigil/backend/internal/db"
)

// ServicePrefix is the URL prefix of the Connect service.
const ServicePrefix = "/sigil.admin.v1.AdminService/"

// Authenticator verifies an OIDC access token and upserts the user, as the agent gateway does.
type Authenticator interface {
	Authenticate(ctx context.Context, accessToken string) (authn.Principal, error)
}

// Service implements AdminService. Every RPC runs behind the bearer and role interceptor.
type Service struct {
	store         *db.Store
	authenticator Authenticator
	roles         config.RoleGroups
	cas           map[string]ca.CA
	profileCA     map[string]string
}

// NewService builds the admin service.
func NewService(store *db.Store, authenticator Authenticator, roles config.RoleGroups) *Service {
	return &Service{store: store, authenticator: authenticator, roles: roles}
}

// WithCertificateAuthorities installs the CAs used for revocation. profileCA maps each profile to a CA name.
func (s *Service) WithCertificateAuthorities(cas map[string]ca.CA, profileCA map[string]string) *Service {
	s.cas = cas
	s.profileCA = profileCA
	return s
}

// Handler returns the path and handler to mount for the Connect service.
func (s *Service) Handler() (string, http.Handler) {
	return adminv1connect.NewAdminServiceHandler(s, connect.WithInterceptors(s.authInterceptor()))
}

type principalKey struct{}

type principal struct {
	userID string
	roles  []string
}

func principalFrom(ctx context.Context) principal {
	value, _ := ctx.Value(principalKey{}).(principal)
	return value
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

// requireAdmin rejects callers without the admin role. Used for RPCs that helpdesk may not run.
func requireAdmin(ctx context.Context) error {
	if !slices.Contains(principalFrom(ctx).roles, "admin") {
		return connect.NewError(connect.CodePermissionDenied, errors.New("this action requires the admin role"))
	}
	return nil
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

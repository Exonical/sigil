package gateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"

	backendv1 "github.com/Exonical/sigil/backend/gen/sigil/backend/v1"
	"github.com/Exonical/sigil/backend/internal/authn"
	"github.com/Exonical/sigil/backend/internal/config"
	"github.com/Exonical/sigil/backend/internal/db"
	"github.com/Exonical/sigil/backend/internal/policy"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// enrollmentLifetimeMinutes bounds how long a SCEP enrollment challenge stays valid after PrepareEnrollment.
const enrollmentLifetimeMinutes = 10

// enrollmentGate is the result of the checks that PrepareEnrollment and IssueCertificate share before any CSR is read.
type enrollmentGate struct {
	profile  config.Profile
	token    db.Token
	assigned db.User
}

// enrollmentRejection is a refusal from the shared checks. The caller audits it and returns it.
type enrollmentRejection struct {
	code   codes.Code
	reason string
	detail map[string]any
}

// checkEnrollment runs the checks shared by PrepareEnrollment and IssueCertificate: the profile exists, its CA is
// configured, the token is in inventory and locked for this transaction, the caller may enroll it under the profile,
// and the assigned user exists. It is the only place these checks are written.
func (s *Server) checkEnrollment(
	ctx context.Context,
	tx pgx.Tx,
	station db.Station,
	principalUserID string,
	groups []string,
	tokenVendor, tokenSerial, profileName string,
) (enrollmentGate, *enrollmentRejection, error) {
	profile, ok := s.profileByName(profileName)
	if !ok {
		return enrollmentGate{}, &enrollmentRejection{code: codes.PermissionDenied, reason: "profile is not defined"}, nil
	}
	if _, ok := s.issuers.cas[profile.CA]; !ok {
		return enrollmentGate{}, &enrollmentRejection{code: codes.FailedPrecondition, reason: "certificate authority is not configured"}, nil
	}
	token, err := db.LockToken(ctx, tx, tokenVendor, tokenSerial)
	if errors.Is(err, pgx.ErrNoRows) {
		return enrollmentGate{}, &enrollmentRejection{code: codes.PermissionDenied, reason: "token is not in inventory"}, nil
	}
	if err != nil {
		s.logger.Error("lock certificate token failed", "error", err)
		return enrollmentGate{}, nil, status.Error(codes.Internal, "could not look up token inventory")
	}
	roles := rolesFor(groups, s.config.OIDC.RoleGroups)
	decision := policy.AuthorizeIssuance(policy.IssuanceRequest{
		Roles:        roles,
		Station:      station,
		Token:        &token,
		UserID:       principalUserID,
		ProfileRoles: profile.Roles,
	})
	if !decision.Allowed {
		return enrollmentGate{}, &enrollmentRejection{code: codes.PermissionDenied, reason: decision.Reason, detail: map[string]any{"station": station.ID}}, nil
	}
	assigned, err := s.store.UserByID(ctx, tx, *token.AssignedUserID)
	if err != nil {
		s.logger.Error("read assigned user failed", "error", err)
		return enrollmentGate{}, nil, status.Error(codes.Internal, "could not read the token's assigned user")
	}
	return enrollmentGate{profile: profile, token: token, assigned: assigned}, nil, nil
}

// PrepareEnrollment runs the same checks as IssueCertificate and, for a SCEP profile, issues the one-time challenge
// that the CSR must carry. It runs before the agent generates a key, so an enrollment that would be refused never
// touches the token. The challenge is returned once and is stored only as its SHA-256.
func (s *Server) PrepareEnrollment(
	ctx context.Context,
	request *backendv1.PrepareEnrollmentRequest,
) (*backendv1.PrepareEnrollmentResponse, error) {
	station, actorID, err := s.authenticatedStation(ctx)
	if err != nil {
		return nil, err
	}
	principal, err := s.auth.Authenticate(ctx, request.AccessToken)
	if err != nil {
		if auditErr := s.auditEvent(ctx, "station", actorID, "PrepareEnrollment", "token", request.TokenSerial, "denied", "OIDC access token rejected"); auditErr != nil {
			return nil, status.Error(codes.Internal, "could not record enrollment decision")
		}
		if errors.Is(err, authn.ErrUserStore) {
			return nil, status.Error(codes.Internal, "could not record authenticated user")
		}
		return nil, status.Error(codes.Unauthenticated, "OIDC access token is invalid")
	}

	tx, err := s.store.Pool.Begin(ctx)
	if err != nil {
		s.logger.Error("begin enrollment transaction failed", "error", err)
		return nil, status.Error(codes.Internal, "could not prepare enrollment")
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	reject := func(code codes.Code, reason string, detail map[string]any) error {
		if detail == nil {
			detail = map[string]any{}
		}
		detail["profile"] = request.Profile
		detail["reason"] = reason
		if err := appendAudit(ctx, tx, "user", principal.UserID, "PrepareEnrollment", "token", request.TokenSerial, "denied", detail); err != nil {
			return status.Error(codes.Internal, "could not record enrollment decision")
		}
		if err := tx.Commit(ctx); err != nil {
			return status.Error(codes.Internal, "could not record enrollment decision")
		}
		committed = true
		return status.Error(code, reason)
	}

	gate, rejection, err := s.checkEnrollment(ctx, tx, station, principal.UserID, principal.Groups, request.TokenVendor, request.TokenSerial, request.Profile)
	if err != nil {
		return nil, err
	}
	if rejection != nil {
		return nil, reject(rejection.code, rejection.reason, rejection.detail)
	}

	response := &backendv1.PrepareEnrollmentResponse{}
	if s.caType(gate.profile.CA) == "scep" {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, status.Error(codes.Internal, "could not prepare enrollment")
		}
		challenge := hex.EncodeToString(secret)
		digest := sha256.Sum256([]byte(challenge))
		id, expires, err := s.store.InsertEnrollmentChallenge(ctx, tx, db.EnrollmentChallenge{
			TokenID:         gate.token.ID,
			Profile:         gate.profile.Name,
			UserID:          gate.assigned.ID,
			StationID:       station.ID,
			PrincipalUserID: principal.UserID,
			ChallengeSHA256: digest[:],
		}, enrollmentLifetimeMinutes)
		if err != nil {
			s.logger.Error("record enrollment challenge failed", "error", err)
			return nil, status.Error(codes.Internal, "could not prepare enrollment")
		}
		response.EnrollmentId = id
		response.ChallengePassword = challenge
		response.ExpiresUnix = expires
	}
	if err := appendAudit(ctx, tx, "user", principal.UserID, "PrepareEnrollment", "token", request.TokenSerial, "success", map[string]any{
		"profile":       gate.profile.Name,
		"enrollment_id": response.EnrollmentId,
		"station":       station.ID,
	}); err != nil {
		return nil, status.Error(codes.Internal, "could not record enrollment decision")
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, status.Error(codes.Internal, "could not record enrollment decision")
	}
	committed = true
	return response, nil
}

// caType returns the configured type of a certificate authority, or "" when it is not configured.
func (s *Server) caType(name string) string {
	return s.config.CA[name].Type
}

// expectedEmailAddresses returns the email SANs the CA will issue for the user under this profile.
func expectedEmailAddresses(profile config.Profile, user db.User) []string {
	if profile.EmailSAN && user.Email != "" {
		return []string{user.Email}
	}
	return nil
}

// enrollmentMatches reports whether an enrollment belongs to this request. The challenge hash is compared in constant
// time, and the record must be unexpired and still issued.
func enrollmentMatches(record db.EnrollmentChallenge, challenge, tokenID, profile, stationID, principalUserID string) bool {
	digest := sha256.Sum256([]byte(challenge))
	return record.State == "issued" &&
		!record.Expired &&
		subtle.ConstantTimeCompare(record.ChallengeSHA256, digest[:]) == 1 &&
		record.TokenID == tokenID &&
		record.Profile == profile &&
		record.StationID == stationID &&
		record.PrincipalUserID == principalUserID
}

// submitEnrollment binds an issued challenge to the CSR key in its own short transaction. The webhook from the CA
// reads this committed state while the issuance transaction still holds the token lock, so it must commit first.
func (s *Server) submitEnrollment(ctx context.Context, enrollmentID string, csrSPKI []byte) (bool, error) {
	tx, err := s.store.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	submitted, err := s.store.SubmitEnrollment(ctx, tx, enrollmentID, csrSPKI)
	if err != nil || !submitted {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	backendv1 "github.com/Exonical/sigil/backend/gen/sigil/backend/v1"
	"github.com/Exonical/sigil/backend/internal/attestation"
	"github.com/Exonical/sigil/backend/internal/audit"
	"github.com/Exonical/sigil/backend/internal/ca"
	"github.com/Exonical/sigil/backend/internal/config"
	"github.com/Exonical/sigil/backend/internal/db"
	"github.com/Exonical/sigil/backend/internal/policy"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// issuanceSettings holds the external CAs and the attestation verifier used for enrollment.
type issuanceSettings struct {
	cas    map[string]ca.CA
	attest func(attestationDER, slotIntermediateDER []byte, now time.Time) (attestation.Attestation, error)
}

// ConfigureIssuance installs the certificate authorities used by IssueCertificate.
// Attestation is verified with the Yubico roots embedded in the backend.
func (s *Server) ConfigureIssuance(cas map[string]ca.CA) {
	s.issuers = issuanceSettings{cas: cas, attest: attestation.Verify}
}

// ListProfiles returns the certificate profiles the caller may enroll. With a token, only profiles
// that the caller may enroll on that token are returned.
func (s *Server) ListProfiles(
	ctx context.Context,
	request *backendv1.ListProfilesRequest,
) (*backendv1.ListProfilesResponse, error) {
	station, actorID, err := s.authenticatedStation(ctx)
	if err != nil {
		return nil, err
	}
	principal, err := s.authenticatePrincipal(ctx, actorID, "ListProfiles", request.TokenSerial, request.AccessToken)
	if err != nil {
		return nil, err
	}
	roles := rolesFor(principal.Groups, s.config.OIDC.RoleGroups)
	var token *db.Token
	if request.TokenSerial != "" {
		found, err := s.inventory.FindToken(ctx, request.TokenVendor, request.TokenSerial)
		if errors.Is(err, pgx.ErrNoRows) {
			if auditErr := s.auditEvent(ctx, "user", principal.UserID, "ListProfiles", "token", request.TokenSerial, audit.OutcomeDenied, "token is not in inventory"); auditErr != nil {
				s.logger.Error("audit unknown token decision failed", "error", auditErr)
				return nil, status.Error(codes.Internal, "could not record profile listing")
			}
			return nil, status.Error(codes.PermissionDenied, "token is not in inventory")
		}
		if err != nil {
			return nil, status.Error(codes.Internal, "could not look up token inventory")
		}
		token = &found
	}
	profiles := make([]*backendv1.CertificateProfile, 0, len(s.config.Profiles))
	for _, profile := range s.config.Profiles {
		allowed := policy.ProfileVisible(roles, profile.Roles)
		if token != nil {
			allowed = policy.AuthorizeIssuance(policy.IssuanceRequest{
				Roles:        roles,
				Station:      station,
				Token:        token,
				UserID:       principal.UserID,
				ProfileRoles: profile.Roles,
			}).Allowed
		}
		if !allowed {
			continue
		}
		entry := protoProfile(profile)
		if token != nil && token.AssignedUserID != nil {
			expected, err := s.expectedSubject(ctx, *token.AssignedUserID, profile)
			if err != nil {
				return nil, status.Error(codes.Internal, "could not read the token's assigned user")
			}
			entry.ExpectedSubject = expected
		}
		profiles = append(profiles, entry)
	}
	outcome := fmt.Sprintf("%d profiles", len(profiles))
	if err := s.auditEvent(ctx, "user", principal.UserID, "ListProfiles", "token", request.TokenSerial, audit.OutcomeSuccess, outcome); err != nil {
		return nil, status.Error(codes.Internal, "could not record profile listing")
	}
	return &backendv1.ListProfilesResponse{Profiles: profiles}, nil
}

// IssueCertificate verifies an enrollment request and signs it. Checks run in this order: station, principal,
// profile, token and authorization, CSR, attestation, subject, CA signing, then persistence.
// Every rejection is audited with its reason and returns without issuing.
func (s *Server) IssueCertificate(
	ctx context.Context,
	request *backendv1.IssueCertificateRequest,
) (*backendv1.IssueCertificateResponse, error) {
	station, actorID, err := s.authenticatedStation(ctx)
	if err != nil {
		return nil, err
	}
	principal, err := s.authenticatePrincipal(ctx, actorID, "IssueCertificate", request.TokenSerial, request.AccessToken)
	if err != nil {
		return nil, err
	}
	profile, ok := s.profileByName(request.Profile)

	tx, err := s.beginAuditTx(ctx)
	if err != nil {
		s.logger.Error("begin certificate transaction failed", "error", err)
		return nil, status.Error(codes.Internal, "could not issue certificate")
	}
	defer tx.rollbackUnlessCommitted(ctx)
	decision := auditDecision{
		tx: tx, actorType: "user", actorID: principal.UserID, action: "IssueCertificate",
		targetType: "token", targetID: request.TokenSerial,
		detail:  map[string]any{"profile": request.Profile},
		failure: "could not record certificate decision",
	}

	if !ok {
		return nil, decision.deny(ctx, codes.PermissionDenied, "profile is not defined", nil)
	}
	if _, ok := s.issuers.cas[profile.CA]; !ok {
		return nil, decision.deny(ctx, codes.FailedPrecondition, "certificate authority is not configured", nil)
	}

	token, err := db.LockToken(ctx, tx, request.TokenVendor, request.TokenSerial)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, decision.deny(ctx, codes.PermissionDenied, "token is not in inventory", nil)
	}
	if err != nil {
		s.logger.Error("lock certificate token failed", "error", err)
		return nil, status.Error(codes.Internal, "could not look up token inventory")
	}
	roles := rolesFor(principal.Groups, s.config.OIDC.RoleGroups)
	issuance := policy.AuthorizeIssuance(policy.IssuanceRequest{
		Roles:        roles,
		Station:      station,
		Token:        &token,
		UserID:       principal.UserID,
		ProfileRoles: profile.Roles,
	})
	if !issuance.Allowed {
		return nil, decision.deny(ctx, codes.PermissionDenied, issuance.Reason, map[string]any{"station": station.ID})
	}
	assigned, err := s.store.UserByID(ctx, tx, *token.AssignedUserID)
	if err != nil {
		s.logger.Error("read assigned user failed", "error", err)
		return nil, status.Error(codes.Internal, "could not read the token's assigned user")
	}

	csr, err := x509.ParseCertificateRequest(request.CsrDer)
	if err != nil {
		return nil, decision.deny(ctx, codes.InvalidArgument, "certificate request is not valid DER", nil)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, decision.deny(ctx, codes.InvalidArgument, "certificate request signature is invalid", nil)
	}
	if reason := keyAlgorithmMismatch(csr, profile.Algorithm); reason != "" {
		return nil, decision.deny(ctx, codes.FailedPrecondition, reason, nil)
	}

	now := s.now()
	attested, err := s.issuers.attest(request.AttestationDer, request.AttestationIntermediateDer, now)
	if err != nil {
		return nil, decision.deny(ctx, codes.FailedPrecondition, err.Error(), nil)
	}
	if reason := attestationMismatch(attested, token.Serial, profile, csr.RawSubjectPublicKeyInfo); reason != "" {
		return nil, decision.deny(ctx, codes.FailedPrecondition, reason, map[string]any{"attested_serial": attested.Serial})
	}

	commonName, err := subjectCommonName(profile.Subject, assigned)
	if err != nil {
		return nil, decision.deny(ctx, codes.FailedPrecondition, err.Error(), nil)
	}
	if csr.Subject.CommonName != commonName {
		return nil, decision.deny(ctx, codes.FailedPrecondition, "certificate request subject does not match the assigned user", map[string]any{"expected_subject": commonName})
	}
	signRequest := ca.SignRequest{
		Subject:   commonName,
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(time.Duration(profile.ValidityHours) * time.Hour),
	}
	if profile.EmailSAN && assigned.Email != "" {
		signRequest.EmailAddresses = []string{assigned.Email}
	}
	chain, err := s.issuers.cas[profile.CA].Sign(ctx, request.CsrDer, signRequest)
	if err != nil {
		s.logger.Error("certificate authority failed", "profile", profile.Name, "error", err)
		return nil, decision.fail(ctx, codes.Unavailable, "certificate authority did not issue the certificate", nil)
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, decision.fail(ctx, codes.Internal, "certificate authority returned an invalid certificate", nil)
	}
	serialHex := hex.EncodeToString(leaf.SerialNumber.Bytes())
	subject := leaf.Subject.String()

	if mismatch := issuedCertificateMismatch(leaf, chain, csr, signRequest, s.issuers.cas[profile.CA].Roots(), now); mismatch != "" {
		s.revokeMismatched(ctx, profile.CA, serialHex, mismatch)
		if err := tx.auditAndCommit(ctx, decision.event(audit.OutcomeError, map[string]any{
			"reason":             mismatch,
			"certificate_serial": serialHex,
		})); err != nil {
			return nil, status.Error(codes.Internal, "could not record the issued certificate")
		}
		return nil, status.Error(codes.FailedPrecondition, "certificate authority returned a certificate that does not match the request")
	}

	if _, err := s.store.InsertCertificate(ctx, tx, db.CertificateRecord{
		TokenID:         token.ID,
		Slot:            profile.Slot,
		Profile:         profile.Name,
		UserID:          assigned.ID,
		SerialNumber:    serialHex,
		Subject:         subject,
		NotBefore:       leaf.NotBefore,
		NotAfter:        leaf.NotAfter,
		IssuedByStation: station.ID,
		DER:             chain[0],
		// The attestation is stored with the certificate, in the same transaction.
		AttestationDER:             request.AttestationDer,
		AttestationIntermediateDER: request.AttestationIntermediateDer,
		AttestedFirmware:           attested.Firmware,
		AttestationRoot:            attested.Root,
	}); err != nil {
		s.logger.Error("record certificate failed", "error", err)
		return nil, status.Error(codes.Internal, "could not record the issued certificate")
	}
	if err := tx.auditAndCommit(ctx, decision.event(audit.OutcomeSuccess, map[string]any{
		"slot":               profile.Slot,
		"certificate_serial": serialHex,
		"not_after":          leaf.NotAfter.UTC().Format(time.RFC3339),
		"station":            station.ID,
		"caller_os_user":     request.CallerOsUser,
	})); err != nil {
		return nil, status.Error(codes.Internal, "could not record the issued certificate")
	}

	return &backendv1.IssueCertificateResponse{
		ChainDer:     chain,
		SerialNumber: serialHex,
		Subject:      subject,
		NotAfterUnix: leaf.NotAfter.Unix(),
	}, nil
}

// expectedSubject returns the subject CN the CA will issue for the assigned user under this profile.
func (s *Server) expectedSubject(ctx context.Context, userID string, profile config.Profile) (string, error) {
	tx, err := s.store.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	user, err := s.store.UserByID(ctx, tx, userID)
	if err != nil {
		return "", err
	}
	return subjectCommonName(profile.Subject, user)
}

func (s *Server) profileByName(name string) (config.Profile, bool) {
	for _, profile := range s.config.Profiles {
		if profile.Name == name {
			return profile, true
		}
	}
	return config.Profile{}, false
}

func protoProfile(profile config.Profile) *backendv1.CertificateProfile {
	slot, _ := strconv.ParseUint(profile.Slot, 16, 8)
	return &backendv1.CertificateProfile{
		Name:        profile.Name,
		DisplayName: profile.DisplayName,
		PivSlot:     uint32(slot),
		Algorithm:   profile.Algorithm,
		PinPolicy:   profile.PinPolicy,
		TouchPolicy: profile.TouchPolicy,
	}
}

// keyAlgorithmMismatch returns a reason when the CSR key does not match the profile algorithm.
func keyAlgorithmMismatch(csr *x509.CertificateRequest, algorithm string) string {
	if csr.PublicKeyAlgorithm != x509.ECDSA {
		return "certificate request key must be ECDSA"
	}
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "certificate request key must be ECDSA"
	}
	want := map[string]string{"p256": "P-256", "p384": "P-384"}[algorithm]
	if key.Curve.Params().Name != want {
		return "certificate request key does not match the profile algorithm"
	}
	return ""
}

// attestationMismatch returns a reason when the attestation does not describe this token and key.
func attestationMismatch(attested attestation.Attestation, tokenSerial string, profile config.Profile, csrSPKI []byte) string {
	serial, err := strconv.ParseUint(tokenSerial, 10, 32)
	if err != nil || uint32(serial) != attested.Serial {
		return "attestation serial number does not match the token"
	}
	if slot, err := strconv.ParseUint(profile.Slot, 16, 8); err != nil || byte(slot) != attested.Slot {
		return "attestation slot does not match the profile"
	}
	if attested.PinPolicy != attestationPinPolicy[profile.PinPolicy] {
		return "attestation PIN policy does not match the profile"
	}
	if attested.TouchPolicy != attestationTouchPolicy[profile.TouchPolicy] {
		return "attestation touch policy does not match the profile"
	}
	if !bytes.Equal(attested.SubjectPublicKeyInfo, csrSPKI) {
		return "attested key does not match the certificate request key"
	}
	return ""
}

// Yubico usage policy values from developers.yubico.com PIV attestation documentation.
var attestationPinPolicy = map[string]byte{"never": 0x01, "once": 0x02, "always": 0x03}

var attestationTouchPolicy = map[string]byte{"never": 0x01, "always": 0x02, "cached": 0x03}

// subjectCommonName expands a "CN=..." subject template from the assigned user. The CSR subject is ignored.
func subjectCommonName(template string, user db.User) (string, error) {
	if !strings.HasPrefix(template, "CN=") {
		return "", errors.New("profile subject must be a CN= template")
	}
	username := user.Username
	if username == "" {
		username = user.DisplayName
	}
	if username == "" {
		username = user.Email
	}
	replacer := strings.NewReplacer("{username}", username, "{email}", user.Email, "{subject}", user.Subject)
	value := replacer.Replace(strings.TrimPrefix(template, "CN="))
	if value == "" {
		return "", errors.New("the assigned user has no name for the certificate subject")
	}
	return value, nil
}

// revokeMismatched asks the issuing CA to revoke a certificate that failed the request checks. The request is already
// rejected and nothing was stored, so a failed revocation is logged rather than returned.
func (s *Server) revokeMismatched(ctx context.Context, caName, serialHex, reason string) {
	if err := s.issuers.cas[caName].Revoke(ctx, serialHex, 0, reason); err != nil {
		s.logger.Error("revoke mismatched certificate failed", "serial", serialHex, "error", err)
		return
	}
	s.logger.Info("revoked mismatched certificate", "serial", serialHex)
}

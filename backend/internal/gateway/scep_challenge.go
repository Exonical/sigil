package gateway

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Exonical/sigil/backend/internal/db"
)

const (
	scepChallengePathPrefix = "/ca/scep-challenge/"
	maxSCEPChallengeBody    = 64 << 10
)

// SCEPWebhookCA is the webhook configuration for one SCEP CA: the key step-ca signs its webhook requests with, and the
// profiles that enroll through that CA.
type SCEPWebhookCA struct {
	Name     string
	Secret   []byte
	Profiles []string
}

// SCEPChallengeWebhook answers step-ca's SCEPCHALLENGE webhook. step-ca calls it while it is signing a SCEP request.
// A challenge is accepted once, only for the CSR key it was issued for, and only while the enrollment is submitted.
type SCEPChallengeWebhook struct {
	store  *db.Store
	logger *slog.Logger
	cas    map[string]SCEPWebhookCA
}

// NewSCEPChallengeWebhook builds the handler for the given SCEP CAs.
func NewSCEPChallengeWebhook(store *db.Store, logger *slog.Logger, cas []SCEPWebhookCA) *SCEPChallengeWebhook {
	byName := make(map[string]SCEPWebhookCA, len(cas))
	for _, ca := range cas {
		byName[ca.Name] = ca
	}
	return &SCEPChallengeWebhook{store: store, logger: logger, cas: byName}
}

// scepChallengeBody is the part of step-ca's webhook request that the decision uses.
type scepChallengeBody struct {
	SCEPChallenge          string `json:"scepChallenge"`
	SCEPTransactionID      string `json:"scepTransactionID"`
	X509CertificateRequest *struct {
		PublicKey []byte `json:"publicKey"`
	} `json:"x509CertificateRequest"`
}

// ServeHTTP verifies the request, decides, and audits the decision. The signature is checked before the body is parsed.
func (h *SCEPChallengeWebhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, scepChallengePathPrefix)
	ca, ok := h.cas[name]
	if !ok || name == r.URL.Path || name == "" {
		http.NotFound(w, r)
		return
	}
	clientCertificate := r.TLS != nil && len(r.TLS.PeerCertificates) > 0
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSCEPChallengeBody))
	if err != nil {
		h.audit(r.Context(), name, "", "deny", "body is larger than 64 KiB or unreadable", clientCertificate)
		http.Error(w, "request body is too large", http.StatusRequestEntityTooLarge)
		return
	}
	if !validWebhookSignature(ca.Secret, body, r.Header.Get("X-Smallstep-Signature")) {
		h.audit(r.Context(), name, "", "deny", "signature does not verify", clientCertificate)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var request scepChallengeBody
	if err := json.Unmarshal(body, &request); err != nil || request.SCEPChallenge == "" || request.X509CertificateRequest == nil {
		h.audit(r.Context(), name, "", "deny", "request has no challenge or certificate request", clientCertificate)
		writeWebhookDecision(w, false)
		return
	}
	allowed, enrollmentID, reason := h.decide(r.Context(), ca, request)
	outcome := "deny"
	if allowed {
		outcome = "allow"
	}
	h.audit(r.Context(), name, enrollmentID, outcome, reason, clientCertificate)
	writeWebhookDecision(w, allowed)
}

// decide consumes the challenge if it is valid for this CA and CSR key. When it refuses, it reports why, for the audit.
func (h *SCEPChallengeWebhook) decide(ctx context.Context, ca SCEPWebhookCA, request scepChallengeBody) (bool, string, string) {
	digest := sha256.Sum256([]byte(request.SCEPChallenge))
	publicKey := request.X509CertificateRequest.PublicKey
	id, _, consumed, err := h.store.ConsumeEnrollment(ctx, digest[:], publicKey, ca.Profiles)
	if err != nil {
		h.logger.Error("consume enrollment challenge failed", "error", err)
		return false, "", "could not consume the enrollment challenge"
	}
	if consumed {
		return true, id, "challenge consumed for the submitted key"
	}
	record, err := h.store.EnrollmentByChallenge(ctx, digest[:])
	switch {
	case errors.Is(err, db.ErrEnrollmentNotFound):
		return false, "", "unknown challenge"
	case err != nil:
		h.logger.Error("read enrollment challenge failed", "error", err)
		return false, "", "could not read the enrollment challenge"
	case record.State == "consumed":
		return false, record.ID, "challenge was already consumed"
	case record.Expired:
		return false, record.ID, "challenge expired"
	case record.State != "submitted":
		return false, record.ID, "enrollment was not submitted"
	case !bytes.Equal(record.CSRSPKI, publicKey):
		return false, record.ID, "CSR key does not match the submitted key"
	case !containsString(ca.Profiles, record.Profile):
		return false, record.ID, "profile is not served by this CA"
	default:
		return false, record.ID, "challenge is not valid"
	}
}

// audit records a decision. The challenge value is never written.
func (h *SCEPChallengeWebhook) audit(ctx context.Context, caName, enrollmentID, outcome, reason string, clientCertificate bool) {
	tx, err := h.store.Pool.Begin(ctx)
	if err != nil {
		h.logger.Error("begin SCEP challenge audit failed", "error", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := appendAudit(ctx, tx, "ca", caName, "SCEPChallenge", "enrollment", enrollmentID, outcome, map[string]any{
		"reason":                reason,
		"client_certificate":    clientCertificate,
		"certificate_authority": caName,
	}); err != nil {
		h.logger.Error("record SCEP challenge audit failed", "error", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		h.logger.Error("commit SCEP challenge audit failed", "error", err)
	}
}

// validWebhookSignature checks the signature step-ca sends in X-Smallstep-Signature. step-ca computes the hex of
// HMAC-SHA256 over the raw request body, keyed with the base64-decoded webhook secret (webhook.go, DoWithContext).
func validWebhookSignature(secret, body []byte, header string) bool {
	got, err := hex.DecodeString(header)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), got)
}

func writeWebhookDecision(w http.ResponseWriter, allowed bool) {
	w.Header().Set("Content-Type", "application/json")
	if allowed {
		_, _ = io.WriteString(w, `{"allow":true}`)
		return
	}
	_, _ = io.WriteString(w, `{"allow":false}`)
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

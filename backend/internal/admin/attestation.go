package admin

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"connectrpc.com/connect"
	adminv1 "github.com/Exonical/sigil/backend/gen/sigil/admin/v1"
	"github.com/Exonical/sigil/backend/internal/attestation"
	"github.com/jackc/pgx/v5"
)

// attestationRow is what the backend stored for a certificate at issuance.
type attestationRow struct {
	der      []byte
	firmware *string
	root     *string
}

func (s *Service) attestationRows(ctx context.Context, ids []string) (map[string]attestationRow, error) {
	rows, err := s.store.Pool.Query(ctx, `
		SELECT id::text, attestation_der, attested_firmware, attestation_root
		FROM certificates WHERE id = ANY($1::uuid[])
	`, ids)
	if err != nil {
		return nil, internal("could not read attestations", err)
	}
	defer rows.Close()
	out := make(map[string]attestationRow, len(ids))
	for rows.Next() {
		var id string
		var row attestationRow
		if err := rows.Scan(&id, &row.der, &row.firmware, &row.root); err != nil {
			return nil, internal("could not read attestations", err)
		}
		out[id] = row
	}
	if err := rows.Err(); err != nil {
		return nil, internal("could not read attestations", err)
	}
	return out, nil
}

// summarize builds the portal summary. The chain was verified at issuance, so the attested fields are read from
// the stored DER without a second chain check. A DER that does not parse still reports present and the stored root.
func summarize(row attestationRow) *adminv1.AttestationSummary {
	summary := &adminv1.AttestationSummary{Present: row.der != nil}
	if row.firmware != nil {
		summary.Firmware = *row.firmware
	}
	if row.root != nil {
		summary.Root = *row.root
	}
	if row.der == nil {
		return summary
	}
	fields, err := attestation.Describe(row.der)
	if err != nil {
		return summary
	}
	summary.AttestedSerial = strconv.FormatUint(uint64(fields.Serial), 10)
	summary.Slot = fmt.Sprintf("%02x", fields.Slot)
	summary.PinPolicy = fmt.Sprintf("%02x", fields.PinPolicy)
	summary.TouchPolicy = fmt.Sprintf("%02x", fields.TouchPolicy)
	if summary.Firmware == "" {
		summary.Firmware = fields.Firmware
	}
	return summary
}

// attachAttestations sets the attestation summary on each certificate.
func (s *Service) attachAttestations(ctx context.Context, certificates []*adminv1.CertificateSummary) error {
	if len(certificates) == 0 {
		return nil
	}
	ids := make([]string, 0, len(certificates))
	for _, certificate := range certificates {
		ids = append(ids, certificate.Id)
	}
	rows, err := s.attestationRows(ctx, ids)
	if err != nil {
		return err
	}
	for _, certificate := range certificates {
		certificate.Attestation = summarize(rows[certificate.Id])
	}
	return nil
}

// GetCertificateAttestation returns the stored attestation DER for a certificate, with its summary. Admins and help
// desk may read it. The read is audited in the hash chain with the certificate id and no response data.
func (s *Service) GetCertificateAttestation(ctx context.Context, req *connect.Request[adminv1.CertificateAttestationRequest]) (*connect.Response[adminv1.CertificateAttestationResponse], error) {
	id := req.Msg.CertificateId
	if id == "" {
		return nil, invalid("a certificate id is required")
	}
	var attestationDER, intermediateDER []byte
	var firmware, root *string
	err := s.store.Pool.QueryRow(ctx, `
		SELECT attestation_der, attestation_intermediate_der, attested_firmware, attestation_root
		FROM certificates WHERE id = $1::uuid
	`, id).Scan(&attestationDER, &intermediateDER, &firmware, &root)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, notFound("the certificate does not exist")
		}
		return nil, internal("could not read the certificate", err)
	}
	if err := s.auditRead(ctx, "Admin.GetCertificateAttestation", "certificate", id, map[string]any{"certificate_id": id}); err != nil {
		return nil, err
	}
	return connect.NewResponse(&adminv1.CertificateAttestationResponse{
		AttestationDer:             attestationDER,
		AttestationIntermediateDer: intermediateDER,
		Summary:                    summarize(attestationRow{der: attestationDER, firmware: firmware, root: root}),
	}), nil
}

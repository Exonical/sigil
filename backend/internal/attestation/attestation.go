// Package attestation verifies YubiKey PIV attestation certificates.
//
// Trust comes from Yubico's published PKI, embedded at build time:
//   - roots/yubico-piv-ca-1.pem: "Yubico PIV Root CA Serial 263751" (firmware before 5.7.4)
//   - roots/yubico-ca-1.pem: "Yubico Attestation Root 1" (firmware 5.7.4 and later)
//   - roots/yubico-intermediate.pem: Yubico intermediate certificates, used only as an intermediate pool
//
// Sources: https://developers.yubico.com/PKI/yubico-piv-ca-1.pem,
// https://developers.yubico.com/PKI/yubico-ca-1.pem and
// https://developers.yubico.com/PKI/yubico-intermediate.pem (see docs/attestation-roots.md).
//
// Extension OIDs are from Yubico's PIV attestation arc 1.3.6.1.4.1.41482.3:
// .3 firmware, .7 serial number, .8 usage policy (PIN policy byte, then touch policy byte).
package attestation

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "embed"
)

//go:embed roots/yubico-piv-ca-1.pem
var legacyRootPEM []byte

//go:embed roots/yubico-ca-1.pem
var currentRootPEM []byte

//go:embed roots/yubico-intermediate.pem
var intermediatesPEM []byte

var (
	oidFirmware = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 3}
	oidSerial   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 7}
	oidPolicy   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 3, 8}
)

// Trust holds the roots and the intermediate pool used to verify attestation chains.
// Intermediates are never trust anchors; a chain must end at one of Roots.
type Trust struct {
	Roots         *x509.CertPool
	Intermediates []*x509.Certificate
}

// Attestation is the verified content of an attestation certificate.
type Attestation struct {
	// Slot is the attested PIV slot, from the subject "YubiKey PIV Attestation <slot>" where <slot> is two
	// lowercase hex digits, for example 9a. Yubico documents the subject as the attested slot appended to that string.
	Slot        byte
	Serial      uint32
	Firmware    string
	PinPolicy   byte
	TouchPolicy byte
	// SubjectPublicKeyInfo is the attested key, DER encoded, for comparison with a CSR.
	SubjectPublicKeyInfo []byte
}

// EmbeddedTrust returns the Yubico roots and intermediates compiled into the backend.
func EmbeddedTrust() (Trust, error) {
	roots := x509.NewCertPool()
	for _, source := range [][]byte{legacyRootPEM, currentRootPEM} {
		certs, err := parsePEMCertificates(source)
		if err != nil {
			return Trust{}, fmt.Errorf("parse embedded Yubico root: %w", err)
		}
		for _, cert := range certs {
			roots.AddCert(cert)
		}
	}
	intermediates, err := parsePEMCertificates(intermediatesPEM)
	if err != nil {
		return Trust{}, fmt.Errorf("parse embedded Yubico intermediates: %w", err)
	}
	return Trust{Roots: roots, Intermediates: intermediates}, nil
}

// Verify checks an attestation certificate against the embedded Yubico trust at time now.
// slotIntermediateDER is the slot F9 certificate that signed the attestation.
func Verify(attestationDER, slotIntermediateDER []byte, now time.Time) (Attestation, error) {
	trust, err := EmbeddedTrust()
	if err != nil {
		return Attestation{}, err
	}
	return VerifyWith(trust, attestationDER, slotIntermediateDER, now)
}

// VerifyWith checks an attestation certificate against the given trust.
func VerifyWith(trust Trust, attestationDER, slotIntermediateDER []byte, now time.Time) (Attestation, error) {
	leaf, err := x509.ParseCertificate(attestationDER)
	if err != nil {
		return Attestation{}, errors.New("attestation certificate is not valid DER")
	}
	slot, err := x509.ParseCertificate(slotIntermediateDER)
	if err != nil {
		return Attestation{}, errors.New("slot F9 intermediate certificate is not valid DER")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range trust.Intermediates {
		intermediates.AddCert(cert)
	}
	intermediates.AddCert(slot)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         trust.Roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return Attestation{}, fmt.Errorf("attestation chain does not verify to a Yubico root: %w", err)
	}
	return parseExtensions(leaf)
}

const slotSubjectPrefix = "YubiKey PIV Attestation "

// parseSlot reads the attested slot from the subject CN "YubiKey PIV Attestation <slot>".
func parseSlot(commonName string) (byte, error) {
	if !strings.HasPrefix(commonName, slotSubjectPrefix) {
		return 0, errors.New("attestation subject is not a YubiKey PIV attestation")
	}
	digits := strings.TrimPrefix(commonName, slotSubjectPrefix)
	if len(digits) != 2 || strings.ToLower(digits) != digits {
		return 0, errors.New("attestation slot must be two lowercase hex digits")
	}
	slot, err := hex.DecodeString(digits)
	if err != nil {
		return 0, errors.New("attestation slot must be two lowercase hex digits")
	}
	return slot[0], nil
}

func parseExtensions(leaf *x509.Certificate) (Attestation, error) {
	slot, err := parseSlot(leaf.Subject.CommonName)
	if err != nil {
		return Attestation{}, err
	}
	result := Attestation{Slot: slot}
	result.SubjectPublicKeyInfo = append([]byte(nil), leaf.RawSubjectPublicKeyInfo...)
	var seenSerial, seenPolicy bool
	for _, extension := range leaf.Extensions {
		switch {
		case extension.Id.Equal(oidSerial):
			serial, err := parseSerial(extension.Value)
			if err != nil {
				return Attestation{}, err
			}
			result.Serial = serial
			seenSerial = true
		case extension.Id.Equal(oidPolicy):
			pin, touch, err := parsePolicy(extension.Value)
			if err != nil {
				return Attestation{}, err
			}
			result.PinPolicy, result.TouchPolicy = pin, touch
			seenPolicy = true
		case extension.Id.Equal(oidFirmware):
			result.Firmware = parseFirmware(extension.Value)
		}
	}
	if !seenSerial {
		return Attestation{}, errors.New("attestation certificate has no serial number extension")
	}
	if !seenPolicy {
		return Attestation{}, errors.New("attestation certificate has no usage policy extension")
	}
	return result, nil
}

// parseSerial accepts a DER INTEGER, or the four-byte big-endian encoding Yubico documents.
func parseSerial(value []byte) (uint32, error) {
	var number int64
	if rest, err := asn1.Unmarshal(value, &number); err == nil && len(rest) == 0 && number >= 0 && number <= 0xffffffff {
		return uint32(number), nil
	}
	if len(value) == 4 {
		return binary.BigEndian.Uint32(value), nil
	}
	return 0, errors.New("attestation serial number extension is malformed")
}

// parsePolicy accepts a DER OCTET STRING, or the raw two bytes.
func parsePolicy(value []byte) (byte, byte, error) {
	var octets []byte
	if rest, err := asn1.Unmarshal(value, &octets); err == nil && len(rest) == 0 && len(octets) == 2 {
		return octets[0], octets[1], nil
	}
	if len(value) == 2 {
		return value[0], value[1], nil
	}
	return 0, 0, errors.New("attestation usage policy extension is malformed")
}

func parseFirmware(value []byte) string {
	var text string
	if rest, err := asn1.Unmarshal(value, &text); err == nil && len(rest) == 0 {
		return text
	}
	if len(value) == 3 {
		return fmt.Sprintf("%d.%d.%d", value[0], value[1], value[2])
	}
	return ""
}

func parsePEMCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := bytes.TrimSpace(data)
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificates found")
	}
	return certs, nil
}

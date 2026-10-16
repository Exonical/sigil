package ca

import (
	"encoding/asn1"
	"errors"
)

// oidChallengePassword is the PKCS#9 challengePassword attribute, which SCEP clients place in the CSR.
var oidChallengePassword = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}

// ChallengePassword returns the challengePassword attribute of a PKCS#10 request, or "" when the request has none.
// The Go parser in crypto/x509 does not expose this attribute, so it is read here from the DER.
func ChallengePassword(csrDER []byte) (string, error) {
	var request struct {
		Info      asn1.RawValue
		Algorithm asn1.RawValue
		Signature asn1.BitString
	}
	if _, err := asn1.Unmarshal(csrDER, &request); err != nil {
		return "", errors.New("certificate request is not valid DER")
	}
	var info struct {
		Version    int
		Subject    asn1.RawValue
		PublicKey  asn1.RawValue
		Attributes []asn1.RawValue `asn1:"optional,tag:0"`
	}
	if _, err := asn1.Unmarshal(request.Info.FullBytes, &info); err != nil {
		return "", errors.New("certificate request info is malformed")
	}
	for _, raw := range info.Attributes {
		var attribute struct {
			Type   asn1.ObjectIdentifier
			Values []asn1.RawValue `asn1:"set"`
		}
		if _, err := asn1.Unmarshal(raw.FullBytes, &attribute); err != nil {
			return "", errors.New("certificate request attribute is malformed")
		}
		if !attribute.Type.Equal(oidChallengePassword) {
			continue
		}
		if len(attribute.Values) != 1 {
			return "", errors.New("challengePassword must have exactly one value")
		}
		var challenge string
		if _, err := asn1.Unmarshal(attribute.Values[0].FullBytes, &challenge); err != nil {
			return "", errors.New("challengePassword is not a string")
		}
		return challenge, nil
	}
	return "", nil
}

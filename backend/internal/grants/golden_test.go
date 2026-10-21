package grants

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	agentv1 "github.com/Exonical/sigil/backend/gen/sigil/agent/v1"
	"google.golang.org/protobuf/proto"
)

var updateGolden = flag.Bool("update", false, "rewrite the cross-language grant fixture")

const (
	goldenKeyID       = "golden-test-key"
	goldenNotBefore   = int64(1_900_000_000)
	goldenExpiresAt   = int64(1_900_000_120)
	goldenGrantID     = "AAECAwQFBgcICQoLDA0ODw"
	goldenPrivateNote = "TEST-ONLY P-256 key. Never use this fixture key outside tests."
)

type goldenExpected struct {
	Version       uint32 `json:"version"`
	GrantID       string `json:"grant_id"`
	Operation     string `json:"operation"`
	Subject       string `json:"subject"`
	StationID     string `json:"station_id"`
	TokenSerial   string `json:"token_serial"`
	CallerOSUser  string `json:"caller_os_user"`
	NotBeforeUnix int64  `json:"not_before_unix"`
	ExpiresAtUnix int64  `json:"expires_at_unix"`
	PIVSlot       uint32 `json:"piv_slot"`
	KeyID         string `json:"key_id"`
}

type ecdsaSignature struct {
	R, S *big.Int
}

func TestGoldenGrantFixture(t *testing.T) {
	directory := repositoryPath(t, "testdata", "grants", "golden-v1")
	privatePath := filepath.Join(directory, "private_key_test_only.pem")
	publicPath := filepath.Join(directory, "public_key.pem")
	signedPath := filepath.Join(directory, "signed_grant.bin")
	expectedPath := filepath.Join(directory, "expected.json")

	privateKey, err := fixedTestKey()
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	expected := goldenExpected{
		Version:       1,
		GrantID:       goldenGrantID,
		Operation:     agentv1.Operation_PIV_GENERATE_KEY.String(),
		Subject:       "https://idp.example|golden-user",
		StationID:     "station-golden",
		TokenSerial:   "39192733",
		CallerOSUser:  "S-1-5-21-golden",
		NotBeforeUnix: goldenNotBefore,
		ExpiresAtUnix: goldenExpiresAt,
		PIVSlot:       0x9a,
		KeyID:         goldenKeyID,
	}
	operationGrant := &agentv1.OperationGrant{
		Version:       expected.Version,
		GrantId:       expected.GrantID,
		Operation:     agentv1.Operation_PIV_GENERATE_KEY,
		Subject:       expected.Subject,
		StationId:     expected.StationID,
		TokenSerial:   expected.TokenSerial,
		CallerOsUser:  expected.CallerOSUser,
		NotBeforeUnix: expected.NotBeforeUnix,
		ExpiresAtUnix: expected.ExpiresAtUnix,
		PivSlot:       expected.PIVSlot,
	}
	grantBytes, err := (proto.MarshalOptions{Deterministic: true}).Marshal(operationGrant)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(grantBytes)
	expectedBytes, err := json.MarshalIndent(expected, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	expectedBytes = append(expectedBytes, '\n')

	if *updateGolden {
		r, signatureS, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		halfOrder := new(big.Int).Rsh(new(big.Int).Set(privateKey.Params().N), 1)
		if signatureS.Cmp(halfOrder) > 0 {
			signatureS.Sub(privateKey.Params().N, signatureS)
		}
		signature, err := asn1.Marshal(ecdsaSignature{R: r, S: signatureS})
		if err != nil {
			t.Fatal(err)
		}
		signedBytes, err := (proto.MarshalOptions{Deterministic: true}).Marshal(&agentv1.SignedGrant{
			Grant: grantBytes, Signature: signature, KeyId: goldenKeyID,
		})
		if err != nil {
			t.Fatal(err)
		}
		for path, contents := range map[string][]byte{
			publicPath:   publicPEM,
			signedPath:   signedBytes,
			expectedPath: expectedBytes,
		} {
			if err := os.WriteFile(path, contents, 0o600); err != nil {
				t.Fatalf("write golden fixture %s: %v", filepath.Base(path), err)
			}
		}
		t.Log(goldenPrivateNote)
	}

	fixturePrivate, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fixturePrivate, privatePEM) {
		t.Fatal("checked-in test-only private key differs from the fixed test key")
	}
	privateBlock, _ := pem.Decode(fixturePrivate)
	if privateBlock == nil {
		t.Fatal("test-only private key fixture is not PEM")
	}
	fixtureKeyAny, err := x509.ParsePKCS8PrivateKey(privateBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	fixtureKey, ok := fixtureKeyAny.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("test-only private key fixture is not P-256 ECDSA")
	}
	fixedBytes, fixedErr := privateKey.Bytes()
	fixtureBytes, fixtureErr := fixtureKey.Bytes()
	if fixedErr != nil || fixtureErr != nil || !bytes.Equal(fixtureBytes, fixedBytes) {
		t.Fatal("checked-in test-only private key differs from the fixed test key")
	}
	fixturePublic, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(fixturePublic) != string(publicPEM) {
		t.Fatal("checked-in golden public key differs from the fixed test key")
	}
	fixtureExpected, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(fixtureExpected) != string(expectedBytes) {
		t.Fatal("golden expected.json differs from the fixed grant")
	}
	fixtureSigned, err := os.ReadFile(signedPath)
	if err != nil {
		t.Fatal(err)
	}
	var decoded agentv1.SignedGrant
	if err := proto.Unmarshal(fixtureSigned, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.KeyId != expected.KeyID || !bytes.Equal(decoded.Grant, grantBytes) {
		t.Fatal("golden signed grant does not contain the deterministic grant bytes")
	}
	var decodedSignature ecdsaSignature
	rest, err := asn1.Unmarshal(decoded.Signature, &decodedSignature)
	if err != nil || len(rest) != 0 || decodedSignature.R == nil || decodedSignature.S == nil {
		t.Fatalf("golden signature is not valid DER: %v", err)
	}
	if decodedSignature.S.Cmp(new(big.Int).Rsh(new(big.Int).Set(fixtureKey.Params().N), 1)) > 0 {
		t.Fatal("golden signature is not low-S normalized")
	}
	if !ecdsa.Verify(&fixtureKey.PublicKey, digest[:], decodedSignature.R, decodedSignature.S) {
		t.Fatal("golden grant signature did not verify")
	}
}

func fixedTestKey() (*ecdsa.PrivateKey, error) {
	scalar, err := hex.DecodeString("1111111111111111111111111111111111111111111111111111111111111111")
	if err != nil {
		return nil, err
	}
	return ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
}

func repositoryPath(t *testing.T, parts ...string) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate golden fixture path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", ".."))
	return filepath.Join(append([]string{root}, parts...)...)
}

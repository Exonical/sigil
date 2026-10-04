package signing

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/Exonical/sigil/backend/internal/config"
)

type Signer interface {
	KeyID() string
	Sign(msg []byte) ([]byte, error)
}

type FileSigner struct {
	keyID string
	key   *ecdsa.PrivateKey
}

type ecdsaDER struct {
	R, S *big.Int
}

func NewFileSigner(keyID, path string) (*FileSigner, error) {
	if keyID == "" {
		return nil, errors.New("signing key ID is required")
	}
	if err := config.CheckPrivateFile(path); err != nil {
		return nil, fmt.Errorf("unsafe grant signing key: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("could not read grant signing key")
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("grant signing key must be PKCS#8 PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("grant signing key is invalid PKCS#8")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("grant signing key must be ECDSA P-256")
	}
	curveKey, err := key.ECDH()
	if err != nil || curveKey.Curve() != ecdh.P256() {
		return nil, errors.New("grant signing key must be ECDSA P-256")
	}
	if _, err := key.Bytes(); err != nil {
		return nil, errors.New("grant signing key is invalid")
	}
	return &FileSigner{keyID: keyID, key: key}, nil
}

func (s *FileSigner) KeyID() string {
	return s.keyID
}

func (s *FileSigner) Sign(msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	r, signatureS, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("sign grant: %w", err)
	}
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(s.key.Params().N), 1)
	if signatureS.Cmp(halfOrder) > 0 {
		signatureS.Sub(s.key.Params().N, signatureS)
	}
	return asn1.Marshal(ecdsaDER{R: r, S: signatureS})
}

func GenerateKeyPair() ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate P-256 key: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("encode PKCS#8 private key: %w", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("encode SPKI public key: %w", err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	return privatePEM, publicPEM, nil
}

func WriteNewKeyPair(privatePath, publicPath string) error {
	if err := os.MkdirAll(filepath.Dir(privatePath), 0o700); err != nil {
		return fmt.Errorf("create private key directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(publicPath), 0o700); err != nil {
		return fmt.Errorf("create public key directory: %w", err)
	}
	privatePEM, publicPEM, err := GenerateKeyPair()
	if err != nil {
		return err
	}
	if err := writeNewFile(privatePath, privatePEM, 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := writeNewFile(publicPath, publicPEM, 0o644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}
	return nil
}

func writeNewFile(path string, contents []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	return nil
}

func Verify(publicKey *ecdsa.PublicKey, message, derSignature []byte) bool {
	if publicKey == nil || publicKey.Curve.Params().Name != elliptic.P256().Params().Name {
		return false
	}
	var signature ecdsaDER
	rest, err := asn1.Unmarshal(derSignature, &signature)
	if err != nil || len(rest) != 0 || signature.R == nil || signature.S == nil {
		return false
	}
	digest := sha256.Sum256(message)
	return ecdsa.Verify(publicKey, digest[:], signature.R, signature.S)
}

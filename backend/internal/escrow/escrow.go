package escrow

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const aadVersion = "sigil-escrow-v1\x00"

type Context struct {
	Vendor    string
	Serial    string
	Kind      string
	Algorithm string
	Version   int
}

type Envelope struct {
	KEKID      string
	DEKNonce   []byte
	WrappedDEK []byte
	Nonce      []byte
	Ciphertext []byte
}

type Keyring struct {
	currentID string
	current   [32]byte
	previous  map[string][32]byte
}

func NewKeyring(currentID string, current []byte, previous map[string][]byte) (*Keyring, error) {
	if strings.TrimSpace(currentID) == "" || len(current) != 32 {
		return nil, errors.New("escrow requires a key ID and a 32-byte current KEK")
	}
	keyring := &Keyring{currentID: currentID, previous: make(map[string][32]byte, len(previous))}
	copy(keyring.current[:], current)
	for id, key := range previous {
		if strings.TrimSpace(id) == "" || id == currentID || len(key) != 32 {
			return nil, errors.New("previous escrow KEKs require distinct IDs and 32-byte keys")
		}
		var material [32]byte
		copy(material[:], key)
		keyring.previous[id] = material
	}
	return keyring, nil
}

func (k *Keyring) CurrentID() string {
	return k.currentID
}

func (k *Keyring) Close() {
	clear(k.current[:])
	for id, key := range k.previous {
		clear(key[:])
		k.previous[id] = key
	}
	clear(k.previous)
}

func (k *Keyring) Encrypt(ctx Context, secret []byte) (Envelope, error) {
	if err := validateSecret(ctx, secret); err != nil {
		return Envelope{}, err
	}
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return Envelope{}, errors.New("generate escrow DEK")
	}
	defer clear(dek)

	wrappingGCM, err := newGCM(k.current[:])
	if err != nil {
		return Envelope{}, err
	}
	dekGCM, err := newGCM(dek)
	if err != nil {
		return Envelope{}, err
	}
	aad := AdditionalData(ctx)
	dekNonce := make([]byte, wrappingGCM.NonceSize())
	if _, err := rand.Read(dekNonce); err != nil {
		return Envelope{}, errors.New("generate escrow DEK nonce")
	}
	nonce := make([]byte, dekGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, errors.New("generate escrow nonce")
	}
	return Envelope{
		KEKID:      k.currentID,
		DEKNonce:   dekNonce,
		WrappedDEK: wrappingGCM.Seal(nil, dekNonce, dek, aad),
		Nonce:      nonce,
		Ciphertext: dekGCM.Seal(nil, nonce, secret, aad),
	}, nil
}

func (k *Keyring) Decrypt(ctx Context, envelope Envelope) ([]byte, error) {
	var kek []byte
	if envelope.KEKID == k.currentID {
		kek = k.current[:]
	} else if previous, ok := k.previous[envelope.KEKID]; ok {
		kek = previous[:]
	} else {
		return nil, errors.New("escrow KEK ID is unavailable")
	}
	wrappingGCM, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	dek, err := wrappingGCM.Open(nil, envelope.DEKNonce, envelope.WrappedDEK, AdditionalData(ctx))
	if err != nil || len(dek) != 32 {
		clear(dek)
		return nil, errors.New("escrow wrapped DEK authentication failed")
	}
	defer clear(dek)
	dekGCM, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	secret, err := dekGCM.Open(nil, envelope.Nonce, envelope.Ciphertext, AdditionalData(ctx))
	if err != nil {
		return nil, errors.New("escrow ciphertext authentication failed")
	}
	if err := validateSecret(ctx, secret); err != nil {
		clear(secret)
		return nil, errors.New("escrow plaintext is invalid")
	}
	return secret, nil
}

func AdditionalData(ctx Context) []byte {
	return []byte(aadVersion + ctx.Vendor + "\x00" + ctx.Serial + "\x00" + ctx.Kind +
		"\x00" + ctx.Algorithm + "\x00" + strconv.Itoa(ctx.Version))
}

func GeneratePUK() ([]byte, error) {
	puk := make([]byte, 8)
	limit := big.NewInt(10)
	for index := range puk {
		digit, err := rand.Int(rand.Reader, limit)
		if err != nil {
			clear(puk)
			return nil, errors.New("generate escrow PUK")
		}
		puk[index] = byte('0' + digit.Int64())
	}
	return puk, nil
}

func GenerateManagementKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		clear(key)
		return nil, errors.New("generate escrow management key")
	}
	return key, nil
}

func WriteNewKEK(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("escrow KEK output path is required")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create escrow key directory: %w", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		clear(key)
		return errors.New("generate escrow KEK")
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(key) + "\n")
	clear(key)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		clear(encoded)
		return fmt.Errorf("create escrow KEK file: %w", err)
	}
	if _, err := file.Write(encoded); err != nil {
		clear(encoded)
		_ = file.Close()
		return fmt.Errorf("write escrow KEK file: %w", err)
	}
	clear(encoded)
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync escrow KEK file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close escrow KEK file: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("protect escrow KEK file: %w", err)
	}
	return nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("escrow AES key is invalid")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("create escrow AES-GCM")
	}
	return gcm, nil
}

func validateSecret(ctx Context, secret []byte) error {
	if ctx.Vendor == "" || ctx.Serial == "" || ctx.Version < 1 {
		return errors.New("escrow associated data is incomplete")
	}
	switch ctx.Kind {
	case "puk":
		if ctx.Algorithm != "" || len(secret) != 8 {
			return errors.New("escrow PUK must be eight digits")
		}
		for _, digit := range secret {
			if digit < '0' || digit > '9' {
				return errors.New("escrow PUK must be eight digits")
			}
		}
	case "management_key":
		lengths := map[string]int{"aes128": 16, "aes192": 24, "aes256": 32}
		if lengths[ctx.Algorithm] == 0 || len(secret) != lengths[ctx.Algorithm] {
			return errors.New("escrow management key does not match its algorithm")
		}
	default:
		return errors.New("unsupported escrow secret kind")
	}
	return nil
}

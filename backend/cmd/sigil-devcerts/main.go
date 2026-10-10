package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("sigil-devcerts", flag.ContinueOnError)
	outputDirectory := flags.String("out-dir", "", "directory for the development TLS certificate")
	dnsName := flags.String("dns", "", "machine DNS name")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *outputDirectory == "" || *dnsName == "" {
		return errors.New("sigil-devcerts requires --out-dir and --dns")
	}
	certPath := filepath.Join(*outputDirectory, "backend-server.crt")
	keyPath := filepath.Join(*outputDirectory, "backend-server.key")
	if _, certErr := os.Stat(certPath); certErr == nil {
		if _, keyErr := os.Stat(keyPath); keyErr == nil {
			if err := validateExisting(certPath, keyPath, *dnsName); err != nil {
				return fmt.Errorf("existing backend TLS identity is invalid: %w", err)
			}
			fmt.Println(filepath.Clean(certPath))
			return nil
		}
	}
	if _, err := os.Stat(certPath); err == nil {
		return errors.New("backend TLS certificate exists without its private key")
	}
	if _, err := os.Stat(keyPath); err == nil {
		return errors.New("backend TLS private key exists without its certificate")
	}
	if err := os.MkdirAll(*outputDirectory, 0o700); err != nil {
		return fmt.Errorf("create backend TLS directory: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return errors.New("generate backend TLS key")
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return errors.New("generate backend TLS certificate serial")
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Sigil development backend"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost", *dnsName},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return errors.New("create backend TLS certificate")
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return errors.New("encode backend TLS private key")
	}
	if err := writeNewFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o644); err != nil {
		return fmt.Errorf("write backend TLS certificate: %w", err)
	}
	if err := writeNewFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		return fmt.Errorf("write backend TLS private key: %w", err)
	}
	fmt.Println(filepath.Clean(certPath))
	return nil
}

func validateExisting(certPath, keyPath, dnsName string) error {
	certificatePEM, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	certificateBlock, _ := pem.Decode(certificatePEM)
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" {
		return errors.New("certificate is not PEM encoded")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return errors.New("certificate cannot be parsed")
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		return errors.New("private key is not PKCS#8 PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return errors.New("private key cannot be parsed")
	}
	privateKey, ok := key.(*ecdsa.PrivateKey)
	if !ok || !certificate.NotAfter.After(time.Now()) || certificate.VerifyHostname("localhost") != nil ||
		certificate.VerifyHostname(dnsName) != nil {
		return errors.New("certificate is expired or lacks required DNS names")
	}
	if _, err := privateKey.ECDH(); err != nil {
		return errors.New("private key cannot be used for ECDH")
	}
	certPublic, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return errors.New("certificate public key is invalid")
	}
	keyPublic, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil || string(certPublic) != string(keyPublic) {
		return errors.New("certificate and private key do not match")
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
	return os.Chmod(path, mode)
}

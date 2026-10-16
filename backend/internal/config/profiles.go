package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// CA configures an external certificate authority that signs enrollment requests.
type CA struct {
	Type                    string `toml:"type"`
	URL                     string `toml:"url"`
	RootFile                string `toml:"root_file"`
	Provisioner             string `toml:"provisioner"`
	ProvisionerKeyFile      string `toml:"provisioner_key_file"`
	ProvisionerPasswordFile string `toml:"provisioner_password_file"`
	// SCEP CAs only. The RA certificate and key sign PKCSReq. The webhook secret is the base64 key that step-ca signs
	// its SCEPCHALLENGE webhook requests with. Revoker names a step CA that revokes certificates issued here.
	RACertFile        string `toml:"ra_cert_file"`
	RAKeyFile         string `toml:"ra_key_file"`
	WebhookSecretFile string `toml:"webhook_secret_file"`
	Revoker           string `toml:"revoker"`
}

// Profile describes a certificate that users may enroll on a PIV token.
// Key attributes are fixed here; the agent takes them from the backend, never from the caller.
type Profile struct {
	Name          string   `toml:"name"`
	DisplayName   string   `toml:"display_name"`
	Slot          string   `toml:"slot"`
	Algorithm     string   `toml:"algorithm"`
	PinPolicy     string   `toml:"pin_policy"`
	TouchPolicy   string   `toml:"touch_policy"`
	Subject       string   `toml:"subject"`
	EmailSAN      bool     `toml:"email_san"`
	ValidityHours int      `toml:"validity_hours"`
	CA            string   `toml:"ca"`
	Roles         []string `toml:"roles"`
}

var profileNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

var subjectPlaceholderPattern = regexp.MustCompile(`\{([a-z]+)\}`)

var validSubjectPlaceholders = map[string]bool{"username": true, "email": true, "subject": true}

func resolveCAPaths(base string, cas map[string]CA) {
	for name, ca := range cas {
		ca.RootFile = resolvePath(base, ca.RootFile)
		ca.ProvisionerKeyFile = resolvePath(base, ca.ProvisionerKeyFile)
		ca.ProvisionerPasswordFile = resolvePath(base, ca.ProvisionerPasswordFile)
		ca.RACertFile = resolvePath(base, ca.RACertFile)
		ca.RAKeyFile = resolvePath(base, ca.RAKeyFile)
		ca.WebhookSecretFile = resolvePath(base, ca.WebhookSecretFile)
		cas[name] = ca
	}
}

func validateCAs(cas map[string]CA) error {
	for name, ca := range cas {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("CA names must not be empty")
		}
		if !strings.HasPrefix(ca.URL, "https://") {
			return fmt.Errorf("CA %q url must be an https URL", name)
		}
		switch ca.Type {
		case "step":
			if err := validateStepCA(name, ca); err != nil {
				return err
			}
		case "scep":
			if err := validateSCEPCA(name, ca, cas); err != nil {
				return err
			}
		default:
			return fmt.Errorf("CA %q has unsupported type %q; supported types: step, scep", name, ca.Type)
		}
	}
	return nil
}

func validateStepCA(name string, ca CA) error {
	if ca.RootFile == "" || ca.Provisioner == "" || ca.ProvisionerKeyFile == "" || ca.ProvisionerPasswordFile == "" {
		return fmt.Errorf("CA %q requires root_file, provisioner, provisioner_key_file and provisioner_password_file", name)
	}
	if err := CheckPrivateFile(ca.ProvisionerKeyFile); err != nil {
		return fmt.Errorf("unsafe CA %q provisioner key: %w", name, err)
	}
	if err := CheckPrivateFile(ca.ProvisionerPasswordFile); err != nil {
		return fmt.Errorf("unsafe CA %q provisioner password: %w", name, err)
	}
	return nil
}

// validateSCEPCA checks a SCEP CA. Its revoker must be a step CA, because SCEP has no revocation of its own.
func validateSCEPCA(name string, ca CA, cas map[string]CA) error {
	if ca.RootFile == "" || ca.RACertFile == "" || ca.RAKeyFile == "" || ca.WebhookSecretFile == "" || ca.Revoker == "" {
		return fmt.Errorf("CA %q requires root_file, ra_cert_file, ra_key_file, webhook_secret_file and revoker", name)
	}
	if err := CheckPrivateFile(ca.RAKeyFile); err != nil {
		return fmt.Errorf("unsafe CA %q RA key: %w", name, err)
	}
	if err := CheckPrivateFile(ca.WebhookSecretFile); err != nil {
		return fmt.Errorf("unsafe CA %q webhook secret: %w", name, err)
	}
	if _, err := LoadWebhookSecret(ca.WebhookSecretFile); err != nil {
		return fmt.Errorf("CA %q webhook secret: %w", name, err)
	}
	revoker, ok := cas[ca.Revoker]
	if !ok {
		return fmt.Errorf("CA %q revoker %q is not configured", name, ca.Revoker)
	}
	if revoker.Type != "step" {
		return fmt.Errorf("CA %q revoker %q must be a step CA", name, ca.Revoker)
	}
	return nil
}

// LoadWebhookSecret reads the base64 key that step-ca uses to sign its webhook requests. The decoded bytes are the
// HMAC key. The secret is never returned in an error.
func LoadWebhookSecret(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("read webhook secret file")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(key) == 0 {
		return nil, errors.New("webhook secret file must contain a non-empty base64 key")
	}
	return key, nil
}

// SCEPCAs returns the names of the SCEP CAs, sorted by name.
func SCEPCAs(cas map[string]CA) []string {
	var names []string
	for name, ca := range cas {
		if ca.Type == "scep" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func validateProfiles(profiles []Profile, cas map[string]CA) error {
	seen := make(map[string]bool, len(profiles))
	for _, profile := range profiles {
		if !profileNamePattern.MatchString(profile.Name) {
			return fmt.Errorf("profile name %q must be lowercase letters, digits and hyphens", profile.Name)
		}
		if seen[profile.Name] {
			return fmt.Errorf("profile name %q is defined more than once", profile.Name)
		}
		seen[profile.Name] = true
		if strings.TrimSpace(profile.DisplayName) == "" {
			return fmt.Errorf("profile %q requires display_name", profile.Name)
		}
		switch profile.Slot {
		case "9a", "9c", "9d", "9e":
		default:
			return fmt.Errorf("profile %q slot must be one of 9a, 9c, 9d, 9e", profile.Name)
		}
		switch profile.Algorithm {
		case "p256", "p384":
		default:
			return fmt.Errorf("profile %q algorithm must be p256 or p384", profile.Name)
		}
		switch profile.PinPolicy {
		case "once", "always", "never":
		default:
			return fmt.Errorf("profile %q pin_policy must be once, always or never", profile.Name)
		}
		switch profile.TouchPolicy {
		case "never", "always", "cached":
		default:
			return fmt.Errorf("profile %q touch_policy must be never, always or cached", profile.Name)
		}
		if profile.Subject == "" {
			return fmt.Errorf("profile %q requires subject", profile.Name)
		}
		for _, match := range subjectPlaceholderPattern.FindAllStringSubmatch(profile.Subject, -1) {
			if !validSubjectPlaceholders[match[1]] {
				return fmt.Errorf("profile %q subject uses unknown placeholder {%s}", profile.Name, match[1])
			}
		}
		if profile.ValidityHours < 1 || profile.ValidityHours > 2160 {
			return fmt.Errorf("profile %q validity_hours must be between 1 and 2160", profile.Name)
		}
		if _, ok := cas[profile.CA]; !ok {
			return fmt.Errorf("profile %q references unknown CA %q", profile.Name, profile.CA)
		}
		if len(profile.Roles) == 0 {
			return fmt.Errorf("profile %q requires at least one role", profile.Name)
		}
	}
	return nil
}

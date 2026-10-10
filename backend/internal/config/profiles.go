package config

import (
	"fmt"
	"regexp"
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
		cas[name] = ca
	}
}

func validateCAs(cas map[string]CA) error {
	for name, ca := range cas {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("CA names must not be empty")
		}
		if ca.Type != "step" {
			return fmt.Errorf("CA %q has unsupported type %q; supported types: step", name, ca.Type)
		}
		if !strings.HasPrefix(ca.URL, "https://") {
			return fmt.Errorf("CA %q url must be an https URL", name)
		}
		if ca.RootFile == "" || ca.Provisioner == "" || ca.ProvisionerKeyFile == "" || ca.ProvisionerPasswordFile == "" {
			return fmt.Errorf("CA %q requires root_file, provisioner, provisioner_key_file and provisioner_password_file", name)
		}
		if err := CheckPrivateFile(ca.ProvisionerKeyFile); err != nil {
			return fmt.Errorf("unsafe CA %q provisioner key: %w", name, err)
		}
		if err := CheckPrivateFile(ca.ProvisionerPasswordFile); err != nil {
			return fmt.Errorf("unsafe CA %q provisioner password: %w", name, err)
		}
	}
	return nil
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

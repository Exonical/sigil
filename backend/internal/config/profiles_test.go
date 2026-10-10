package config

import "testing"

func validProfile() Profile {
	return Profile{
		Name:          "piv-authentication",
		DisplayName:   "PIV Authentication",
		Slot:          "9a",
		Algorithm:     "p256",
		PinPolicy:     "once",
		TouchPolicy:   "never",
		Subject:       "CN={username}",
		EmailSAN:      true,
		ValidityHours: 720,
		CA:            "dev-step",
		Roles:         []string{"admin", "helpdesk", "user"},
	}
}

func TestValidateProfilesAcceptsTheDevProfile(t *testing.T) {
	cas := map[string]CA{"dev-step": {}}
	if err := validateProfiles([]Profile{validProfile()}, cas); err != nil {
		t.Fatal(err)
	}
}

func TestValidateProfilesRejectsInvalidDefinitions(t *testing.T) {
	cases := map[string]func(*Profile){
		"bad name":            func(p *Profile) { p.Name = "Bad Name" },
		"bad slot":            func(p *Profile) { p.Slot = "f9" },
		"bad algorithm":       func(p *Profile) { p.Algorithm = "rsa2048" },
		"bad pin policy":      func(p *Profile) { p.PinPolicy = "default" },
		"bad touch policy":    func(p *Profile) { p.TouchPolicy = "sometimes" },
		"unknown placeholder": func(p *Profile) { p.Subject = "CN={department}" },
		"validity too long":   func(p *Profile) { p.ValidityHours = 2161 },
		"unknown CA":          func(p *Profile) { p.CA = "missing" },
		"no roles":            func(p *Profile) { p.Roles = nil },
		"no subject":          func(p *Profile) { p.Subject = "" },
	}
	for name, mutate := range cases {
		profile := validProfile()
		mutate(&profile)
		if err := validateProfiles([]Profile{profile}, map[string]CA{"dev-step": {}}); err == nil {
			t.Fatalf("%s: expected a validation error", name)
		}
	}
}

func TestValidateProfilesRejectsDuplicateNames(t *testing.T) {
	profiles := []Profile{validProfile(), validProfile()}
	if err := validateProfiles(profiles, map[string]CA{"dev-step": {}}); err == nil {
		t.Fatal("duplicate profile names must be rejected")
	}
}

func TestValidateCAsRequiresHTTPSAndPrivateKeyFiles(t *testing.T) {
	if err := validateCAs(map[string]CA{"dev-step": {Type: "step", URL: "http://ca.example", RootFile: "r", Provisioner: "p", ProvisionerKeyFile: "k", ProvisionerPasswordFile: "pw"}}); err == nil {
		t.Fatal("a CA URL must be https")
	}
	if err := validateCAs(map[string]CA{"dev-step": {Type: "ejbca", URL: "https://ca.example", RootFile: "r", Provisioner: "p", ProvisionerKeyFile: "k", ProvisionerPasswordFile: "pw"}}); err == nil {
		t.Fatal("unsupported CA types must be rejected")
	}
}

package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

type Config struct {
	ListenGRPC   string        `toml:"listen_grpc"`
	DatabaseURL  string        `toml:"database_url"`
	TLS          TLS           `toml:"tls"`
	OIDC         OIDC          `toml:"oidc"`
	Grants       Grants        `toml:"grants"`
	Policy       Policy        `toml:"policy"`
	Escrow       Escrow        `toml:"escrow"`
	CA           map[string]CA `toml:"ca"`
	Profiles     []Profile     `toml:"profiles"`
	Lifecycle    Lifecycle     `toml:"lifecycle"`
	ListenPortal string        `toml:"listen_portal"`
	Portal       Portal        `toml:"portal"`
	CAWebhook    CAWebhook     `toml:"ca_webhook"`
}

// CAWebhook configures the HTTPS listener that step-ca's SCEPCHALLENGE webhook calls. It is required when a SCEP CA is
// configured.
type CAWebhook struct {
	Listen   string `toml:"listen"`
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
}

type TLS struct {
	CertFile     string `toml:"cert_file"`
	KeyFile      string `toml:"key_file"`
	ClientCAFile string `toml:"client_ca_file"`
}

type OIDC struct {
	Issuer      string     `toml:"issuer"`
	CAFile      string     `toml:"ca_file"`
	Audience    string     `toml:"audience"`
	GroupsClaim string     `toml:"groups_claim"`
	RoleGroups  RoleGroups `toml:"role_groups"`
}

type Escrow struct {
	KEKID        string            `toml:"kek_id"`
	KEKFile      string            `toml:"kek_file"`
	PreviousKEKs map[string]string `toml:"previous_keks"`
	CurrentKey   []byte            `toml:"-"`
	PreviousKeys map[string][]byte `toml:"-"`
}

type RoleGroups struct {
	Admin    []string `toml:"admin"`
	Helpdesk []string `toml:"helpdesk"`
}

type Grants struct {
	KeyID           string `toml:"key_id"`
	SigningKeyFile  string `toml:"signing_key_file"`
	LifetimeSeconds int64  `toml:"lifetime_seconds"`
}

type Policy struct {
	SelfServiceOperations []string `toml:"self_service_operations"`
}

func Load(path string) (*Config, error) {
	if err := CheckPrivateFile(path); err != nil {
		return nil, fmt.Errorf("unsafe backend config: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read backend config: %w", err)
	}
	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, errors.New("could not parse backend config TOML")
	}
	if cfg.OIDC.GroupsClaim == "" {
		cfg.OIDC.GroupsClaim = "groups"
	}
	if cfg.Portal.ClientID == "" {
		cfg.Portal.ClientID = "sigil"
	}
	if cfg.Portal.PublicURL == "" && cfg.ListenPortal != "" {
		cfg.Portal.PublicURL = "https://" + cfg.ListenPortal
	}
	if cfg.Lifecycle.LostRevocationGraceHours == 0 {
		cfg.Lifecycle.LostRevocationGraceHours = 24
	}
	if cfg.Grants.LifetimeSeconds == 0 {
		cfg.Grants.LifetimeSeconds = 120
	}
	base := filepath.Dir(path)
	cfg.TLS.CertFile = resolvePath(base, cfg.TLS.CertFile)
	cfg.TLS.KeyFile = resolvePath(base, cfg.TLS.KeyFile)
	cfg.TLS.ClientCAFile = resolvePath(base, cfg.TLS.ClientCAFile)
	cfg.OIDC.CAFile = resolvePath(base, cfg.OIDC.CAFile)
	cfg.Grants.SigningKeyFile = resolvePath(base, cfg.Grants.SigningKeyFile)
	cfg.Escrow.KEKFile = resolvePath(base, cfg.Escrow.KEKFile)
	resolveCAPaths(base, cfg.CA)
	cfg.CAWebhook.CertFile = resolvePath(base, cfg.CAWebhook.CertFile)
	cfg.CAWebhook.KeyFile = resolvePath(base, cfg.CAWebhook.KeyFile)
	for id, path := range cfg.Escrow.PreviousKEKs {
		cfg.Escrow.PreviousKEKs[id] = resolvePath(base, path)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.Escrow.KEKID != "" {
		key, err := loadKEK(cfg.Escrow.KEKFile)
		if err != nil {
			return nil, fmt.Errorf("load current escrow KEK: %w", err)
		}
		cfg.Escrow.CurrentKey = key
		cfg.Escrow.PreviousKeys = make(map[string][]byte, len(cfg.Escrow.PreviousKEKs))
		for id, path := range cfg.Escrow.PreviousKEKs {
			key, err := loadKEK(path)
			if err != nil {
				return nil, fmt.Errorf("load previous escrow KEK %q: %w", id, err)
			}
			cfg.Escrow.PreviousKeys[id] = key
		}
	}
	return &cfg, nil
}

func resolvePath(base, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(base, path)
}

func (c *Config) Validate() error {
	if strings.TrimSpace(c.ListenGRPC) == "" {
		return fmt.Errorf("listen_grpc is required")
	}
	if _, _, err := net.SplitHostPort(c.ListenGRPC); err != nil {
		return fmt.Errorf("listen_grpc must be a host:port address")
	}
	if strings.TrimSpace(c.DatabaseURL) == "" {
		return fmt.Errorf("database_url is required")
	}
	if c.TLS.CertFile == "" || c.TLS.KeyFile == "" || c.TLS.ClientCAFile == "" {
		return fmt.Errorf("tls cert_file, key_file, and client_ca_file are required")
	}
	if _, err := os.Stat(c.TLS.CertFile); err != nil {
		return fmt.Errorf("TLS file %q is unavailable", c.TLS.CertFile)
	}
	if err := CheckPrivateFile(c.TLS.KeyFile); err != nil {
		return fmt.Errorf("unsafe TLS private key: %w", err)
	}
	if c.OIDC.Issuer == "" || c.OIDC.Audience == "" {
		return fmt.Errorf("oidc issuer and audience are required")
	}
	issuer, err := url.Parse(c.OIDC.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" {
		return fmt.Errorf("oidc issuer must be an HTTPS URL")
	}
	if c.OIDC.CAFile != "" {
		if _, err := os.Stat(c.OIDC.CAFile); err != nil {
			return fmt.Errorf("OIDC CA file %q is unavailable", c.OIDC.CAFile)
		}
	}
	if c.Grants.KeyID == "" || c.Grants.SigningKeyFile == "" {
		return fmt.Errorf("grants key_id and signing_key_file are required")
	}
	if err := c.validatePortal(); err != nil {
		return err
	}
	if c.Lifecycle.LostRevocationGraceHours < 1 || c.Lifecycle.LostRevocationGraceHours > 720 {
		return fmt.Errorf("lifecycle lost_revocation_grace_hours must be between 1 and 720")
	}
	if c.Grants.LifetimeSeconds < 30 || c.Grants.LifetimeSeconds > 300 {
		return fmt.Errorf("grants lifetime_seconds must be between 30 and 300")
	}
	if err := CheckPrivateFile(c.Grants.SigningKeyFile); err != nil {
		return fmt.Errorf("unsafe grant signing key: %w", err)
	}
	if c.Escrow.KEKID != "" || c.Escrow.KEKFile != "" || len(c.Escrow.PreviousKEKs) != 0 {
		if strings.TrimSpace(c.Escrow.KEKID) == "" || strings.TrimSpace(c.Escrow.KEKFile) == "" {
			return fmt.Errorf("escrow kek_id and kek_file are required")
		}
		if err := CheckPrivateFile(c.Escrow.KEKFile); err != nil {
			return fmt.Errorf("unsafe current escrow KEK: %w", err)
		}
		for id, path := range c.Escrow.PreviousKEKs {
			if strings.TrimSpace(id) == "" || strings.TrimSpace(path) == "" || id == c.Escrow.KEKID {
				return fmt.Errorf("escrow previous KEKs require an ID and file path")
			}
			if err := CheckPrivateFile(path); err != nil {
				return fmt.Errorf("unsafe previous escrow KEK %q: %w", id, err)
			}
		}
	}
	for _, operation := range c.Policy.SelfServiceOperations {
		switch operation {
		case "PIV_GENERATE_KEY", "PIV_IMPORT_CERTIFICATE", "PIV_DELETE_CERTIFICATE",
			"PIV_UNBLOCK_PIN", "PIV_CHANGE_PUK", "PIV_CHANGE_MANAGEMENT_KEY", "PIV_SET_RETRIES",
			"PIV_DELETE_KEY", "PIV_MANAGED_INITIALIZE":
		default:
			return fmt.Errorf("unknown self_service_operations entry %q", operation)
		}
	}
	if err := validateCAs(c.CA); err != nil {
		return err
	}
	if len(SCEPCAs(c.CA)) > 0 {
		if err := c.validateCAWebhook(); err != nil {
			return err
		}
	}
	if err := validateProfiles(c.Profiles, c.CA); err != nil {
		return err
	}
	return nil
}

// validateCAWebhook checks the listener that SCEP CAs depend on.
func (c *Config) validateCAWebhook() error {
	if strings.TrimSpace(c.CAWebhook.Listen) == "" {
		return fmt.Errorf("ca_webhook listen is required when a SCEP CA is configured")
	}
	if _, _, err := net.SplitHostPort(c.CAWebhook.Listen); err != nil {
		return fmt.Errorf("ca_webhook listen must be a host:port address")
	}
	if c.CAWebhook.CertFile == "" || c.CAWebhook.KeyFile == "" {
		return fmt.Errorf("ca_webhook cert_file and key_file are required")
	}
	if _, err := os.Stat(c.CAWebhook.CertFile); err != nil {
		return fmt.Errorf("ca_webhook certificate file: %w", err)
	}
	if err := CheckPrivateFile(c.CAWebhook.KeyFile); err != nil {
		return fmt.Errorf("unsafe ca_webhook key: %w", err)
	}
	return nil
}

func loadKEK(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("key file must contain a base64-encoded 32-byte key")
	}
	return key, nil
}

func CheckPrivateFile(path string) error {
	if path == "" {
		return fmt.Errorf("path is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%q is not a regular file", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%q must not be group- or world-readable", path)
	}
	return nil
}

// Lifecycle configures background certificate lifecycle jobs.
type Lifecycle struct {
	// LostRevocationGraceHours is how long a lost token keeps its certificates before they are revoked.
	LostRevocationGraceHours int `toml:"lost_revocation_grace_hours"`
}

// Portal configures the admin web portal listener and its browser settings.
type Portal struct {
	// PublicURL is the portal origin the browser uses for API calls. It defaults to https://<listen_portal>.
	PublicURL string `toml:"public_url"`
	// ClientID is the OIDC public client the portal signs in with.
	ClientID string `toml:"client_id"`
	// DevOrigins are Vite dev-server origins allowed to call the API with CORS. Empty in production.
	DevOrigins []string `toml:"dev_origins"`
}

func (c *Config) validatePortal() error {
	if c.ListenPortal == "" {
		if c.Portal.PublicURL != "" || len(c.Portal.DevOrigins) != 0 {
			return fmt.Errorf("portal settings require listen_portal")
		}
		return nil
	}
	if _, _, err := net.SplitHostPort(c.ListenPortal); err != nil {
		return fmt.Errorf("listen_portal must be a host:port address")
	}
	if !strings.HasPrefix(c.Portal.PublicURL, "https://") {
		return fmt.Errorf("portal public_url must be an HTTPS URL")
	}
	for _, origin := range c.Portal.DevOrigins {
		if !strings.HasPrefix(origin, "http://localhost:") && !strings.HasPrefix(origin, "http://127.0.0.1:") {
			return fmt.Errorf("portal dev_origins must be local http origins")
		}
	}
	return nil
}

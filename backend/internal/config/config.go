package config

import (
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
	ListenGRPC  string `toml:"listen_grpc"`
	DatabaseURL string `toml:"database_url"`
	TLS         TLS    `toml:"tls"`
	OIDC        OIDC   `toml:"oidc"`
	Grants      Grants `toml:"grants"`
	Policy      Policy `toml:"policy"`
}

type TLS struct {
	CertFile     string `toml:"cert_file"`
	KeyFile      string `toml:"key_file"`
	ClientCAFile string `toml:"client_ca_file"`
}

type OIDC struct {
	Issuer      string     `toml:"issuer"`
	Audience    string     `toml:"audience"`
	GroupsClaim string     `toml:"groups_claim"`
	RoleGroups  RoleGroups `toml:"role_groups"`
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
	if cfg.Grants.LifetimeSeconds == 0 {
		cfg.Grants.LifetimeSeconds = 120
	}
	base := filepath.Dir(path)
	cfg.TLS.CertFile = resolvePath(base, cfg.TLS.CertFile)
	cfg.TLS.KeyFile = resolvePath(base, cfg.TLS.KeyFile)
	cfg.TLS.ClientCAFile = resolvePath(base, cfg.TLS.ClientCAFile)
	cfg.Grants.SigningKeyFile = resolvePath(base, cfg.Grants.SigningKeyFile)
	if err := cfg.Validate(); err != nil {
		return nil, err
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
	for _, path := range []string{c.TLS.CertFile, c.TLS.ClientCAFile} {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("TLS file %q is unavailable", path)
		}
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
	if c.Grants.KeyID == "" || c.Grants.SigningKeyFile == "" {
		return fmt.Errorf("grants key_id and signing_key_file are required")
	}
	if c.Grants.LifetimeSeconds < 30 || c.Grants.LifetimeSeconds > 300 {
		return fmt.Errorf("grants lifetime_seconds must be between 30 and 300")
	}
	if err := CheckPrivateFile(c.Grants.SigningKeyFile); err != nil {
		return fmt.Errorf("unsafe grant signing key: %w", err)
	}
	for _, operation := range c.Policy.SelfServiceOperations {
		switch operation {
		case "PIV_GENERATE_KEY", "PIV_IMPORT_CERTIFICATE", "PIV_DELETE_CERTIFICATE",
			"PIV_UNBLOCK_PIN", "PIV_CHANGE_PUK", "PIV_CHANGE_MANAGEMENT_KEY", "PIV_SET_RETRIES":
		default:
			return fmt.Errorf("unknown self_service_operations entry %q", operation)
		}
	}
	return nil
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

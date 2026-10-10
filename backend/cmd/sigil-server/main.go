package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/Exonical/sigil/backend/internal/audit"
	"github.com/Exonical/sigil/backend/internal/authn"
	"github.com/Exonical/sigil/backend/internal/ca"
	"github.com/Exonical/sigil/backend/internal/config"
	"github.com/Exonical/sigil/backend/internal/db"
	"github.com/Exonical/sigil/backend/internal/escrow"
	"github.com/Exonical/sigil/backend/internal/gateway"
	"github.com/Exonical/sigil/backend/internal/signing"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if err := run(os.Args[1:]); err != nil {
		slog.Error("command failed", "error", err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("expected serve, migrate, station, audit, keygen, or escrow")
	}
	switch args[0] {
	case "serve":
		return serve(args[1:])
	case "migrate":
		return migrate(args[1:])
	case "station":
		if len(args) < 2 {
			return errors.New("expected station add or station disable")
		}
		switch args[1] {
		case "add":
			return stationAdd(args[2:])
		case "disable":
			return stationDisable(args[2:])
		default:
			return errors.New("expected station add or station disable")
		}
	case "token":
		return tokenCommand(args[1:])
	case "audit":
		if len(args) < 2 || args[1] != "verify" {
			return errors.New("expected audit verify")
		}
		return auditVerify(args[2:])
	case "keygen":
		return keygen(args[1:])
	case "escrow":
		if len(args) < 2 || args[1] != "keygen" {
			return errors.New("expected escrow keygen")
		}
		return escrowKeygen(args[2:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func serve(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := flags.String("config", "", "backend TOML config")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, store, err := loadConfigAndStore(context.Background(), *configPath)
	if err != nil {
		return err
	}
	defer store.Close()
	authenticator, err := authn.New(context.Background(), authn.Config{
		Issuer: cfg.OIDC.Issuer, CAFile: cfg.OIDC.CAFile,
		Audience: cfg.OIDC.Audience, GroupsClaim: cfg.OIDC.GroupsClaim,
	}, store)
	if err != nil {
		return err
	}
	signer, err := signing.NewFileSigner(cfg.Grants.KeyID, cfg.Grants.SigningKeyFile)
	if err != nil {
		return err
	}
	service := gateway.New(store, authenticator, signer, *cfg, slog.Default())
	cas, err := buildCertificateAuthorities(cfg.CA)
	if err != nil {
		return err
	}
	service.ConfigureIssuance(cas)
	defer service.Close()
	server, err := gateway.NewGRPCServer(cfg.TLS, service)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	slog.Info("starting backend gRPC gateway", "listen_grpc", cfg.ListenGRPC)
	return gateway.ListenAndServe(ctx, cfg.ListenGRPC, server)
}

func migrate(args []string) error {
	flags := flag.NewFlagSet("migrate", flag.ContinueOnError)
	configPath := flags.String("config", "", "backend TOML config")
	if err := flags.Parse(args); err != nil {
		return err
	}
	_, store, err := loadConfigAndStore(context.Background(), *configPath)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.Migrate(context.Background()); err != nil {
		return err
	}
	slog.Info("database migrations are current")
	return nil
}

func stationAdd(args []string) error {
	flags := flag.NewFlagSet("station add", flag.ContinueOnError)
	configPath := flags.String("config", "", "backend TOML config")
	id := flags.String("id", "", "station ID")
	dns := flags.String("dns", "", "station DNS name")
	name := flags.String("name", "", "station display name")
	mode := flags.String("mode", "", "station or user")
	if err := flags.Parse(args); err != nil {
		return err
	}
	dnsName, err := normalizeDNSName(*dns)
	if err != nil {
		return err
	}
	if *id == "" || (*mode != "station" && *mode != "user") {
		return errors.New("station add requires --id, --dns, and --mode station|user")
	}
	displayName := *name
	if displayName == "" {
		displayName = *id
	}
	_, store, err := loadConfigAndStore(context.Background(), *configPath)
	if err != nil {
		return err
	}
	defer store.Close()
	ctx := context.Background()
	tx, err := store.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin station registration: %w", err)
	}
	if err := store.AddStation(ctx, tx, db.Station{
		ID: *id, DNSName: dnsName, DisplayName: displayName, Mode: *mode,
	}); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if _, err := audit.Append(ctx, tx, audit.Event{
		ActorType:  "system",
		ActorID:    "sigil-server-cli",
		Action:     "StationAdd",
		TargetType: "station",
		TargetID:   *id,
		Outcome:    "success",
		Detail: map[string]any{
			"dns_name":     dnsName,
			"display_name": displayName,
			"mode":         *mode,
		},
	}); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit station registration: %w", err)
	}
	slog.Info("station registered", "station_id", *id, "dns_name", dnsName)
	return nil
}

func stationDisable(args []string) error {
	flags := flag.NewFlagSet("station disable", flag.ContinueOnError)
	configPath := flags.String("config", "", "backend TOML config")
	id := flags.String("id", "", "station ID")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return errors.New("station disable requires --id")
	}
	_, store, err := loadConfigAndStore(context.Background(), *configPath)
	if err != nil {
		return err
	}
	defer store.Close()
	ctx := context.Background()
	tx, err := store.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin station disable: %w", err)
	}
	if err := store.DisableStation(ctx, tx, *id); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if _, err := audit.Append(ctx, tx, audit.Event{
		ActorType:  "system",
		ActorID:    "sigil-server-cli",
		Action:     "StationDisable",
		TargetType: "station",
		TargetID:   *id,
		Outcome:    "success",
		Detail:     map[string]any{"reason": "disabled by operator"},
	}); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit station disable: %w", err)
	}
	slog.Info("station disabled", "station_id", *id)
	return nil
}

func auditVerify(args []string) error {
	flags := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	configPath := flags.String("config", "", "backend TOML config")
	if err := flags.Parse(args); err != nil {
		return err
	}
	_, store, err := loadConfigAndStore(context.Background(), *configPath)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := audit.Verify(context.Background(), store.Pool); err != nil {
		return err
	}
	fmt.Println("audit chain verified")
	return nil
}

func keygen(args []string) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	privatePath := flags.String("out", "", "private PKCS#8 PEM output")
	publicPath := flags.String("public-out", "", "public SPKI PEM output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *privatePath == "" || *publicPath == "" {
		return errors.New("keygen requires --out and --public-out")
	}
	if err := signing.WriteNewKeyPair(*privatePath, *publicPath); err != nil {
		return err
	}
	fmt.Println(filepath.Clean(*publicPath))
	return nil
}

func escrowKeygen(args []string) error {
	flags := flag.NewFlagSet("escrow keygen", flag.ContinueOnError)
	outputPath := flags.String("out", "", "base64-encoded escrow KEK output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *outputPath == "" {
		return errors.New("escrow keygen requires --out")
	}
	if err := escrow.WriteNewKEK(*outputPath); err != nil {
		return err
	}
	fmt.Println(filepath.Clean(*outputPath))
	return nil
}

func loadConfigAndStore(ctx context.Context, path string) (*config.Config, *db.Store, error) {
	if path == "" {
		return nil, nil, errors.New("--config is required")
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, nil, err
	}
	store, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, nil, err
	}
	return cfg, store, nil
}

func normalizeDNSName(value string) (string, error) {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if name == "" || len(name) > 253 || net.ParseIP(name) != nil {
		return "", errors.New("station add requires a valid DNS name in --dns")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("station add requires a valid DNS name in --dns")
		}
		for _, character := range label {
			if !((character >= 'a' && character <= 'z') ||
				(character >= '0' && character <= '9') || character == '-') {
				return "", errors.New("station add requires a valid DNS name in --dns")
			}
		}
	}
	return name, nil
}

func buildCertificateAuthorities(configs map[string]config.CA) (map[string]ca.CA, error) {
	cas := make(map[string]ca.CA, len(configs))
	for name, settings := range configs {
		root, err := os.ReadFile(settings.RootFile)
		if err != nil {
			return nil, fmt.Errorf("read CA %q root file: %w", name, err)
		}
		encrypted, err := os.ReadFile(settings.ProvisionerKeyFile)
		if err != nil {
			return nil, fmt.Errorf("read CA %q provisioner key: %w", name, err)
		}
		password, err := os.ReadFile(settings.ProvisionerPasswordFile)
		if err != nil {
			return nil, fmt.Errorf("read CA %q provisioner password: %w", name, err)
		}
		key, err := ca.LoadProvisionerKey(encrypted, bytes.TrimSpace(password))
		if err != nil {
			return nil, fmt.Errorf("load CA %q provisioner key: %w", name, err)
		}
		client, err := ca.NewStep(ca.StepConfig{URL: settings.URL, RootPEM: root, Provisioner: settings.Provisioner, Key: key})
		if err != nil {
			return nil, fmt.Errorf("configure CA %q: %w", name, err)
		}
		cas[name] = client
	}
	return cas, nil
}

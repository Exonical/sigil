package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/Exonical/sigil/backend/internal/audit"
	"github.com/Exonical/sigil/backend/internal/authn"
	"github.com/Exonical/sigil/backend/internal/config"
	"github.com/Exonical/sigil/backend/internal/db"
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
		return errors.New("expected serve, migrate, station, audit, or keygen")
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
	case "audit":
		if len(args) < 2 || args[1] != "verify" {
			return errors.New("expected audit verify")
		}
		return auditVerify(args[2:])
	case "keygen":
		return keygen(args[1:])
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
		Issuer: cfg.OIDC.Issuer, Audience: cfg.OIDC.Audience, GroupsClaim: cfg.OIDC.GroupsClaim,
	}, store)
	if err != nil {
		return err
	}
	signer, err := signing.NewFileSigner(cfg.Grants.KeyID, cfg.Grants.SigningKeyFile)
	if err != nil {
		return err
	}
	service := gateway.New(store, authenticator, signer, *cfg, slog.Default())
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
	name := flags.String("name", "", "station display name")
	mode := flags.String("mode", "", "station or user")
	certificatePath := flags.String("cert", "", "station client certificate PEM")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *id == "" || *name == "" || *certificatePath == "" || (*mode != "station" && *mode != "user") {
		return errors.New("station add requires --id, --name, --cert, and --mode station|user")
	}
	_, store, err := loadConfigAndStore(context.Background(), *configPath)
	if err != nil {
		return err
	}
	defer store.Close()
	certificate, err := readCertificate(*certificatePath)
	if err != nil {
		return err
	}
	spki, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return errors.New("station certificate public key is unsupported")
	}
	hash := sha256.Sum256(spki)
	ctx := context.Background()
	tx, err := store.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin station registration: %w", err)
	}
	if err := store.AddStation(ctx, tx, db.Station{ID: *id, DisplayName: *name, Mode: *mode}, hash[:]); err != nil {
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
			"display_name": *name,
			"mode":         *mode,
		},
	}); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit station registration: %w", err)
	}
	slog.Info("station registered", "station_id", *id)
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

func readCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read station certificate: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("station certificate must be PEM encoded")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("station certificate is invalid")
	}
	return certificate, nil
}

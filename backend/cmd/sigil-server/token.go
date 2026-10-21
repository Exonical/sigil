package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"

	"github.com/Exonical/sigil/backend/internal/audit"
)

func tokenCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("expected token assign or token unassign")
	}
	switch args[0] {
	case "assign":
		return tokenAssign(args[1:])
	case "unassign":
		return tokenUnassign(args[1:])
	default:
		return errors.New("expected token assign or token unassign")
	}
}

func tokenAssign(args []string) error {
	flags := flag.NewFlagSet("token assign", flag.ContinueOnError)
	configPath := flags.String("config", "", "backend TOML config")
	vendor := flags.String("vendor", "Yubico", "token vendor")
	serial := flags.String("serial", "", "token serial number")
	user := flags.String("user", "", "assigned user's username or email")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *serial == "" || *user == "" {
		return errors.New("token assign requires --serial and --user")
	}
	_, store, err := loadConfigAndStore(context.Background(), *configPath)
	if err != nil {
		return err
	}
	defer store.Close()
	ctx := context.Background()
	tx, err := store.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin token assign: %w", err)
	}
	userID, err := store.FindUserByName(ctx, tx, *user)
	if err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	tokenID, err := store.AssignToken(ctx, tx, *vendor, *serial, userID)
	if err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if _, err := audit.Append(ctx, tx, audit.Event{
		ActorType:  "system",
		ActorID:    "sigil-server-cli",
		Action:     "TokenAssign",
		TargetType: "token",
		TargetID:   tokenID,
		Outcome:    "success",
		Detail:     map[string]any{"vendor": *vendor, "serial": *serial, "user": *user, "user_id": userID},
	}); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit token assign: %w", err)
	}
	slog.Info("token assigned", "serial", *serial, "user", *user)
	return nil
}

func tokenUnassign(args []string) error {
	flags := flag.NewFlagSet("token unassign", flag.ContinueOnError)
	configPath := flags.String("config", "", "backend TOML config")
	vendor := flags.String("vendor", "Yubico", "token vendor")
	serial := flags.String("serial", "", "token serial number")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *serial == "" {
		return errors.New("token unassign requires --serial")
	}
	_, store, err := loadConfigAndStore(context.Background(), *configPath)
	if err != nil {
		return err
	}
	defer store.Close()
	ctx := context.Background()
	tx, err := store.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin token unassign: %w", err)
	}
	tokenID, err := store.UnassignToken(ctx, tx, *vendor, *serial)
	if err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if _, err := audit.Append(ctx, tx, audit.Event{
		ActorType:  "system",
		ActorID:    "sigil-server-cli",
		Action:     "TokenUnassign",
		TargetType: "token",
		TargetID:   tokenID,
		Outcome:    "success",
		Detail:     map[string]any{"vendor": *vendor, "serial": *serial},
	}); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit token unassign: %w", err)
	}
	slog.Info("token unassigned", "serial", *serial)
	return nil
}

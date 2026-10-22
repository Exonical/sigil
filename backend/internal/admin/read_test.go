package admin

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"connectrpc.com/connect"
)

func TestInternalLogsTheCauseButReturnsOnlyTheGenericMessage(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	ctx := context.WithValue(context.Background(), principalKey{}, principal{userID: "operator-1"})
	err := internal(ctx, "could not record the change", errors.New("duplicate key value violates unique constraint"))

	var connectErr *connect.Error
	if !errors.As(err, &connectErr) || connectErr.Code() != connect.CodeInternal {
		t.Fatalf("want a CodeInternal connect error, got %v", err)
	}
	if connectErr.Message() != "could not record the change" {
		t.Fatalf("the client message must stay generic, got %q", connectErr.Message())
	}
	logged := logs.String()
	for _, want := range []string{`"level":"ERROR"`, `"msg":"could not record the change"`, `"actor":"operator-1"`, `"error":"duplicate key value violates unique constraint"`} {
		if !strings.Contains(logged, want) {
			t.Fatalf("log line %q is missing %s", logged, want)
		}
	}
}

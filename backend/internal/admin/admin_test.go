package admin

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	adminv1 "github.com/Exonical/sigil/backend/gen/sigil/admin/v1"
	"github.com/Exonical/sigil/backend/gen/sigil/admin/v1/adminv1connect"
	"github.com/Exonical/sigil/backend/internal/authn"
	"github.com/Exonical/sigil/backend/internal/config"
	"github.com/Exonical/sigil/backend/internal/db"
	"github.com/Exonical/sigil/backend/internal/testdb"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// fakeAuthenticator maps fixed bearer tokens to fixed group memberships. OIDC itself is covered elsewhere.
type fakeAuthenticator struct{}

func (fakeAuthenticator) Authenticate(_ context.Context, token string) (authn.Principal, error) {
	switch token {
	case "admin-token":
		return authn.Principal{UserID: "admin-user", Groups: []string{"sigil-admins"}}, nil
	case "helpdesk-token":
		return authn.Principal{UserID: "helpdesk-user", Groups: []string{"sigil-helpdesk"}}, nil
	case "user-token":
		return authn.Principal{UserID: "plain-user", Groups: []string{"everyone"}}, nil
	default:
		return authn.Principal{}, errors.New("token rejected")
	}
}

type adminFixture struct {
	ctx    context.Context
	store  *db.Store
	client adminv1connect.AdminServiceClient
	server *httptest.Server
	userID string
}

func newAdminFixture(t *testing.T) adminFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	store, cleanup, err := testdb.Open(ctx)
	if err != nil {
		if errors.Is(err, testdb.ErrNotConfigured) {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	service := NewService(store, fakeAuthenticator{}, config.RoleGroups{
		Admin:    []string{"sigil-admins"},
		Helpdesk: []string{"sigil-helpdesk"},
	})
	path, handler := service.Handler()
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	spki := sha256.Sum256([]byte("admin-station"))
	if _, err := store.Pool.Exec(ctx, `
		INSERT INTO stations(id, display_name, mode, cert_spki_sha256, status, dns_name)
		VALUES('station-admin-test', 'Admin test station', 'station', $1, 'active', 'station-admin-test.example.test')
	`, spki[:]); err != nil {
		t.Fatal(err)
	}
	userID, err := store.UpsertUser(ctx, "https://idp.example/", "subject-alice", "alice", "alice@example.test", "Alice Example")
	if err != nil {
		t.Fatal(err)
	}
	return adminFixture{
		ctx:    ctx,
		store:  store,
		server: server,
		userID: userID,
		client: adminv1connect.NewAdminServiceClient(server.Client(), server.URL),
	}
}

// call attaches a bearer token when non-empty. Tokens are fixed strings in the fake authenticator.
func call[Req, Res any](f adminFixture, token string, rpc func(adminv1connect.AdminServiceClient, context.Context, *connect.Request[Req]) (*connect.Response[Res], error), msg *Req) (*connect.Response[Res], error) {
	request := connect.NewRequest(msg)
	if token != "" {
		request.Header().Set("Authorization", "Bearer "+token)
	}
	return rpc(f.client, f.ctx, request)
}

func codeOf(err error) connect.Code {
	return connect.CodeOf(err)
}

func (f adminFixture) seedToken(t *testing.T, serial, status string, assignedUser *string) string {
	t.Helper()
	var tokenID string
	if err := f.store.Pool.QueryRow(f.ctx, `
		INSERT INTO tokens(vendor, model, serial, status, assigned_user_id, last_station_id, nickname)
		VALUES('Yubico', 'YubiKey 5 FIPS', $1, $2, $3::uuid, 'station-admin-test', $1 || ' desk')
		RETURNING id::text
	`, serial, status, assignedUser).Scan(&tokenID); err != nil {
		t.Fatal(err)
	}
	return tokenID
}

func TestMissingAndInvalidBearerTokensAreUnauthenticated(t *testing.T) {
	f := newAdminFixture(t)
	for _, token := range []string{"", "not-a-token"} {
		_, err := call(f, token, adminv1connect.AdminServiceClient.GetDashboard, &adminv1.Empty{})
		if codeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("token %q: code = %v, want Unauthenticated", token, codeOf(err))
		}
	}
}

func TestUsersWithoutAnOperatorRoleAreDeniedEveryRPC(t *testing.T) {
	f := newAdminFixture(t)
	_, err := call(f, "user-token", adminv1connect.AdminServiceClient.GetDashboard, &adminv1.Empty{})
	if codeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("GetDashboard for a plain user: code = %v, want PermissionDenied", codeOf(err))
	}
	_, err = call(f, "user-token", adminv1connect.AdminServiceClient.DeleteKey, &adminv1.DeleteKeyRequest{
		Token: &adminv1.TokenRef{Vendor: "Yubico", Serial: "1"}, ConfirmSerial: "1",
	})
	if codeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("DeleteKey for a plain user: code = %v, want PermissionDenied before any handler runs", codeOf(err))
	}
}

func TestHelpdeskAndAdminReadTheDashboardWithCounts(t *testing.T) {
	f := newAdminFixture(t)
	f.seedToken(t, "39192733", "active", &f.userID)
	f.seedToken(t, "40000001", "unassigned", nil)
	for _, token := range []string{"helpdesk-token", "admin-token"} {
		response, err := call(f, token, adminv1connect.AdminServiceClient.GetDashboard, &adminv1.Empty{})
		if err != nil {
			t.Fatalf("%s: %v", token, err)
		}
		if response.Msg.TokensByStatus["active"] != 1 || response.Msg.TokensByStatus["unassigned"] != 1 {
			t.Fatalf("%s: tokens by status = %v", token, response.Msg.TokensByStatus)
		}
		if response.Msg.StationsByStatus["active"] != 1 {
			t.Fatalf("%s: stations by status = %v", token, response.Msg.StationsByStatus)
		}
	}
}

func TestUnimplementedRPCsReturnUnimplementedForOperators(t *testing.T) {
	f := newAdminFixture(t)
	_, err := call(f, "admin-token", adminv1connect.AdminServiceClient.DeleteKey, &adminv1.DeleteKeyRequest{
		Token: &adminv1.TokenRef{Vendor: "Yubico", Serial: "1"}, ConfirmSerial: "1",
	})
	if codeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("DeleteKey code = %v, want Unimplemented in this slice", codeOf(err))
	}
}

func TestListTokensFiltersByTextStatusAndPages(t *testing.T) {
	f := newAdminFixture(t)
	f.seedToken(t, "39192733", "active", &f.userID)
	f.seedToken(t, "40000001", "unassigned", nil)
	f.seedToken(t, "40000002", "lost", nil)

	bySerial, err := call(f, "helpdesk-token", adminv1connect.AdminServiceClient.ListTokens, &adminv1.ListTokensRequest{Search: "3919"})
	if err != nil || len(bySerial.Msg.Tokens) != 1 || bySerial.Msg.Tokens[0].Serial != "39192733" {
		t.Fatalf("search by serial = %v, %v", bySerial, err)
	}
	byUser, err := call(f, "helpdesk-token", adminv1connect.AdminServiceClient.ListTokens, &adminv1.ListTokensRequest{Search: "ALICE@example"})
	if err != nil || len(byUser.Msg.Tokens) != 1 || byUser.Msg.Tokens[0].AssignedUser.Username != "alice" {
		t.Fatalf("search by assigned user email = %v, %v", byUser, err)
	}
	literal, err := call(f, "helpdesk-token", adminv1connect.AdminServiceClient.ListTokens, &adminv1.ListTokensRequest{Search: "%"})
	if err != nil || len(literal.Msg.Tokens) != 0 {
		t.Fatalf("a percent sign must match literally, not as a wildcard: %v, %v", literal, err)
	}
	lost, err := call(f, "helpdesk-token", adminv1connect.AdminServiceClient.ListTokens, &adminv1.ListTokensRequest{Status: "lost"})
	if err != nil || len(lost.Msg.Tokens) != 1 || lost.Msg.Tokens[0].Serial != "40000002" {
		t.Fatalf("status filter = %v, %v", lost, err)
	}
	page, err := call(f, "helpdesk-token", adminv1connect.AdminServiceClient.ListTokens, &adminv1.ListTokensRequest{PageSize: 1, Page: 1})
	if err != nil || len(page.Msg.Tokens) != 1 || page.Msg.Total != 3 || page.Msg.Tokens[0].Serial != "40000001" {
		t.Fatalf("second page of one = %v, %v", page, err)
	}
}

func TestGetTokenNeverReturnsEscrowValues(t *testing.T) {
	f := newAdminFixture(t)
	tokenID := f.seedToken(t, "39192733", "active", &f.userID)

	// Known plaintext markers, stored as the escrow ciphertext, wrapped key, and nonce. The response must never
	// contain them in raw, base64, or hex form.
	markers := []string{"ESCROW-PUK-PLAINTEXT-MARKER-12345678", "ESCROW-MK-PLAINTEXT-MARKER-AES256-KEY", "ESCROW-DEK-WRAP-MARKER-0001"}
	if _, err := f.store.Pool.Exec(f.ctx, `
		INSERT INTO grants(grant_id, operation, user_id, station_id, token_serial, piv_slot, caller_os_user, not_before, expires_at, key_id)
		VALUES('grant-escrow-1', 'PIV_CHANGE_PUK', $1::uuid, 'station-admin-test', '39192733', 0, 'S-1-5-test', now(), now() + interval '1 hour', 'sigil-dev-v1')
	`, f.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Pool.Exec(f.ctx, `
		INSERT INTO escrowed_secrets(token_id, kind, algorithm, version, state, kek_id, dek_nonce, wrapped_dek, nonce, ciphertext, grant_id, station_id, activated_at)
		VALUES($1::uuid, 'puk', 'puk-utf8', 2, 'active', 'sigil-dev-v1', $2, $3, $4, $5, 'grant-escrow-1', 'station-admin-test', now())
	`, tokenID, []byte(markers[2]), []byte(markers[2]), []byte(markers[0]), []byte(markers[0])); err != nil {
		t.Fatal(err)
	}

	response, err := call(f, "helpdesk-token", adminv1connect.AdminServiceClient.GetToken, &adminv1.TokenRef{Vendor: "Yubico", Serial: "39192733"})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Msg.Escrow) != 1 || response.Msg.Escrow[0].Kind != "puk" || response.Msg.Escrow[0].State != "active" || response.Msg.Escrow[0].Version != 2 {
		t.Fatalf("escrow metadata = %v", response.Msg.Escrow)
	}
	binary, err := proto.Marshal(response.Msg)
	if err != nil {
		t.Fatal(err)
	}
	asJSON, err := protojson.Marshal(response.Msg)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range markers {
		encodings := map[string]string{
			"raw":    marker,
			"base64": base64.StdEncoding.EncodeToString([]byte(marker)),
			"hex":    hex.EncodeToString([]byte(marker)),
		}
		for name, value := range encodings {
			if strings.Contains(string(binary), value) || strings.Contains(string(asJSON), value) {
				t.Fatalf("GetToken leaked escrow material as %s", name)
			}
		}
	}
}

func TestGetTokenReturnsNotFoundForAnUnknownToken(t *testing.T) {
	f := newAdminFixture(t)
	_, err := call(f, "helpdesk-token", adminv1connect.AdminServiceClient.GetToken, &adminv1.TokenRef{Vendor: "Yubico", Serial: "missing"})
	if codeOf(err) != connect.CodeNotFound {
		t.Fatalf("code = %v, want NotFound", codeOf(err))
	}
}

func TestBearerCheckRunsBeforeTheRequestIsParsed(t *testing.T) {
	f := newAdminFixture(t)
	_, err := call(f, "", adminv1connect.AdminServiceClient.ListTokens, &adminv1.ListTokensRequest{Search: strings.Repeat("x", 10)})
	if codeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", codeOf(err))
	}
}

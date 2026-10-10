package portal

import (
	"strings"
	"testing"
)

func TestPortalConfigCarriesTheRoleGroupsForTheBrowser(t *testing.T) {
	handler, err := NewHandler(Options{
		Issuer:     "https://localhost:9443/application/o/sigil/",
		ClientID:   "sigil",
		PublicURL:  "https://localhost:8443",
		APIPrefix:  "/sigil.admin.v1.AdminService/",
		RoleGroups: map[string][]string{"admin": {"sigil-admins"}, "helpdesk": {"sigil-helpdesk"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := do(t, handler, "GET", "/portal-config.json", nil).Body.String()
	want := `"roleGroups":{"admin":["sigil-admins"],"helpdesk":["sigil-helpdesk"]}`
	if !strings.Contains(body, want) {
		t.Fatalf("portal-config = %s, missing %s", body, want)
	}
}

package portal

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestHandler(t *testing.T, api http.Handler) http.Handler {
	t.Helper()
	handler, err := NewHandler(Options{
		Issuer:     "https://localhost:9443/application/o/sigil/",
		ClientID:   "sigil",
		PublicURL:  "https://localhost:8443",
		DevOrigins: []string{"http://localhost:5173"},
		APIPrefix:  "/sigil.admin.v1.AdminService/",
		API:        api,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func do(t *testing.T, handler http.Handler, method, target string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, nil)
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestEveryResponseCarriesTheSecurityHeaders(t *testing.T) {
	handler := newTestHandler(t, nil)
	for _, target := range []string{"/", "/tokens/39192733", "/portal-config.json", "/index.html"} {
		response := do(t, handler, http.MethodGet, target, nil)
		headers := response.Header()
		csp := headers.Get("Content-Security-Policy")
		for _, want := range []string{
			"default-src 'self'",
			"frame-ancestors 'none'",
			"connect-src 'self' https://localhost:9443",
			"object-src 'none'",
		} {
			if !strings.Contains(csp, want) {
				t.Fatalf("%s CSP = %q, missing %q", target, csp, want)
			}
		}
		if strings.Contains(csp, "unsafe-inline") && !strings.Contains(csp, "style-src 'self' 'unsafe-inline'") {
			t.Fatalf("%s allows inline scripts: %q", target, csp)
		}
		if got := headers.Get("Strict-Transport-Security"); !strings.HasPrefix(got, "max-age=") {
			t.Fatalf("%s HSTS = %q", target, got)
		}
		if headers.Get("X-Frame-Options") != "DENY" || headers.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s missing framing or sniffing headers: %v", target, headers)
		}
	}
}

func TestUnknownClientRoutesFallBackToTheAppShell(t *testing.T) {
	handler := newTestHandler(t, nil)
	response := do(t, handler, http.MethodGet, "/tokens/39192733/certificates", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want the app shell", response.Code)
	}
	body, _ := io.ReadAll(response.Body)
	if !strings.Contains(string(body), "<title>Sigil admin portal</title>") {
		t.Fatalf("fallback did not serve index.html: %q", body)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("the app shell must not be cached")
	}
}

func TestApiAndConnectPathsNeverFallBackToTheAppShell(t *testing.T) {
	handler := newTestHandler(t, nil)
	for _, target := range []string{"/api/v1/tokens", "/sigil.admin.v1.AdminService/Unknown", "/sigil.other.Service/Call"} {
		response := do(t, handler, http.MethodPost, target, nil)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404 with no fallback", target, response.Code)
		}
		if strings.Contains(response.Body.String(), "<html") {
			t.Fatalf("%s returned the app shell", target)
		}
	}
}

func TestAPIPrefixIsRoutedToTheConnectHandler(t *testing.T) {
	var reached bool
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusTeapot)
	})
	handler := newTestHandler(t, api)
	response := do(t, handler, http.MethodPost, "/sigil.admin.v1.AdminService/GetDashboard", nil)
	if !reached || response.Code != http.StatusTeapot {
		t.Fatalf("API route not served by the Connect handler: reached=%v status=%d", reached, response.Code)
	}
}

func TestPortalConfigComesFromTheBackendSettings(t *testing.T) {
	handler := newTestHandler(t, nil)
	response := do(t, handler, http.MethodGet, "/portal-config.json", nil)
	body := response.Body.String()
	for _, want := range []string{
		`"issuer":"https://localhost:9443/application/o/sigil/"`,
		`"clientId":"sigil"`,
		`"apiBase":"https://localhost:8443"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("portal-config = %s, missing %s", body, want)
		}
	}
	if response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("content type = %q", response.Header().Get("Content-Type"))
	}
}

func TestDevOriginsGetCORSAndOthersDoNot(t *testing.T) {
	handler := newTestHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	allowed := do(t, handler, http.MethodOptions, "/sigil.admin.v1.AdminService/ListTokens", map[string]string{"Origin": "http://localhost:5173"})
	if allowed.Code != http.StatusNoContent || allowed.Header().Get("Access-Control-Allow-Origin") != "http://localhost:5173" {
		t.Fatalf("preflight from the dev origin: status=%d headers=%v", allowed.Code, allowed.Header())
	}
	other := do(t, handler, http.MethodOptions, "/sigil.admin.v1.AdminService/ListTokens", map[string]string{"Origin": "https://evil.example"})
	if other.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("an unlisted origin must not receive CORS headers")
	}
}

func TestMethodsOtherThanGetOrHeadAreRejectedForTheShell(t *testing.T) {
	handler := newTestHandler(t, nil)
	response := do(t, handler, http.MethodPost, "/tokens", nil)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST to the app shell = %d", response.Code)
	}
}

// Package portal serves the admin web portal: the built single-page app, its browser configuration, and the
// security headers every response carries. The built assets are embedded from dist; the committed placeholder
// index.html is replaced by the web build.
package portal

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strings"
)

//go:embed dist
var distFiles embed.FS

// Options configure the portal handler.
type Options struct {
	// Issuer is the OIDC issuer URL. The browser signs in against it and it is allowed as a connect-src origin.
	Issuer string
	// ClientID is the OIDC public client the browser uses.
	ClientID string
	// PublicURL is the portal origin the browser calls for the API.
	PublicURL string
	// DevOrigins are Vite dev-server origins that may call the API with CORS. Empty in production.
	DevOrigins []string
	// APIPrefix is the URL prefix of the Connect service, for example /sigil.admin.v1.AdminService/.
	APIPrefix string
	// API serves Connect requests under APIPrefix.
	API http.Handler
}

// NewHandler returns the portal HTTP handler.
func NewHandler(options Options) (http.Handler, error) {
	assets, err := fs.Sub(distFiles, "dist")
	if err != nil {
		return nil, err
	}
	issuerOrigin, err := origin(options.Issuer)
	if err != nil {
		return nil, err
	}
	allowedDev := make(map[string]bool, len(options.DevOrigins))
	for _, value := range options.DevOrigins {
		allowedDev[value] = true
	}
	config := map[string]string{
		"issuer":   options.Issuer,
		"clientId": options.ClientID,
		"apiBase":  options.PublicURL,
	}
	configJSON, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	csp := strings.Join([]string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data:",
		"connect-src 'self' " + issuerOrigin,
		"frame-ancestors 'none'",
		"base-uri 'self'",
		"form-action 'self' " + issuerOrigin,
		"object-src 'none'",
	}, "; ")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w, csp)
		if strings.HasPrefix(r.URL.Path, options.APIPrefix) {
			applyDevCORS(w, r, allowedDev)
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if options.API == nil {
				http.NotFound(w, r)
				return
			}
			options.API.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/portal-config.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write(configJSON)
			return
		}
		if isAPIPath(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		serveAsset(w, r, assets)
	}), nil
}

// isAPIPath reports paths that belong to the API or to Connect. They never fall back to the single-page app.
func isAPIPath(p string) bool {
	return strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/sigil.")
}

func serveAsset(w http.ResponseWriter, r *http.Request, assets fs.FS) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" {
		name = "index.html"
	}
	if info, err := fs.Stat(assets, name); err == nil && !info.IsDir() {
		http.ServeFileFS(w, r, assets, name)
		return
	}
	// Client-side routes fall back to the app shell. The shell itself is never cached.
	w.Header().Set("Cache-Control", "no-store")
	http.ServeFileFS(w, r, assets, "index.html")
}

func setSecurityHeaders(w http.ResponseWriter, csp string) {
	headers := w.Header()
	headers.Set("Content-Security-Policy", csp)
	headers.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	headers.Set("X-Content-Type-Options", "nosniff")
	headers.Set("X-Frame-Options", "DENY")
	headers.Set("Referrer-Policy", "no-referrer")
}

func applyDevCORS(w http.ResponseWriter, r *http.Request, allowed map[string]bool) {
	origin := r.Header.Get("Origin")
	if origin == "" || !allowed[origin] {
		return
	}
	headers := w.Header()
	headers.Set("Access-Control-Allow-Origin", origin)
	headers.Set("Vary", "Origin")
	headers.Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	headers.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Connect-Protocol-Version, Connect-Timeout-Ms")
	headers.Set("Access-Control-Max-Age", "600")
}

// origin returns scheme://host for an absolute URL.
func origin(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

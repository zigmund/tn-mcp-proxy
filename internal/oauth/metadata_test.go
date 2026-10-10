package oauth

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
)

func newMux(t *testing.T, publicURL string, ups ...config.Upstream) *http.ServeMux {
	t.Helper()
	cfg := &config.Config{PublicURL: publicURL, Upstreams: ups}
	mux := http.NewServeMux()
	New(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil))).Register(mux)
	return mux
}

func do(mux *http.ServeMux, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return v
}

var (
	upTN    = config.Upstream{Name: "tn", Title: "Tradernet", Path: "/tn/mcp"}
	upOther = config.Upstream{Name: "other", Title: "Other", Path: "/other/mcp"}
)

func TestAuthServerMetadata(t *testing.T) {
	for _, base := range []string{"https://mcp.example.com", "http://localhost:8787"} {
		mux := newMux(t, base, upTN)
		want := AuthServerMetadata{
			Issuer:                            base,
			AuthorizationEndpoint:             base + "/oauth/authorize",
			TokenEndpoint:                     base + "/oauth/token",
			RegistrationEndpoint:              base + "/oauth/register",
			ResponseTypesSupported:            []string{"code"},
			ResponseModesSupported:            []string{"query"},
			GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
			CodeChallengeMethodsSupported:     []string{"S256"},
			TokenEndpointAuthMethodsSupported: []string{"none", "client_secret_post", "client_secret_basic"},
		}
		for _, p := range []string{PathAuthServerMetadata, PathOIDCMetadata} {
			rec := do(mux, http.MethodGet, p)
			if rec.Code != 200 {
				t.Fatalf("%s: status %d", p, rec.Code)
			}
			if got := decode[AuthServerMetadata](t, rec); !reflect.DeepEqual(got, want) {
				t.Errorf("%s: got %+v want %+v", p, got, want)
			}
			if strings.Contains(rec.Body.String(), "scopes_supported") {
				t.Errorf("%s: scopes_supported must be omitted", p)
			}
		}
	}
}

func TestProtectedResourceMetadata(t *testing.T) {
	base := "https://mcp.example.com"
	mux := newMux(t, base, upTN, upOther)
	for _, u := range []config.Upstream{upTN, upOther} {
		rec := do(mux, http.MethodGet, PathResourceMetadataPrefix+u.Path)
		if rec.Code != 200 {
			t.Fatalf("%s: status %d", u.Path, rec.Code)
		}
		want := ProtectedResourceMetadata{
			Resource:               base + u.Path,
			AuthorizationServers:   []string{base},
			BearerMethodsSupported: []string{"header"},
			ResourceName:           u.Title,
		}
		if got := decode[ProtectedResourceMetadata](t, rec); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %+v want %+v", u.Path, got, want)
		}
	}
}

func TestResourceMetadataRootFallback(t *testing.T) {
	one := newMux(t, "https://mcp.example.com", upTN)
	rec := do(one, http.MethodGet, PathResourceMetadataPrefix)
	if rec.Code != 200 {
		t.Fatalf("single upstream root: status %d", rec.Code)
	}
	if got := decode[ProtectedResourceMetadata](t, rec); got.Resource != "https://mcp.example.com/tn/mcp" {
		t.Errorf("resource = %q", got.Resource)
	}

	two := newMux(t, "https://mcp.example.com", upTN, upOther)
	if rec := do(two, http.MethodGet, PathResourceMetadataPrefix); rec.Code != 404 {
		t.Errorf("two upstreams root: status %d, want 404", rec.Code)
	}
}

func TestHeaders(t *testing.T) {
	mux := newMux(t, "https://mcp.example.com", upTN)
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		rec := do(mux, m, PathAuthServerMetadata)
		if rec.Code != 200 {
			t.Fatalf("%s: status %d", m, rec.Code)
		}
		for k, v := range map[string]string{
			"Content-Type":                "application/json",
			"Cache-Control":               "public, max-age=300",
			"Access-Control-Allow-Origin": "*",
		} {
			if got := rec.Header().Get(k); got != v {
				t.Errorf("%s %s = %q, want %q", m, k, got, v)
			}
		}
		if m == http.MethodHead && rec.Body.Len() != 0 {
			t.Error("HEAD returned a body")
		}
	}
}

func TestNotFoundAndMethodNotAllowed(t *testing.T) {
	mux := newMux(t, "https://mcp.example.com", upTN)
	for _, p := range []string{PathResourceMetadataPrefix + "/unknown/mcp", PathResourceMetadataPrefix + "/tn", PathResourceMetadataPrefix + "/tn/mcp/extra"} {
		if rec := do(mux, http.MethodGet, p); rec.Code != 404 {
			t.Errorf("GET %s: status %d, want 404", p, rec.Code)
		}
	}
	for _, p := range []string{PathAuthServerMetadata, PathOIDCMetadata, PathResourceMetadataPrefix + "/tn/mcp", PathResourceMetadataPrefix} {
		rec := do(mux, http.MethodPost, p)
		if rec.Code != 405 {
			t.Errorf("POST %s: status %d, want 405", p, rec.Code)
		}
		if a := rec.Header().Get("Allow"); !strings.Contains(a, "GET") {
			t.Errorf("POST %s: Allow = %q", p, a)
		}
	}
}

func TestRFCKeyNames(t *testing.T) {
	mux := newMux(t, "https://mcp.example.com", upTN)
	as := decode[map[string]any](t, do(mux, http.MethodGet, PathAuthServerMetadata))
	for _, k := range []string{"issuer", "authorization_endpoint", "token_endpoint", "registration_endpoint",
		"response_types_supported", "response_modes_supported", "grant_types_supported",
		"code_challenge_methods_supported", "token_endpoint_auth_methods_supported"} {
		if _, ok := as[k]; !ok {
			t.Errorf("AS metadata lacks %q", k)
		}
	}
	if _, ok := as["scopes_supported"]; ok {
		t.Error("scopes_supported must be absent")
	}
	prm := decode[map[string]any](t, do(mux, http.MethodGet, PathResourceMetadataPrefix+"/tn/mcp"))
	for _, k := range []string{"resource", "authorization_servers", "bearer_methods_supported", "resource_name"} {
		if _, ok := prm[k]; !ok {
			t.Errorf("PRM lacks %q", k)
		}
	}
}

func TestPreflight(t *testing.T) {
	mux := newMux(t, "https://mcp.example.com", upTN)
	for _, p := range []string{PathAuthServerMetadata, PathOIDCMetadata, PathResourceMetadataPrefix + "/tn/mcp", PathResourceMetadataPrefix} {
		rec := do(mux, http.MethodOptions, p)
		if rec.Code != http.StatusNoContent {
			t.Errorf("OPTIONS %s: status %d", p, rec.Code)
		}
		h := rec.Header()
		if h.Get("Access-Control-Allow-Origin") != "*" ||
			h.Get("Access-Control-Allow-Methods") != "GET, HEAD, OPTIONS" ||
			!strings.Contains(h.Get("Access-Control-Allow-Headers"), "MCP-Protocol-Version") {
			t.Errorf("OPTIONS %s: bad CORS headers %v", p, h)
		}
	}
}

func TestZeroUpstreamsAndNilLogger(t *testing.T) {
	cfg := &config.Config{PublicURL: "https://mcp.example.com"}
	mux := http.NewServeMux()
	New(cfg, nil, nil).Register(mux) // nil logger must not panic
	for _, p := range []string{PathAuthServerMetadata, PathOIDCMetadata} {
		if rec := do(mux, http.MethodGet, p); rec.Code != 200 {
			t.Errorf("%s: status %d", p, rec.Code)
		}
	}
	if rec := do(mux, http.MethodGet, PathResourceMetadataPrefix); rec.Code != 404 {
		t.Errorf("root PRM with no upstreams: status %d, want 404", rec.Code)
	}
}

func TestHeadContentLength(t *testing.T) {
	mux := newMux(t, "https://mcp.example.com", upTN)
	for _, p := range []string{PathAuthServerMetadata, PathResourceMetadataPrefix + "/tn/mcp"} {
		get, head := do(mux, http.MethodGet, p), do(mux, http.MethodHead, p)
		if g, h := get.Header().Get("Content-Length"), head.Header().Get("Content-Length"); g == "" || g != h {
			t.Errorf("%s: GET Content-Length %q, HEAD %q", p, g, h)
		}
	}
}

func TestOtherMethodsNotAllowed(t *testing.T) {
	mux := newMux(t, "https://mcp.example.com", upTN)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if rec := do(mux, m, PathAuthServerMetadata); rec.Code != 405 {
			t.Errorf("%s: status %d, want 405", m, rec.Code)
		}
	}
}

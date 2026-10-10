package oauth

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zigmund/tn-mcp-proxy/internal/seal"
)

const (
	maxRegisterBody  = 64 << 10
	maxRedirectURIs  = 10
	maxClientNameLen = 100 // runes
)

var (
	supportedAuthMethods = []string{authNone, authClientSecretPost, authClientSecretBasic}
	supportedGrantTypes  = []string{"authorization_code", "refresh_token"}
	supportedRespTypes   = []string{"code"}
)

// registerRequest is the subset of RFC 7591 client metadata we honour; unknown
// fields (including scope) are ignored.
type registerRequest struct {
	RedirectURIs  []string `json:"redirect_uris"`
	AuthMethod    *string  `json:"token_endpoint_auth_method"`
	GrantTypes    []string `json:"grant_types"`
	ResponseTypes []string `json:"response_types"`
	ClientName    string   `json:"client_name"`
}

type registerResponse struct {
	ClientID              string   `json:"client_id"`
	ClientSecret          string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt      int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt *int64   `json:"client_secret_expires_at,omitempty"`
	RedirectURIs          []string `json:"redirect_uris"`
	AuthMethod            string   `json:"token_endpoint_auth_method"`
	GrantTypes            []string `json:"grant_types"`
	ResponseTypes         []string `json:"response_types"`
	ClientName            string   `json:"client_name,omitempty"`
}

type oauthError struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeRegisterError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, oauthError{Error: code, Description: desc})
}

// handleRegister implements stateless RFC 7591 dynamic client registration:
// the client_id is a sealed client record and the secret is derived from it.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	// Registration is credential-free, so open CORS is safe here; it is set
	// per handler (not in writeJSON) so the token endpoint does not inherit it.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if s.sealer == nil {
		s.log.Error("registration requested without a sealer")
		writeRegisterError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		writeRegisterError(w, http.StatusUnsupportedMediaType, "invalid_client_metadata", "Content-Type must be application/json")
		return
	}
	var req registerRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRegisterBody))
	if err := dec.Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeRegisterError(w, http.StatusBadRequest, "invalid_client_metadata", "request body too large")
		} else {
			writeRegisterError(w, http.StatusBadRequest, "invalid_client_metadata", "malformed JSON body")
		}
		return
	}
	// Reject trailing data: a second Decode must hit a clean EOF.
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeRegisterError(w, http.StatusBadRequest, "invalid_client_metadata", "malformed JSON body")
		return
	}

	if n := len(req.RedirectURIs); n < 1 || n > maxRedirectURIs {
		writeRegisterError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris must contain 1 to 10 entries")
		return
	}
	for _, u := range req.RedirectURIs {
		if !slices.Contains(s.cfg.OAuth.AllowedRedirectURIs, u) {
			writeRegisterError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect URI is not allowed")
			return
		}
	}
	method := authClientSecretBasic // RFC 7591 default
	if req.AuthMethod != nil {
		method = *req.AuthMethod
		if !slices.Contains(supportedAuthMethods, method) {
			writeRegisterError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported token_endpoint_auth_method")
			return
		}
	}
	// Unlike the RFC default (authorization_code only) we default to both
	// grants, since refresh is supported.
	grants, ok := subsetOf(req.GrantTypes, supportedGrantTypes)
	if !ok {
		writeRegisterError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported grant_types")
		return
	}
	resps, ok := subsetOf(req.ResponseTypes, supportedRespTypes)
	if !ok {
		writeRegisterError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported response_types")
		return
	}

	if slices.Contains(resps, "code") && !slices.Contains(grants, "authorization_code") {
		writeRegisterError(w, http.StatusBadRequest, "invalid_client_metadata", "response_types code requires grant_types authorization_code")
		return
	}

	uris := dedupe(req.RedirectURIs)
	rec := client{
		RedirectURIs: uris,
		Name:         sanitizeClientName(req.ClientName),
		AuthMethod:   method,
		IssuedAt:     s.now().Unix(),
	}
	id, err := s.sealer.Seal(seal.KindClient, rec, time.Time{})
	if err != nil {
		s.log.Error("sealing client id", "err", err)
		writeRegisterError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	resp := registerResponse{
		ClientID:         id,
		ClientIDIssuedAt: rec.IssuedAt,
		RedirectURIs:     uris,
		AuthMethod:       method,
		GrantTypes:       grants,
		ResponseTypes:    resps,
		ClientName:       rec.Name,
	}
	if method != authNone {
		resp.ClientSecret = s.clientSecret(id)
		resp.ClientSecretExpiresAt = new(int64) // 0: never expires
	}
	s.log.Debug("client registered", "auth_method", method, "client_name", rec.Name)
	writeJSON(w, http.StatusCreated, resp)
}

// subsetOf returns the deduplicated got (or a copy of all when got is empty)
// and whether every element of got is in all.
func subsetOf(got, all []string) ([]string, bool) {
	if len(got) == 0 {
		return slices.Clone(all), true
	}
	for _, g := range got {
		if !slices.Contains(all, g) {
			return nil, false
		}
	}
	return dedupe(got), true
}

func dedupe(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// sanitizeClientName makes a client-supplied name safe to display: it drops
// control characters, invisible format characters (bidi overrides, zero-width),
// Unicode separators other than the ASCII space (U+2028/2029, NBSP, ...) and
// blank-looking Hangul fillers, collapses whitespace runs and caps the length.
// Output escaping is still the renderer's job.
func sanitizeClientName(name string) string {
	name = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r):
			return -1
		case unicode.Is(unicode.Z, r) && r != ' ':
			return -1
		case r == 0x115F, r == 0x1160, r == 0x3164, r == 0xFFA0:
			return -1
		}
		return r
	}, name)
	name = strings.Join(strings.Fields(name), " ")
	if utf8.RuneCountInString(name) > maxClientNameLen {
		name = strings.TrimSpace(string([]rune(name)[:maxClientNameLen]))
	}
	return name
}

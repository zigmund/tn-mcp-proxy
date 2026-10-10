package proxy

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
)

// maxInspectBody caps how much of an upstream response is buffered to look for
// a credential-rejecting tool error. Anything larger is forwarded unchanged.
// The cap applies to the bytes on the wire and, for gzip, to the decoded size.
const maxInspectBody = 64 << 10

// unauthorizedBody is what http.Error writes for the proxy's own 401s.
const unauthorizedBody = "unauthorized\n"

// narrowAcceptEncoding returns the Accept-Encoding to send upstream when tool
// error inspection is on: only codings the proxy can decode. gzip is kept when
// the client accepts it; otherwise identity. br, zstd and deflate are dropped.
func narrowAcceptEncoding(clientValue string) string {
	if acceptsGzip(clientValue) {
		return "gzip"
	}
	return "identity"
}

// acceptsGzip reports whether an Accept-Encoding value allows gzip (an
// explicit gzip or x-gzip with q>0, or a wildcard with q>0 that no explicit
// entry overrides).
func acceptsGzip(v string) bool {
	star, explicit, hasExplicit := false, false, false
	for part := range strings.SplitSeq(v, ",") {
		coding, params, _ := strings.Cut(part, ";")
		coding = strings.ToLower(strings.TrimSpace(coding))
		ok := qValue(params) > 0
		switch coding {
		case "gzip", "x-gzip":
			hasExplicit = true
			explicit = explicit || ok
		case "*":
			star = ok
		}
	}
	if hasExplicit {
		return explicit
	}
	return star
}

// qValue parses the q parameter of an Accept-Encoding entry (default 1).
func qValue(params string) float64 {
	for p := range strings.SplitSeq(params, ";") {
		k, val, ok := strings.Cut(p, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "q") {
			q, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
			if err != nil {
				return 0
			}
			return q
		}
	}
	return 1
}

// inspectToolError looks at a 200 JSON response to a POST for a tool error
// (isError: true). That only triggers a credential re-check; if the upstream
// rejects the stored credentials, resp becomes the proxy's 401 invalid_token
// challenge. Otherwise resp
// is left byte-for-byte as received (the body is only buffered, never altered).
// A non-nil error is a failed body read; the caller must fail the response.
func (h *handler) inspectToolError(resp *http.Response) error {
	if h.rechecker == nil ||
		resp.Request == nil || resp.Request.Method != http.MethodPost ||
		resp.StatusCode != http.StatusOK ||
		resp.ContentLength > maxInspectBody { // known to be too large: do not touch
		return nil
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return nil
	}
	enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	if enc != "" && enc != "identity" && enc != "gzip" {
		return nil // cannot decode (we asked upstream not to send it); pass through
	}

	// Read up to cap+1 bytes: one extra byte tells "exactly cap" from "more".
	orig := resp.Body
	buf, err := io.ReadAll(io.LimitReader(orig, maxInspectBody+1))
	if err != nil {
		return fmt.Errorf("reading upstream response: %w", err)
	}
	if len(buf) > maxInspectBody {
		// Too large to inspect: replay what was read, then stream the rest.
		resp.Body = &replayBody{Reader: io.MultiReader(bytes.NewReader(buf), orig), c: orig}
		return nil
	}
	_ = orig.Close() // fully consumed
	resp.Body = io.NopCloser(bytes.NewReader(buf))

	data := buf
	if enc == "gzip" {
		if data = gunzipBounded(buf); data == nil {
			return nil
		}
	}
	if !hasToolError(data) {
		return nil
	}

	// A tool error is only a trigger: business errors (bad ticker, closed
	// market) are common. Re-run the upstream's credential check; only a clear
	// rejection turns the response into a 401. Every other outcome forwards the
	// original response (the buffered body is already in place).
	creds, _ := resp.Request.Context().Value(credsKey{}).(map[string]string)
	if h.rechecker.recheck(resp.Request.Context(), h.up, creds) != verdictRejected {
		return nil
	}

	h.log.Warn("upstream rejected credentials (tool error, confirmed by re-check)")
	resp.Body = io.NopCloser(strings.NewReader(unauthorizedBody))
	resp.StatusCode = http.StatusUnauthorized
	resp.Status = "401 Unauthorized"
	resp.ContentLength = int64(len(unauthorizedBody))
	resp.TransferEncoding = nil
	resp.Uncompressed = false
	for _, k := range []string{"Content-Encoding", "Etag", "Content-Md5", "Digest"} {
		resp.Header.Del(k)
	}
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	resp.Header.Set("X-Content-Type-Options", "nosniff")
	resp.Header.Set("Content-Length", strconv.Itoa(len(unauthorizedBody)))
	resp.Header.Set("WWW-Authenticate", h.challengeValue("invalid_token", "upstream rejected credentials"))
	return nil
}

// replayBody is a response body whose closing closes the original body.
type replayBody struct {
	io.Reader
	c io.Closer
}

func (b *replayBody) Close() error { return b.c.Close() }

// gunzipBounded decodes gzip data, returning nil when it is corrupt or
// decodes to more than maxInspectBody bytes.
func gunzipBounded(b []byte) []byte {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil
	}
	defer func() { _ = zr.Close() }()
	out, err := io.ReadAll(io.LimitReader(zr, maxInspectBody+1))
	if err != nil || len(out) > maxInspectBody {
		return nil
	}
	return out
}

// rpcResponse is the part of a JSON-RPC response (MCP tool result) that the
// trigger needs. Unknown fields are ignored.
type rpcResponse struct {
	Result *struct {
		IsError bool `json:"isError"`
	} `json:"result"`
}

// hasToolError reports whether body is a JSON-RPC response (or a batch of
// them) in which some result has isError=true. It does not look at the error
// text. Malformed input never matches.
func hasToolError(body []byte) bool {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return false
	}
	var msgs []json.RawMessage
	if body[0] == '[' {
		if json.Unmarshal(body, &msgs) != nil {
			return false
		}
	} else {
		msgs = []json.RawMessage{body}
	}
	for _, m := range msgs {
		var r rpcResponse
		if json.Unmarshal(m, &r) == nil && r.Result != nil && r.Result.IsError {
			return true
		}
	}
	return false
}

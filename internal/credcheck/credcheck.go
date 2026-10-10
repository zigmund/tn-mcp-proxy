// Package credcheck verifies upstream credentials with one authenticated MCP
// tools/call (the upstream's validate block). It is shared by the OAuth
// authorize form and the proxy's re-check after a tool error.
package credcheck

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
)

// Credential check limits.
const (
	maxCheckBody     = 1 << 20 // per response body
	maxChecks        = 16      // concurrent checks across all upstreams
	checkDialTimeout = 10 * time.Second
	deleteTimeout    = 2 * time.Second // best-effort session teardown

	mcpProtocolVersion = "2025-06-18" // offered in initialize
	idInitialize       = 1
	idToolCall         = 2
)

// Outcomes of a credential check, as returned by Checker.check (wrapped in
// a *CheckError that carries the log details).
var (
	// ErrRejected: the upstream definitively refused the credentials.
	ErrRejected = errors.New("credentials rejected by upstream")
	// ErrUnavailable: no verdict (outage, timeout, misconfiguration, a
	// malformed reply). Callers must fail closed.
	ErrUnavailable = errors.New("credential check unavailable")
)

// CheckError is a non-OK check outcome. step and reason are fixed vocabulary:
// they never contain credentials or upstream text, so they are safe to log.
type CheckError struct {
	kind   error  // ErrRejected or ErrUnavailable
	Step   string // initialize, initialized or tools/call
	Reason string
	Cause  error // transport error with the URL stripped, for logs only
}

func (e *CheckError) Error() string { return e.kind.Error() + ": " + e.Step + ": " + e.Reason }
func (e *CheckError) Unwrap() error { return e.kind }

func rejected(step, reason string) *CheckError {
	return &CheckError{kind: ErrRejected, Step: step, Reason: reason}
}

func unavailable(step, reason string, cause error) *CheckError {
	return &CheckError{kind: ErrUnavailable, Step: step, Reason: reason, Cause: cause}
}

// Checker verifies credentials with one authenticated MCP tools/call. It
// owns its HTTP client: redirects are never followed, because the credential
// headers would be forwarded to whatever host the upstream names.
type Checker struct {
	client  *http.Client
	sem     chan struct{} // bounds concurrent checks
	version string        // the binary's version, sent in User-Agent and clientInfo
}

// DefaultVersion is used when New is given an empty version.
const DefaultVersion = "dev"

// New returns a Checker that identifies itself as tn-mcp-proxy/version, in
// the User-Agent header and the MCP clientInfo. An empty version means "dev".
func New(version string) *Checker {
	if version == "" {
		version = DefaultVersion
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	// Credentials travel in request headers: never route the check through an
	// HTTP(S)_PROXY from the environment, which would see them.
	t.Proxy = nil
	t.DialContext = (&net.Dialer{Timeout: checkDialTimeout}).DialContext
	t.TLSHandshakeTimeout = checkDialTimeout
	t.DisableCompression = true
	return &Checker{
		client: &http.Client{
			Transport:     t,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		sem:     make(chan struct{}, maxChecks),
		version: version,
	}
}

// check runs the validate flow of up with creds (header -> value). It returns
// nil when the upstream accepts them, otherwise a *CheckError whose kind is
// ErrRejected or ErrUnavailable. The whole check is bounded by
// up.Validate.Timeout and ctx.
func (c *Checker) Check(ctx context.Context, up config.Upstream, creds map[string]string) error {
	v := up.Validate
	if v == nil {
		return nil
	}
	timeout := v.Timeout
	if timeout <= 0 {
		timeout = config.DefaultValidateTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Waiting for a slot counts toward the timeout.
	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return unavailable("initialize", "too many concurrent checks", nil)
	}

	s := &mcpSession{c: c, url: up.URL, creds: creds, version: mcpProtocolVersion}
	err := s.run(ctx, v)
	<-c.sem // the slot is not held during the best-effort DELETE
	if s.id != "" {
		s.close(ctx)
	}
	if err != nil {
		return err
	}
	return nil
}

// mcpSession is one stateless-or-stateful MCP exchange with an upstream.
type mcpSession struct {
	c       *Checker
	url     string
	creds   map[string]string
	id      string // Mcp-Session-Id, when the upstream issued one
	version string // protocol version: offered, then negotiated
	// negotiated is set once initialize succeeded; the protocol version header
	// is sent from then on.
	negotiated bool
}

func (s *mcpSession) run(ctx context.Context, v *config.Validate) *CheckError {
	initReq, err := marshalRPC(idInitialize, "initialize", map[string]any{
		"protocolVersion": mcpProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "tn-mcp-proxy", "version": s.c.version},
	})
	if err != nil {
		return unavailable("initialize", "encoding request", nil)
	}
	msg, ce := s.call(ctx, "initialize", initReq, idInitialize)
	if ce != nil {
		return ce
	}
	var res struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if present(msg.Error) {
		return rpcError("initialize", msg.Error)
	}
	if !isObject(msg.Result) || json.Unmarshal(msg.Result, &res) != nil {
		return unavailable("initialize", "malformed response", nil)
	}
	// A version other than the offered one is accepted as is: we only echo it
	// back in Mcp-Protocol-Version, and the check needs no feature negotiation.
	if res.ProtocolVersion != "" {
		s.version = res.ProtocolVersion
	}
	s.negotiated = true

	note, err := marshalRPC(0, "notifications/initialized", nil)
	if err != nil {
		return unavailable("initialized", "encoding request", nil)
	}
	if _, ce := s.call(ctx, "initialized", note, 0); ce != nil {
		return ce
	}

	args := v.Arguments
	if args == nil {
		args = map[string]any{}
	}
	tc, err := marshalRPC(idToolCall, "tools/call", map[string]any{"name": v.Tool, "arguments": args})
	if err != nil {
		return unavailable("tools/call", "encoding request", nil)
	}
	msg, ce = s.call(ctx, "tools/call", tc, idToolCall)
	if ce != nil {
		return ce
	}
	if present(msg.Error) {
		return rpcError("tools/call", msg.Error)
	}
	var out struct {
		IsError bool `json:"isError"`
	}
	if !isObject(msg.Result) || json.Unmarshal(msg.Result, &out) != nil {
		return unavailable("tools/call", "malformed response", nil)
	}
	if out.IsError {
		return rejected("tools/call", "tool reported an error")
	}
	return nil
}

// call POSTs payload and classifies the HTTP outcome. For a request (id != 0)
// it returns the matching JSON-RPC response; for a notification (id == 0) any
// 2xx will do and the returned message is nil.
func (s *mcpSession) call(ctx context.Context, step string, payload []byte, id int64) (*rpcMessage, *CheckError) {
	resp, err := s.do(ctx, http.MethodPost, payload)
	if err != nil {
		return nil, transportError(ctx, step, err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, rejected(step, "http "+strconv.Itoa(resp.StatusCode))
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		// 3xx included: redirects are not followed.
		return nil, unavailable(step, "http "+strconv.Itoa(resp.StatusCode), nil)
	}
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" && s.id == "" {
		s.id = sid
	}
	if id == 0 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, nil
	}
	msg, err := parseRPC(resp.Header.Get("Content-Type"), resp.Body, id)
	switch {
	case err == nil:
		return msg, nil
	case errors.Is(err, errBodyTooLarge):
		return nil, unavailable(step, "response too large", nil)
	case ctx.Err() != nil:
		return nil, transportError(ctx, step, ctx.Err())
	case errors.Is(err, errNoResponse):
		return nil, unavailable(step, "no matching response", nil)
	case errors.Is(err, errContentType):
		return nil, unavailable(step, "unsupported content type", nil)
	default:
		return nil, unavailable(step, "malformed response", nil)
	}
}

// do sends one request with the credentials and the session headers.
func (s *mcpSession) do(ctx context.Context, method string, payload []byte) (*http.Response, error) {
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.url, body)
	if err != nil {
		return nil, err
	}
	for k, v := range s.creds {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "tn-mcp-proxy/"+s.c.version)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
	}
	if s.id != "" {
		req.Header.Set("Mcp-Session-Id", s.id)
	}
	if s.negotiated {
		req.Header.Set("Mcp-Protocol-Version", s.version)
	}
	return s.c.client.Do(req)
}

// close ends the upstream session. Best effort: it runs even when the check's
// own deadline has passed, and its errors are ignored.
func (s *mcpSession) close(ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), deleteTimeout)
	defer cancel()
	if resp, err := s.do(ctx, http.MethodDelete, nil); err == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}
}

// transportError maps a failed round trip to an unavailable outcome. The
// *url.Error wrapper is dropped: it embeds the URL, which may carry a secret.
func transportError(ctx context.Context, step string, err error) *CheckError {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	reason := "transport error"
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		reason = "timeout"
	} else if errors.Is(err, context.Canceled) {
		reason = "canceled"
	}
	return unavailable(step, reason, err)
}

// rpcError reports a JSON-RPC error object: unavailable, not rejected, since it
// points at a misconfiguration (unknown tool, bad arguments) rather than bad
// credentials. Only the numeric code is kept.
func rpcError(step string, raw json.RawMessage) *CheckError {
	var e struct {
		Code *int `json:"code"`
	}
	reason := "jsonrpc error"
	if json.Unmarshal(raw, &e) == nil && e.Code != nil {
		reason += " code " + strconv.Itoa(*e.Code)
	}
	return unavailable(step, reason, nil)
}

// present reports whether raw holds a JSON value other than null: a field
// that is absent or literally null counts as missing.
func present(raw json.RawMessage) bool {
	b := bytes.TrimSpace(raw)
	return len(b) > 0 && string(b) != "null"
}

func isObject(raw json.RawMessage) bool {
	b := bytes.TrimSpace(raw)
	return len(b) > 0 && b[0] == '{'
}

// rpcMessage is the subset of a JSON-RPC 2.0 message the checker looks at.
type rpcMessage struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

// isResponseTo reports whether m is the response (result or error) to the
// request with the given id. Server requests that reuse the id carry a method
// and do not count.
func (m *rpcMessage) isResponseTo(id int64) bool {
	return m.Method == "" && (present(m.Result) || present(m.Error)) &&
		string(bytes.TrimSpace(m.ID)) == strconv.FormatInt(id, 10)
}

func marshalRPC(id int64, method string, params any) ([]byte, error) {
	m := map[string]any{"jsonrpc": "2.0", "method": method}
	if id != 0 {
		m["id"] = id
	}
	if params != nil {
		m["params"] = params
	}
	return json.Marshal(m)
}

var (
	errBodyTooLarge = errors.New("response too large")
	errNoResponse   = errors.New("no matching response")
	errMalformed    = errors.New("malformed response")
	errContentType  = errors.New("unsupported content type")
)

// parseRPC extracts the JSON-RPC response with the given id from an MCP
// response body: a single JSON message (application/json) or an SSE stream
// (text/event-stream) in which other messages may precede the response. At
// most maxCheckBody bytes are read.
func parseRPC(contentType string, body io.Reader, id int64) (*rpcMessage, error) {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, errContentType
	}
	lr := &limitedReader{r: body, n: maxCheckBody + 1}
	switch mt {
	case "application/json":
		b, err := io.ReadAll(lr)
		if err != nil {
			return nil, err
		}
		if lr.n <= 0 {
			return nil, errBodyTooLarge
		}
		var m rpcMessage
		if json.Unmarshal(b, &m) != nil { // an array (batch) fails here too
			return nil, errMalformed
		}
		if !m.isResponseTo(id) {
			return nil, errNoResponse
		}
		return &m, nil
	case "text/event-stream":
		m, err := scanSSE(lr, id)
		if err == nil {
			return m, nil
		}
		if lr.n <= 0 {
			return nil, errBodyTooLarge
		}
		return nil, err
	}
	return nil, errContentType
}

// limitedReader reads at most n bytes; n <= 0 afterwards means the source was
// longer than the budget (it is one byte larger than the cap).
type limitedReader struct {
	r io.Reader
	n int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

// scanSSE reads server-sent events and returns the response to id (WHATWG SSE:
// a leading BOM is ignored, lines end in CR, LF or CRLF, events are separated
// by blank lines, data lines are joined by "\n", ":" lines are comments). Only
// events with no type or type "message" carry JSON-RPC messages; others, and
// events that are not JSON or not the response (notifications, server
// requests), are skipped. A final event without a trailing blank line is still
// processed.
func scanSSE(r io.Reader, id int64) (*rpcMessage, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), maxCheckBody+1)
	sc.Split(splitSSELines)
	var (
		data  []string
		event string
		first = true
	)
	flush := func() *rpcMessage {
		d, ev := data, event
		data, event = data[:0], ""
		if len(d) == 0 || (ev != "" && ev != "message") {
			return nil
		}
		var m rpcMessage
		if json.Unmarshal([]byte(strings.Join(d, "\n")), &m) == nil && m.isResponseTo(id) {
			return &m
		}
		return nil
	}
	for sc.Scan() {
		line := sc.Text()
		if first {
			line, first = strings.TrimPrefix(line, "\ufeff"), false
		}
		if line == "" {
			if m := flush(); m != nil {
				return m, nil
			}
			continue
		}
		name, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch name {
		case "": // ":" comment line
		case "data":
			data = append(data, value)
		case "event":
			event = value
		}
		// id, retry and unknown fields are irrelevant here
	}
	if err := sc.Err(); err != nil && !errors.Is(err, bufio.ErrTooLong) {
		return nil, err
	}
	if m := flush(); m != nil {
		return m, nil
	}
	return nil, errNoResponse
}

// splitSSELines is a bufio.SplitFunc for lines ending in CR, LF or CRLF.
func splitSSELines(data []byte, atEOF bool) (int, []byte, error) {
	i := bytes.IndexAny(data, "\r\n")
	switch {
	case i < 0:
		if atEOF && len(data) > 0 {
			return len(data), data, nil
		}
		return 0, nil, nil
	case data[i] == '\r' && i+1 == len(data) && !atEOF:
		return 0, nil, nil // a CR at the buffer end may be the start of a CRLF
	case data[i] == '\r' && i+1 < len(data) && data[i+1] == '\n':
		return i + 2, data[:i], nil
	}
	return i + 1, data[:i], nil
}

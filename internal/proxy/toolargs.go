package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// inspectToolArguments enforces upstream.forbidden_arguments on POST bodies.
// It returns false after writing the response when the request must not be
// relayed. The body is read once, within the request body cap, and replaced by
// the same bytes, so what the upstream receives is byte-for-byte what the
// client sent.
//
// The inspection fails closed. The upstream may parse the body differently
// from Go (other JSON dialects, case-sensitive keys, duplicate keys), so
// anything that is not strictly valid UTF-8 JSON in the expected shape is
// refused instead of guessed at: a body that is not a JSON object or a
// non-empty array of objects gets 400 -32700, a duplicate or mistyped
// structural key (method, params, arguments) gets 400 -32600. Structural keys
// are matched exactly, as strict parsers do, and a key that only equals one
// under case folding (METHOD, Params, argumentſ) is refused with -32600 too.
//
// A compressed body cannot be inspected; the handler refuses any non-identity
// Content-Encoding with 415 before this runs.
//
// The JSON-RPC methods and tool names found on the way are returned for the
// audit log (nil when the inspection is off: the body is then not parsed at
// all, only to be logged).
func (h *handler) inspectToolArguments(w http.ResponseWriter, r *http.Request, maxBody int64, creds map[string]string) (*bodyInfo, bool) {
	if len(h.up.ForbiddenArguments) == 0 || r.Method != http.MethodPost {
		return nil, true
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return nil, false
		}
		h.log.Debug("reading request body", "err", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return nil, false
	}
	info, rej := checkToolArguments(body, h.up.ForbiddenArguments)
	if rej != nil {
		who := h.who(r, creds)
		if rej.argument != "" {
			h.log.Info("tool call with forbidden argument rejected", append([]any{"argument", rej.argument}, who...)...)
		} else {
			h.log.Info("request body refused: not inspectable", append([]any{"reason", rej.message}, who...)...)
		}
		rej.write(w)
		return nil, false
	}
	// Forward the same bytes with an exact Content-Length (a chunked client
	// body becomes a fixed-length one; the content is unchanged).
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.TransferEncoding = nil
	return &info, true
}

// Bounds on what the audit log takes from a request body.
const (
	maxAuditCalls   = 8   // batch entries listed
	maxAuditNameLen = 128 // bytes of a method or tool name
)

// rpcCall is the JSON-RPC method and, for tools/call, the tool name of one
// message. Both are clipped, user-controlled strings.
type rpcCall struct{ method, tool string }

// bodyInfo is what the inspection learned about a request body for the audit
// log. batch is the number of messages of a JSON array (0 for a single
// message); calls holds at most maxAuditCalls of them.
type bodyInfo struct {
	calls []rpcCall
	batch int
}

// clip replaces control and format runes (bidi overrides such as U+202E
// included) and invalid UTF-8 with U+FFFD, so a logged name cannot disguise
// itself, then cuts the result to at most n bytes without splitting a UTF-8
// sequence. The input is pre-cut to n bytes so mapping stays bounded.
func clip(s string, n int) string {
	s = cutRunes(s, n)
	return cutRunes(strings.Map(func(r rune) rune {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || !unicode.IsPrint(r) {
			return utf8.RuneError
		}
		return r
	}, s), n)
}

// cutRunes cuts s to at most n bytes on a UTF-8 sequence boundary.
func cutRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// JSON-RPC error codes used in rejections.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeInvalidParams  = -32602
)

// rejection is a refused request: HTTP 400 with a JSON-RPC error.
type rejection struct {
	code     int
	message  string
	id       json.RawMessage // echoed only when a string, number or null
	argument string          // configured name, for forbidden arguments
}

func (rj *rejection) write(w http.ResponseWriter) {
	id := string(rj.id)
	if id == "" {
		id = "null"
	}
	msg, _ := json.Marshal(rj.message)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + id + `,"error":{"code":` + strconv.Itoa(rj.code) + `,"message":` + string(msg) + `}}`))
}

var (
	errParse   = &rejection{code: codeParseError, message: "Parse error"}
	errInvalid = &rejection{code: codeInvalidRequest, message: "Invalid Request"}
)

// checkToolArguments returns nil when body may be forwarded, else the
// rejection to answer with.
func checkToolArguments(body []byte, forbidden []string) (bodyInfo, *rejection) {
	// Only the four JSON whitespace bytes are trimmed: a byte order mark or
	// another Unicode space is not JSON and must not be skipped.
	body = bytes.Trim(body, " \t\r\n")
	if len(body) == 0 || !utf8.Valid(body) || !json.Valid(body) {
		return bodyInfo{}, errParse
	}
	switch body[0] {
	case '{':
		var c rpcCall
		rej := checkMessage(body, forbidden, true, &c)
		return bodyInfo{calls: []rpcCall{c}}, rej
	case '[':
		// One decoder walks the array; every element must be an object even
		// after an earlier one was rejected, so a malformed batch is a parse
		// error rather than a partial verdict.
		dec := json.NewDecoder(bytes.NewReader(body))
		if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
			return bodyInfo{}, errParse
		}
		var first *rejection
		var info bodyInfo
		for dec.More() {
			var el json.RawMessage
			if err := dec.Decode(&el); err != nil || len(el) == 0 || el[0] != '{' {
				return bodyInfo{}, errParse
			}
			info.batch++
			if first == nil {
				var c rpcCall
				first = checkMessage(el, forbidden, false, &c)
				if len(info.calls) < maxAuditCalls {
					info.calls = append(info.calls, c)
				}
			}
		}
		if info.batch == 0 {
			return bodyInfo{}, errParse
		}
		return info, first
	}
	return bodyInfo{}, errParse
}

// isKeyVariant reports whether k is not exactly one of the structural names
// but equals one of them under Unicode case folding (METHOD, Params, paramſ).
// A parser that matches keys case-insensitively would read such a key as the
// structural one, so it is refused rather than ignored.
func isKeyVariant(k string, names ...string) bool {
	for _, n := range names {
		if k != n && strings.EqualFold(k, n) {
			return true
		}
	}
	return false
}

var errNotObject = errors.New("not an object")

// eachMember calls fn for every member of the JSON object raw, with the
// decoded key and the raw value, in document order (duplicates included).
func eachMember(raw []byte, fn func(key string, val json.RawMessage)) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return errNotObject
	}
	for dec.More() {
		kt, err := dec.Token()
		key, ok := kt.(string)
		if err != nil || !ok {
			return errNotObject
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return err
		}
		fn(key, v)
	}
	return nil
}

// checkMessage inspects one JSON-RPC message object. single reports whether
// it is the whole request, in which case its id is echoed in a rejection. The
// method (and tool name) found are stored in call, clipped.
func checkMessage(raw []byte, forbidden []string, single bool, call *rpcCall) *rejection {
	var method, params, id json.RawMessage
	var dup bool
	err := eachMember(raw, func(k string, v json.RawMessage) {
		dup = dup || isKeyVariant(k, "method", "params")
		switch k {
		case "method":
			dup = dup || method != nil
			method = v
		case "params":
			dup = dup || params != nil
			params = v
		case "id":
			id = v
		}
	})
	if err != nil {
		return errParse
	}
	if dup {
		return errInvalid
	}
	if method == nil {
		return nil // not a request (for example a response): no tool call
	}
	var m string
	if method[0] != '"' || json.Unmarshal(method, &m) != nil {
		return errInvalid
	}
	call.method = clip(m, maxAuditNameLen)
	if m != "tools/call" || params == nil || params[0] != '{' {
		return nil
	}

	var args json.RawMessage
	dup = false
	if err := eachMember(params, func(k string, v json.RawMessage) {
		dup = dup || isKeyVariant(k, "arguments", "name")
		switch k {
		case "arguments":
			dup = dup || args != nil
			args = v
		case "name":
			call.tool = "" // a later non-string name must not leave a stale one
			var n string
			if len(v) > 0 && v[0] == '"' && json.Unmarshal(v, &n) == nil {
				call.tool = clip(n, maxAuditNameLen)
			}
		}
	}); err != nil {
		return errParse
	}
	if dup {
		return errInvalid
	}
	if args == nil || args[0] != '{' {
		return nil
	}
	var hit string
	if err := eachMember(args, func(k string, _ json.RawMessage) {
		for _, f := range forbidden {
			if hit == "" && strings.EqualFold(k, f) {
				hit = f
			}
		}
	}); err != nil {
		return errParse
	}
	if hit == "" {
		return nil
	}
	rej := &rejection{code: codeInvalidParams, message: "argument not allowed: " + hit, argument: hit}
	if single && len(id) > 0 && (id[0] == '"' || id[0] == '-' || id[0] == 'n' || (id[0] >= '0' && id[0] <= '9')) {
		rej.id = id
	}
	return rej
}

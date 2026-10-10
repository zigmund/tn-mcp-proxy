package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
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
// A compressed body cannot be inspected and is refused with 415.
func (h *handler) inspectToolArguments(w http.ResponseWriter, r *http.Request, maxBody int64) bool {
	if len(h.up.ForbiddenArguments) == 0 || r.Method != http.MethodPost {
		return true
	}
	// Defence in depth: the forwarded headers do not include Content-Encoding,
	// but a body is never judged unless it is read as sent.
	for _, v := range r.Header.Values("Content-Encoding") {
		if enc := strings.TrimSpace(v); enc != "" && !strings.EqualFold(enc, "identity") {
			h.log.Info("compressed request body refused: cannot inspect for forbidden arguments")
			http.Error(w, "content-encoding not supported", http.StatusUnsupportedMediaType)
			return false
		}
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return false
		}
		h.log.Debug("reading request body", "err", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return false
	}
	if rej := checkToolArguments(body, h.up.ForbiddenArguments); rej != nil {
		if rej.argument != "" {
			h.log.Info("tool call with forbidden argument rejected", "argument", rej.argument)
		} else {
			h.log.Info("request body refused: not inspectable", "reason", rej.message)
		}
		rej.write(w)
		return false
	}
	// Forward the same bytes with an exact Content-Length (a chunked client
	// body becomes a fixed-length one; the content is unchanged).
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.TransferEncoding = nil
	return true
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
func checkToolArguments(body []byte, forbidden []string) *rejection {
	// Only the four JSON whitespace bytes are trimmed: a byte order mark or
	// another Unicode space is not JSON and must not be skipped.
	body = bytes.Trim(body, " \t\r\n")
	if len(body) == 0 || !utf8.Valid(body) || !json.Valid(body) {
		return errParse
	}
	switch body[0] {
	case '{':
		return checkMessage(body, forbidden, true)
	case '[':
		// One decoder walks the array; every element must be an object even
		// after an earlier one was rejected, so a malformed batch is a parse
		// error rather than a partial verdict.
		dec := json.NewDecoder(bytes.NewReader(body))
		if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
			return errParse
		}
		var first *rejection
		n := 0
		for dec.More() {
			var el json.RawMessage
			if err := dec.Decode(&el); err != nil || len(el) == 0 || el[0] != '{' {
				return errParse
			}
			n++
			if first == nil {
				first = checkMessage(el, forbidden, false)
			}
		}
		if n == 0 {
			return errParse
		}
		return first
	}
	return errParse
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
// it is the whole request, in which case its id is echoed in a rejection.
func checkMessage(raw []byte, forbidden []string, single bool) *rejection {
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
	if m != "tools/call" || params == nil || params[0] != '{' {
		return nil
	}

	var args json.RawMessage
	dup = false
	if err := eachMember(params, func(k string, v json.RawMessage) {
		dup = dup || isKeyVariant(k, "arguments")
		if k == "arguments" {
			dup = dup || args != nil
			args = v
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

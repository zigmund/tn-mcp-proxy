// Package seal produces and verifies self-contained, encrypted and
// authenticated tokens. It is the only cryptographic building block of the
// stateless OAuth server: client ids, authorization codes, access tokens and
// refresh tokens are all blobs created by [Sealer.Seal].
//
// # Token format
//
//	base64.RawURLEncoding( version(1) || keyID(4) || nonce(12) || ciphertext+tag )
//
// The ciphertext is AES-256-GCM over a JSON envelope {"exp":<unix seconds>,"d":<payload>}.
// The additional authenticated data is version || keyID || kind, so a token
// sealed for one [Kind] can never be opened as another, and the header cannot
// be altered without detection. An exp of 0 (or omitted) means "never expires".
// Tokens are at most [MaxTokenSize] (16 KiB, encoded); Seal refuses to produce larger ones and
// Open rejects them. Decoding is strict: only the canonical base64url encoding
// is accepted (no padding, no CR/LF, no non-zero trailing bits), so every
// token has exactly one valid string form and can be used as a cache key.
//
// # Keys and rotation
//
// Each configured 32-byte secret is expanded with HKDF-SHA256 into an AEAD
// key, a MAC key and a short key id (all with distinct info labels). The first
// secret is the primary one: it seals new tokens and signs MACs. Every secret
// is accepted for opening tokens and verifying MACs, so rotation is: prepend a
// new secret, deploy, and drop the old one once its tokens have expired.
//
// Every Seal draws a random 96-bit GCM nonce, which bounds the safe volume to
// roughly 2^32 seals per key; rotation switches sealing to a fresh key and so
// resets that count.
//
// Always construct a Sealer with [New]; the zero value is not usable (Seal and
// Open return an error, MAC panics).
package seal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// Kind separates token families; it is bound into the AEAD additional data.
type Kind string

// Well-known token kinds.
const (
	KindClient  Kind = "client"
	KindCode    Kind = "code"
	KindAccess  Kind = "access"
	KindRefresh Kind = "refresh"
	// KindAuthRequest seals the validated authorize request carried in the
	// credentials form's hidden field between GET and POST.
	KindAuthRequest Kind = "authreq"
)

var (
	// ErrInvalid is returned for any token that is malformed, tampered with,
	// of a different kind, or sealed with an unknown key.
	ErrInvalid = errors.New("seal: invalid token")
	// ErrExpired is returned for an authentic token whose expiry has passed.
	ErrExpired = errors.New("seal: token expired")
	// ErrPayload is returned by Open for an authentic, unexpired token whose
	// payload does not decode into the caller's value. This is a server-side
	// bug (type mismatch between Seal and Open), not a client error.
	ErrPayload = errors.New("seal: payload does not match target type")

	errNotInitialized = errors.New("seal: Sealer not initialized, use New")
)

// MaxTokenSize is the largest encoded token Seal produces and Open accepts.
const MaxTokenSize = 16 << 10

const (
	version      byte = 1
	keySize           = 32
	keyIDSize         = 4
	nonceSize         = 12
	headerSize        = 1 + keyIDSize
	maxTokenSize      = MaxTokenSize
	gcmTagSize        = 16

	labelAEAD = "tn-mcp-proxy seal v1 aead"
	labelMAC  = "tn-mcp-proxy seal v1 mac"
	labelID   = "tn-mcp-proxy seal v1 key id"
)

type keyset struct {
	id     [keyIDSize]byte
	aead   cipher.AEAD
	macKey []byte
}

// Sealer seals and opens tokens. It is safe for concurrent use. Create it with
// New; the zero value is not usable.
type Sealer struct {
	keys []keyset // keys[0] is primary
	now  func() time.Time
}

// Option configures a Sealer in New.
type Option func(*Sealer)

// WithClock overrides the clock used for expiry checks (default time.Now).
// A nil function is ignored.
func WithClock(now func() time.Time) Option {
	return func(s *Sealer) {
		if now != nil {
			s.now = now
		}
	}
}

// New creates a Sealer from raw 32-byte secrets in priority order: the first
// is used for sealing, all are tried for opening. The slices are copied. New
// fails if two keys derive the same key id (duplicate secrets or a collision).
func New(keys [][]byte, opts ...Option) (*Sealer, error) {
	if len(keys) == 0 {
		return nil, errors.New("seal: at least one key is required")
	}
	s := &Sealer{now: time.Now}
	for i, k := range keys {
		if len(k) != keySize {
			return nil, fmt.Errorf("seal: key %d has length %d, want %d", i, len(k), keySize)
		}
		ks, err := deriveKeyset(k)
		if err != nil {
			return nil, fmt.Errorf("seal: key %d: %w", i, err)
		}
		for j := range s.keys {
			if s.keys[j].id == ks.id {
				return nil, fmt.Errorf("seal: key %d has the same key id as key %d", i, j)
			}
		}
		s.keys = append(s.keys, ks)
	}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

func deriveKeyset(secret []byte) (keyset, error) {
	var ks keyset
	aeadKey, err := hkdf.Key(sha256.New, secret, nil, labelAEAD, keySize)
	if err != nil {
		return ks, err
	}
	block, err := aes.NewCipher(aeadKey)
	if err != nil {
		return ks, err
	}
	ks.aead, err = cipher.NewGCM(block)
	if err != nil {
		return ks, err
	}
	ks.macKey, err = hkdf.Key(sha256.New, secret, nil, labelMAC, keySize)
	if err != nil {
		return ks, err
	}
	id, err := hkdf.Key(sha256.New, secret, nil, labelID, keyIDSize)
	if err != nil {
		return ks, err
	}
	copy(ks.id[:], id)
	return ks, nil
}

type envelope struct {
	Exp int64           `json:"exp,omitempty"`
	D   json.RawMessage `json:"d"`
}

func aad(ver byte, id []byte, kind Kind) []byte {
	b := make([]byte, 0, headerSize+len(kind))
	b = append(b, ver)
	b = append(b, id...)
	return append(b, kind...)
}

// marshalJSON encodes v without HTML escaping: <, > and & would otherwise
// become 6-byte escape sequences and inflate a token for no benefit (tokens
// are not embedded in HTML). The output decodes identically, so tokens sealed
// with escaping remain valid.
func marshalJSON(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// marshalEnvelope returns the plaintext sealed for payload: the JSON envelope.
func marshalEnvelope(payload any, expUnix int64) ([]byte, error) {
	d, err := marshalJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("seal: encoding payload: %w", err)
	}
	if len(d) > maxTokenSize {
		return nil, errors.New("seal: token too large")
	}
	plain, err := marshalJSON(envelope{Exp: expUnix, D: d})
	if err != nil {
		return nil, fmt.Errorf("seal: encoding envelope: %w", err)
	}
	return plain, nil
}

// EncodedSize returns the length of the token Seal would produce for payload
// with the largest possible expiry, without encrypting. Callers use it to
// reject input that cannot be sealed before doing any other work. It fails
// only if the payload cannot be encoded.
func EncodedSize(payload any) (int, error) {
	plain, err := marshalEnvelope(payload, math.MaxInt64)
	if err != nil {
		return 0, err
	}
	return base64.RawURLEncoding.EncodedLen(headerSize + nonceSize + len(plain) + gcmTagSize), nil
}

// Seal encrypts payload (JSON-encoded) into a URL-safe token of the given
// kind. A zero exp means the token never expires; otherwise exp is truncated
// to whole seconds and the token is already expired at exp (now >= exp). It
// fails if the encoded token would exceed 16 KiB.
func (s *Sealer) Seal(kind Kind, payload any, exp time.Time) (string, error) {
	if s == nil || len(s.keys) == 0 {
		return "", errNotInitialized
	}
	if kind == "" {
		return "", errors.New("seal: empty kind")
	}
	var expUnix int64
	if !exp.IsZero() {
		expUnix = exp.Unix()
		if expUnix <= 0 {
			return "", errors.New("seal: expiry must be after 1970-01-01")
		}
	}
	plain, err := marshalEnvelope(payload, expUnix)
	if err != nil {
		return "", err
	}

	k := s.keys[0]
	buf := make([]byte, headerSize+nonceSize, headerSize+nonceSize+len(plain)+k.aead.Overhead())
	buf[0] = version
	copy(buf[1:], k.id[:])
	nonce := buf[headerSize : headerSize+nonceSize]
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("seal: reading random nonce: %w", err)
	}
	buf = k.aead.Seal(buf, nonce, plain, aad(version, k.id[:], kind))
	if base64.RawURLEncoding.EncodedLen(len(buf)) > maxTokenSize {
		return "", errors.New("seal: token too large")
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Open authenticates and decrypts token of the given kind and JSON-decodes its
// payload into out. It returns ErrInvalid for anything that fails
// authentication or is not in canonical encoding, ErrExpired for an authentic
// but expired token, and an error wrapping ErrPayload if the authentic payload
// (or its absence) does not decode into out.
func (s *Sealer) Open(kind Kind, token string, out any) error {
	if s == nil || len(s.keys) == 0 {
		return errNotInitialized
	}
	if kind == "" || len(token) == 0 || len(token) > maxTokenSize {
		return ErrInvalid
	}
	// The base64 decoder silently skips CR and LF; reject them so each token
	// has a single string form.
	if strings.ContainsAny(token, "\r\n") {
		return ErrInvalid
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil {
		return ErrInvalid
	}
	if len(raw) < headerSize+nonceSize || raw[0] != version {
		return ErrInvalid
	}
	id := raw[1:headerSize]
	var k *keyset
	for i := range s.keys {
		if hmac.Equal(s.keys[i].id[:], id) {
			k = &s.keys[i]
			break
		}
	}
	if k == nil {
		return ErrInvalid
	}
	nonce := raw[headerSize : headerSize+nonceSize]
	plain, err := k.aead.Open(nil, nonce, raw[headerSize+nonceSize:], aad(raw[0], id, kind))
	if err != nil {
		return ErrInvalid
	}
	var env envelope
	if err := json.Unmarshal(plain, &env); err != nil {
		return ErrInvalid
	}
	if env.Exp != 0 && s.now().Unix() >= env.Exp {
		return ErrExpired
	}
	if err := json.Unmarshal(env.D, out); err != nil {
		return fmt.Errorf("%w: %v", ErrPayload, err)
	}
	return nil
}

// OpenAs is a generic wrapper around [Sealer.Open] returning the decoded
// payload as T.
func OpenAs[T any](s *Sealer, kind Kind, token string) (T, error) {
	var out T
	if err := s.Open(kind, token, &out); err != nil {
		var zero T
		return zero, err
	}
	return out, nil
}

func (k *keyset) mac(purpose string, data []byte) []byte {
	h := hmac.New(sha256.New, k.macKey)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(purpose)))
	h.Write(n[:])
	h.Write([]byte(purpose))
	h.Write(data)
	return h.Sum(nil)
}

// MAC returns HMAC-SHA256 of data under the primary key, domain-separated by
// purpose. It panics on a nil or zero Sealer.
func (s *Sealer) MAC(purpose string, data []byte) []byte {
	return s.keys[0].mac(purpose, data)
}

// VerifyMAC reports whether mac is valid for purpose and data under any
// configured key, in constant time per key.
func (s *Sealer) VerifyMAC(purpose string, data, mac []byte) bool {
	ok := false
	for i := range s.keys {
		if hmac.Equal(s.keys[i].mac(purpose, data), mac) {
			ok = true
		}
	}
	return ok
}

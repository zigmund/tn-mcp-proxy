package seal

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

type payload struct {
	User string `json:"user"`
	N    int    `json:"n"`
}

func key(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func mustNew(t *testing.T, keys ...[]byte) *Sealer {
	t.Helper()
	s, err := New(keys)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var fixedNow = time.Unix(1_800_000_000, 0)

func withClock(s *Sealer) *Sealer {
	s.now = func() time.Time { return fixedNow }
	return s
}

func TestNewErrors(t *testing.T) {
	tests := []struct {
		name string
		keys [][]byte
	}{
		{"nil", nil},
		{"empty", [][]byte{}},
		{"short", [][]byte{make([]byte, 31)}},
		{"long", [][]byte{make([]byte, 33)}},
		{"second bad", [][]byte{key(1), make([]byte, 5)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.keys); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestNewCopiesKeys(t *testing.T) {
	k := key(1)
	s := mustNew(t, k)
	tok, err := s.Seal(KindAccess, payload{"a", 1}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	for i := range k {
		k[i] = 0
	}
	var out payload
	if err := s.Open(KindAccess, tok, &out); err != nil {
		t.Fatal(err)
	}
}

func TestRoundTrip(t *testing.T) {
	s := withClock(mustNew(t, key(1)))
	for _, kind := range []Kind{KindClient, KindCode, KindAccess, KindRefresh, "custom"} {
		t.Run(string(kind), func(t *testing.T) {
			in := payload{"alice", 42}
			tok, err := s.Seal(kind, in, fixedNow.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			var out payload
			if err := s.Open(kind, tok, &out); err != nil {
				t.Fatal(err)
			}
			if out != in {
				t.Fatalf("got %+v want %+v", out, in)
			}
		})
	}
}

func TestSealEmptyKind(t *testing.T) {
	s := mustNew(t, key(1))
	if _, err := s.Seal("", 1, time.Time{}); err == nil {
		t.Fatal("expected error")
	}
	var v int
	if err := s.Open("", "abc", &v); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}

func TestSealUnencodablePayload(t *testing.T) {
	s := mustNew(t, key(1))
	if _, err := s.Seal(KindCode, make(chan int), time.Time{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestWrongKind(t *testing.T) {
	s := mustNew(t, key(1))
	tok, _ := s.Seal(KindCode, payload{"a", 1}, time.Time{})
	var out payload
	if err := s.Open(KindAccess, tok, &out); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}

func TestTamper(t *testing.T) {
	s := mustNew(t, key(1))
	tok, _ := s.Seal(KindAccess, payload{"a", 1}, time.Time{})
	raw, _ := base64.RawURLEncoding.DecodeString(tok)
	regions := []struct {
		name string
		idx  int
	}{
		{"version", 0},
		{"keyid", 1},
		{"nonce", headerSize},
		{"ciphertext first", headerSize + nonceSize},
		{"tag last", len(raw) - 1},
	}
	for _, r := range regions {
		t.Run(r.name, func(t *testing.T) {
			b := bytes.Clone(raw)
			b[r.idx] ^= 0x01
			var out payload
			err := s.Open(KindAccess, base64.RawURLEncoding.EncodeToString(b), &out)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestMalformed(t *testing.T) {
	s := mustNew(t, key(1))
	tok, _ := s.Seal(KindAccess, payload{"a", 1}, time.Time{})
	tests := map[string]string{
		"empty":         "",
		"not base64":    "!!!not*base64!!!",
		"padded":        tok + "=",
		"truncated":     tok[:len(tok)/2],
		"header only":   base64.RawURLEncoding.EncodeToString([]byte{1, 1, 2, 3, 4}),
		"too short tag": tok[:headerSize+nonceSize],
		"oversized":     strings.Repeat("A", maxTokenSize+1),
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			var out payload
			if err := s.Open(KindAccess, in, &out); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestExpiry(t *testing.T) {
	s := withClock(mustNew(t, key(1)))
	tests := []struct {
		name string
		exp  time.Time
		want error
	}{
		{"future", fixedNow.Add(time.Second), nil},
		{"exactly now", fixedNow, ErrExpired},
		{"past", fixedNow.Add(-time.Hour), ErrExpired},
		{"zero never expires", time.Time{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok, err := s.Seal(KindRefresh, payload{"a", 1}, tt.exp)
			if err != nil {
				t.Fatal(err)
			}
			var out payload
			err = s.Open(KindRefresh, tok, &out)
			if tt.want == nil && err != nil || tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("got %v want %v", err, tt.want)
			}
			if errors.Is(err, ErrInvalid) {
				t.Fatal("must not be ErrInvalid")
			}
		})
	}
}

func TestZeroExpFarFuture(t *testing.T) {
	s := mustNew(t, key(1))
	tok, _ := s.Seal(KindClient, payload{"c", 1}, time.Time{})
	s.now = func() time.Time { return time.Unix(1<<40, 0) }
	var out payload
	if err := s.Open(KindClient, tok, &out); err != nil {
		t.Fatal(err)
	}
}

func TestExpiredWrongKindIsInvalid(t *testing.T) {
	s := withClock(mustNew(t, key(1)))
	tok, _ := s.Seal(KindCode, payload{}, fixedNow.Add(-time.Hour))
	var out payload
	if err := s.Open(KindAccess, tok, &out); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}

func TestSealRejectsPreEpochExpiry(t *testing.T) {
	s := mustNew(t, key(1))
	if _, err := s.Seal(KindCode, 1, time.Unix(-5, 0)); err == nil {
		t.Fatal("expected error")
	}
}

func TestRotation(t *testing.T) {
	oldS := mustNew(t, key(1))
	tok, err := oldS.Seal(KindAccess, payload{"a", 1}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	var out payload

	rotated := mustNew(t, key(2), key(1))
	if err := rotated.Open(KindAccess, tok, &out); err != nil {
		t.Fatalf("rotated should open old token: %v", err)
	}

	newOnly := mustNew(t, key(2))
	if err := newOnly.Open(KindAccess, tok, &out); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v", err)
	}

	// New tokens use the primary key id.
	nt, _ := rotated.Seal(KindAccess, payload{"b", 2}, time.Time{})
	raw, _ := base64.RawURLEncoding.DecodeString(nt)
	if !bytes.Equal(raw[1:headerSize], rotated.keys[0].id[:]) {
		t.Fatal("new token not sealed with primary key id")
	}
	if bytes.Equal(rotated.keys[0].id[:], rotated.keys[1].id[:]) {
		t.Fatal("key ids must differ")
	}
	if err := newOnly.Open(KindAccess, nt, &out); err != nil {
		t.Fatal(err)
	}
	if err := oldS.Open(KindAccess, nt, &out); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}

func TestDistinctTokens(t *testing.T) {
	s := mustNew(t, key(1))
	a, _ := s.Seal(KindCode, payload{"a", 1}, time.Time{})
	b, _ := s.Seal(KindCode, payload{"a", 1}, time.Time{})
	if a == b {
		t.Fatal("tokens must differ")
	}
}

func TestMAC(t *testing.T) {
	s := mustNew(t, key(1))
	data := []byte("hello")
	mac := s.MAC("purpose", data)
	if !s.VerifyMAC("purpose", data, mac) {
		t.Fatal("valid mac rejected")
	}
	if s.VerifyMAC("other", data, mac) {
		t.Fatal("wrong purpose accepted")
	}
	if s.VerifyMAC("purpose", []byte("hellp"), mac) {
		t.Fatal("wrong data accepted")
	}
	bad := bytes.Clone(mac)
	bad[0] ^= 1
	if s.VerifyMAC("purpose", data, bad) {
		t.Fatal("tampered mac accepted")
	}
	if s.VerifyMAC("purpose", data, nil) || s.VerifyMAC("purpose", data, mac[:10]) {
		t.Fatal("short mac accepted")
	}
	// Length-prefixed purpose: boundary shifting must not collide.
	if bytes.Equal(s.MAC("ab", []byte("c")), s.MAC("a", []byte("bc"))) {
		t.Fatal("purpose/data boundary collision")
	}
	rotated := mustNew(t, key(2), key(1))
	if !rotated.VerifyMAC("purpose", data, mac) {
		t.Fatal("rotated key should verify old mac")
	}
	if mustNew(t, key(2)).VerifyMAC("purpose", data, mac) {
		t.Fatal("unrelated key verified mac")
	}
}

func TestSealTooLarge(t *testing.T) {
	s := mustNew(t, key(1))
	if _, err := s.Seal(KindAccess, strings.Repeat("x", maxTokenSize), time.Time{}); err == nil {
		t.Fatal("expected too-large error")
	}
	// A token near the limit still round-trips.
	big := strings.Repeat("x", 11_000)
	tok, err := s.Seal(KindAccess, big, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) > maxTokenSize {
		t.Fatalf("token length %d", len(tok))
	}
	if got, err := OpenAs[string](s, KindAccess, tok); err != nil || got != big {
		t.Fatalf("err=%v", err)
	}
}

func TestStrictEncoding(t *testing.T) {
	s := mustNew(t, key(1))
	tok, _ := s.Seal(KindAccess, payload{"a", 1}, time.Time{})
	var out payload
	for name, in := range map[string]string{
		"lf":       tok[:10] + "\n" + tok[10:],
		"cr":       tok[:10] + "\r" + tok[10:],
		"trailing": tok + "\n",
		"crlf":     "\r\n" + tok,
	} {
		if err := s.Open(KindAccess, in, &out); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: got %v", name, err)
		}
	}
	if err := s.Open(KindAccess, tok, &out); err != nil {
		t.Fatal(err)
	}
}

func TestNonCanonicalTrailingBits(t *testing.T) {
	s := mustNew(t, key(1))
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for n := 0; n < 8; n++ {
		tok, _ := s.Seal(KindAccess, strings.Repeat("a", n), time.Time{})
		if len(tok)%4 == 0 {
			continue
		}
		last := strings.IndexByte(alpha, tok[len(tok)-1])
		alt := tok[:len(tok)-1] + string(alpha[last^1])
		var out string
		if err := s.Open(KindAccess, alt, &out); !errors.Is(err, ErrInvalid) {
			t.Fatalf("non-canonical accepted: %v", err)
		}
		if err := s.Open(KindAccess, tok, &out); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatal("could not construct non-canonical token")
}

func TestDuplicateKeys(t *testing.T) {
	if _, err := New([][]byte{key(1), key(2), key(1)}); err == nil {
		t.Fatal("expected duplicate key error")
	}
}

// rawSeal seals an arbitrary plaintext with the primary key.
func rawSeal(s *Sealer, kind Kind, plain []byte) string {
	k := s.keys[0]
	buf := append([]byte{version}, k.id[:]...)
	nonce := make([]byte, nonceSize)
	buf = append(buf, nonce...)
	buf = k.aead.Seal(buf, nonce, plain, aad(version, k.id[:], kind))
	return base64.RawURLEncoding.EncodeToString(buf)
}

func TestErrPayload(t *testing.T) {
	s := mustNew(t, key(1))
	tok, _ := s.Seal(KindAccess, "text", time.Time{})
	var n int
	err := s.Open(KindAccess, tok, &n)
	if !errors.Is(err, ErrPayload) || errors.Is(err, ErrInvalid) || errors.Is(err, ErrExpired) {
		t.Fatalf("got %v", err)
	}
	var p payload
	if err := s.Open(KindAccess, rawSeal(s, KindAccess, []byte(`{"exp":0}`)), &p); !errors.Is(err, ErrPayload) {
		t.Fatalf("missing d: got %v", err)
	}
	if err := s.Open(KindAccess, rawSeal(s, KindAccess, []byte(`not json`)), &p); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad envelope: got %v", err)
	}
}

func TestWithClock(t *testing.T) {
	s, err := New([][]byte{key(1)}, WithClock(func() time.Time { return fixedNow }), WithClock(nil))
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := s.Seal(KindCode, 1, fixedNow.Add(time.Second))
	var v int
	if err := s.Open(KindCode, tok, &v); err != nil {
		t.Fatal(err)
	}
	s2, _ := New([][]byte{key(1)}, WithClock(func() time.Time { return fixedNow.Add(time.Minute) }))
	if err := s2.Open(KindCode, tok, &v); !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v", err)
	}
}

func TestUninitialized(t *testing.T) {
	var v int
	for name, s := range map[string]*Sealer{"nil": nil, "zero": {}} {
		if _, err := s.Seal(KindCode, 1, time.Time{}); err == nil {
			t.Fatalf("%s: Seal should fail", name)
		}
		if err := s.Open(KindCode, "abc", &v); err == nil {
			t.Fatalf("%s: Open should fail", name)
		}
	}
}

func TestOpenAs(t *testing.T) {
	s := mustNew(t, key(1))
	tok, _ := s.Seal(KindAccess, payload{"bob", 7}, time.Time{})
	got, err := OpenAs[payload](s, KindAccess, tok)
	if err != nil || got != (payload{"bob", 7}) {
		t.Fatalf("got %+v, %v", got, err)
	}
	if _, err := OpenAs[payload](s, KindCode, tok); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v", err)
	}
	if _, err := OpenAs[int](s, KindAccess, tok); !errors.Is(err, ErrPayload) {
		t.Fatalf("got %v", err)
	}
}

func TestMACRotationNonPrimary(t *testing.T) {
	a := mustNew(t, key(1), key(2))
	b := mustNew(t, key(2), key(1))
	data := []byte("d")
	mac := a.MAC("p", data) // made by key(1); non-primary in b
	if !b.VerifyMAC("p", data, mac) {
		t.Fatal("non-primary key MAC rejected")
	}
	if b.VerifyMAC("q", data, mac) {
		t.Fatal("different purpose accepted")
	}
}

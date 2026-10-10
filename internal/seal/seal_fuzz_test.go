package seal

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

var fuzzKinds = []Kind{KindClient, KindCode, KindAccess, KindRefresh, KindAuthRequest}

// fuzzKind maps an arbitrary byte to a kind; one extra slot is an unknown kind.
func fuzzKind(i uint8) Kind {
	if int(i)%(len(fuzzKinds)+1) == len(fuzzKinds) {
		return Kind("unknown-kind")
	}
	return fuzzKinds[int(i)%(len(fuzzKinds)+1)]
}

type fuzzPayload struct {
	User string `json:"user"`
	N    int    `json:"n"`
}

// Fixed tokens sealed once with keys key(1), key(2) (primary: key(1)) at the
// fixedNow clock: valid for an hour past it, or expired an hour before it.
// They are constants, not generated per run, because fuzz workers are separate
// processes that must agree on which strings are genuine.
var fuzzGenuine = []struct {
	kind           Kind
	valid, expired string
}{
	{Kind("client"), "AQF8wptM00R1Mhv7j28tqwM7IIVA7lPCzgmj-9-OdWQEsIxiPKu659HMouSZyPElrV50cTBZRuQc8j5gzRvblkgjBcPO4DE-1_8INPmy",
		"AQF8wpucte0dQBdnXZFbQ3JBXZtgZa2f3B71mBg-YFoDygdx_UsUXMBhJLu62oNLsIvFzbmTss_O3cyCjoyRO6IYjSp_wQRS3fTTpw"},
	{Kind("code"), "AQF8wpvH22hIoGkLbPaMXAxbA2-cvMRoQhmTafu_SFy0ID_h3EyivhcWP7fql0u_tddVHqtH1I6L5pA9hswxvLEzTmuDPcAobxZ2dcoq",
		"AQF8wpvfVZMi-59ykSexEm11WVycb8PzpFTAEgGsMC0LomRLD5Wu67ICFgCHZstby9rdcGDzaGWdtWzBiiaL_i0ZTY7sWeJFQgpPPw"},
	{Kind("access"), "AQF8wps2Yq1bZS60_jmMsq2bBR7trHCWY_OGol4R7mVFNc3dsts1-2rwL8DpyG9bPR2e0dSyqbYtbgPqkgrlXT05o99NWLpf5CRzCNZa",
		"AQF8wpvsuK3jy1x0lA1CaH7ofVCtpzSwMxe7FFntw0FNJiavc6JO1z-dnXpW3znSGTEDJX-JeHNtKDqv5v8aMt2Ce4E-KiiW7XMeHg"},
	{Kind("refresh"), "AQF8wptB0MUMcuWpJ2COD-GYMzaL2KDFV7b3b1yqGs3afZBfMeBHB4saETcecgj-triviFSVXiFBQsEUNWBu-DG77YcT5PITJcsi122t",
		"AQF8wptJZryQgCAl-wNxHha6ZNGW8GhejoxoA-r02uJC-HlXRKmis7dxOyItQjC_udimajTu6qU4ZNIDpx1fSrp8XCcbBz4l_oRBqw"},
	{Kind("authreq"), "AQF8wpscB8SKjltcEoJtbqrI4MlWqrY_X5aEQAbxeg8Fa9i-uEeSRHi3xzNfdwNDn_htpaCfofDDY0iI38bONucoze7JG9ApA4Uj7Fru",
		"AQF8wpv_Oio4agod8549FAsGdML1GGFs4VN_0N9hDtqE8i_vB8lJFkPZcPb6dWaFCpTDxjB65JyapwgDvACO0Z8vD5_VkFkUUTcz8w"},
}

func fuzzSealer(tb testing.TB, keys ...[]byte) *Sealer {
	tb.Helper()
	s, err := New(keys, WithClock(func() time.Time { return fixedNow }))
	if err != nil {
		tb.Fatal(err)
	}
	return s
}

// FuzzOpen feeds arbitrary strings to Open for every kind. Nothing may panic,
// and Open may succeed only for tokens this test sealed itself, and only for
// the kind they were sealed as.
func FuzzOpen(f *testing.F) {
	s := fuzzSealer(f, key(1), key(2))
	good := map[string]Kind{} // genuine unexpired tokens
	expired := map[string]Kind{}
	for _, g := range fuzzGenuine {
		good[g.valid], expired[g.expired] = g.kind, g.kind
		f.Add(uint8(0), g.valid)
		f.Add(uint8(1), g.valid)
		f.Add(uint8(2), g.expired)
	}
	for _, seed := range []string{
		"", "A", "AAAA", "=", "AQ==", "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"AQ\r\nAA", "-_-_", string(bytes.Repeat([]byte("A"), 20<<10)),
	} {
		f.Add(uint8(0), seed)
	}

	other := fuzzSealer(f, key(9)) // unrelated keys
	f.Fuzz(func(t *testing.T, kindIdx uint8, token string) {
		kind := fuzzKind(kindIdx)
		var out fuzzPayload
		err := s.Open(kind, token, &out)
		if err == nil {
			if good[token] != kind {
				t.Fatalf("Open(%q) succeeded for a token not sealed as that kind", kind)
			}
			if out.User != "alice" || out.N != 7 {
				t.Fatalf("payload = %+v", out)
			}
			return
		}
		if errors.Is(err, ErrExpired) {
			if expired[token] != kind {
				t.Fatalf("ErrExpired for a token that is not an expired %q token", kind)
			}
			return
		}
		if good[token] == kind && kind != "" {
			t.Fatalf("valid token rejected: %v", err)
		}
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("err = %v, want ErrInvalid", err)
		}
		// The generic wrapper agrees.
		if _, err2 := OpenAs[fuzzPayload](s, kind, token); err2 == nil {
			t.Fatal("OpenAs succeeded where Open failed")
		}
		// A sealer with unrelated keys accepts nothing.
		if _, err := OpenAs[fuzzPayload](other, kind, token); err == nil {
			t.Fatal("token opened under foreign keys")
		}
	})
}

// FuzzSealRoundTrip checks Seal -> Open, kind separation, key rotation and
// that no single-byte modification of a token is accepted.
func FuzzSealRoundTrip(f *testing.F) {
	f.Add(uint8(0), []byte("hello"), uint16(0), uint8(1))
	f.Add(uint8(2), []byte(`{"u":"tn"}`), uint16(40), uint8(0x80))
	f.Add(uint8(4), []byte{}, uint16(3), uint8(0xff))
	f.Add(uint8(1), bytes.Repeat([]byte{0xff}, 512), uint16(900), uint8(4))

	oldOnly := fuzzSealer(f, key(1))
	rotated := fuzzSealer(f, key(2), key(1)) // [new, old]
	newOnly := fuzzSealer(f, key(2))

	f.Fuzz(func(t *testing.T, kindIdx uint8, payload []byte, pos uint16, mask uint8) {
		kind := fuzzKind(kindIdx)
		tok, err := rotated.Seal(kind, payload, time.Time{})
		if err != nil {
			return // oversized payload
		}
		got, err := OpenAs[[]byte](rotated, kind, tok)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("round trip: got %q err %v, want %q", got, err, payload)
		}
		// Sealed under the new key: the new-only sealer opens it, the old-only one does not.
		if _, err := OpenAs[[]byte](newOnly, kind, tok); err != nil {
			t.Fatalf("new-key token rejected by new-only sealer: %v", err)
		}
		if _, err := OpenAs[[]byte](oldOnly, kind, tok); !errors.Is(err, ErrInvalid) {
			t.Fatalf("new-key token under old-only sealer: %v", err)
		}
		// A token from before the rotation still opens under [new, old].
		oldTok, err := oldOnly.Seal(kind, payload, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		if got, err := OpenAs[[]byte](rotated, kind, oldTok); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("old-key token under rotated sealer: %q %v", got, err)
		}
		if _, err := OpenAs[[]byte](newOnly, kind, oldTok); !errors.Is(err, ErrInvalid) {
			t.Fatalf("old-key token after dropping the key: %v", err)
		}
		// Never crosses kinds.
		for _, other := range append(fuzzKinds, "unknown-kind") {
			if other == kind {
				continue
			}
			if _, err := OpenAs[[]byte](rotated, other, tok); !errors.Is(err, ErrInvalid) {
				t.Fatalf("token sealed as %q opened as %q: %v", kind, other, err)
			}
		}
		// Any modification fails: a substituted character, a flipped raw bit,
		// truncation, extension and padding.
		mut := []byte(tok)
		i := int(pos) % len(mut)
		if mask == 0 {
			mask = 1
		}
		mut[i] ^= mask
		mustFail(t, rotated, kind, string(mut), "substituted char")

		raw, _ := base64.RawURLEncoding.DecodeString(tok)
		raw[int(pos)%len(raw)] ^= mask
		mustFail(t, rotated, kind, base64.RawURLEncoding.EncodeToString(raw), "flipped raw byte")
		mustFail(t, rotated, kind, tok[:len(tok)-1], "truncated")
		mustFail(t, rotated, kind, tok+"A", "extended")
		mustFail(t, rotated, kind, tok+"=", "padded")
		mustFail(t, rotated, kind, tok+"\n", "newline")
		mustFail(t, rotated, kind, "", "empty")
	})
}

func mustFail(t *testing.T, s *Sealer, kind Kind, token, what string) {
	t.Helper()
	var out []byte
	if err := s.Open(kind, token, &out); err == nil {
		t.Fatalf("%s token accepted", what)
	}
}

// TestFuzzGenuineTokens guards the constants above: each must open under its
// own kind (valid) or report expiry (expired) with the keys used by FuzzOpen.
func TestFuzzGenuineTokens(t *testing.T) {
	s := fuzzSealer(t, key(1), key(2))
	for _, g := range fuzzGenuine {
		got, err := OpenAs[fuzzPayload](s, g.kind, g.valid)
		if err != nil || got.User != "alice" || got.N != 7 {
			t.Errorf("%s: valid token: %+v %v", g.kind, got, err)
		}
		if _, err := OpenAs[fuzzPayload](s, g.kind, g.expired); !errors.Is(err, ErrExpired) {
			t.Errorf("%s: expired token: %v", g.kind, err)
		}
	}
}

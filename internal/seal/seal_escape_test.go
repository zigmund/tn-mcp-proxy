package seal

import (
	"strings"
	"testing"
	"time"
)

func TestSealDoesNotHTMLEscape(t *testing.T) {
	plain, err := marshalEnvelope(map[string]string{"k": "<a>&</a>"}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), `\u00`) || !strings.Contains(string(plain), "<a>&</a>") {
		t.Errorf("payload was HTML-escaped: %s", plain)
	}
	if strings.HasSuffix(string(plain), "\n") {
		t.Error("trailing newline kept")
	}
}

func TestSealHTMLCharsRoundTripAndFit(t *testing.T) {
	s := mustNew(t, key(1))
	in := map[string]string{"k": strings.Repeat("<>&", 3000)} // 9000 bytes, 54000 if escaped
	tok, err := s.Seal(KindCode, in, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	if err := s.Open(KindCode, tok, &out); err != nil || out["k"] != in["k"] {
		t.Fatalf("round trip: %v", err)
	}
}

func TestEncodedSizeBoundsSeal(t *testing.T) {
	s := mustNew(t, key(1))
	p := map[string]string{"k": strings.Repeat("x", 1234)}
	n, err := EncodedSize(p)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := s.Seal(KindCode, p, time.Unix(1_900_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	// The estimate assumes the widest expiry, so it is at least the real size
	// and exceeds it by a few base64 characters only.
	if n < len(tok) || n > len(tok)+20 {
		t.Errorf("EncodedSize = %d, real token = %d", n, len(tok))
	}
}

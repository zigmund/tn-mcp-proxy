package tokens

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestRedaction(t *testing.T) {
	a := Access{Upstream: "tn", ClientID: "c", Creds: map[string]string{"X-K": "topsecret"}}
	r := Refresh{Upstream: "tn", ClientID: "c", Creds: map[string]string{"X-K": "topsecret"}}

	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	log.Info("x", "a", a, "r", r)

	for _, s := range []string{
		fmt.Sprint(a), fmt.Sprintf("%v %+v %#v", a, a, a), fmt.Sprintf("%v %+v %#v", r, r, r), buf.String(),
	} {
		if strings.Contains(s, "topsecret") {
			t.Errorf("secret leaked: %s", s)
		}
	}
}

func TestJSONKeys(t *testing.T) {
	b, err := json.Marshal(Access{Upstream: "tn", ClientID: "c", Creds: map[string]string{"X-K": "v"}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), `{"u":"tn","c":"c","h":{"X-K":"v"}}`; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	b, err = json.Marshal(Refresh{Upstream: "tn", ClientID: "c", Creds: map[string]string{"X-K": "v"}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), `{"u":"tn","c":"c","h":{"X-K":"v"}}`; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

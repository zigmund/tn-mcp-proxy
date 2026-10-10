package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
)

func TestRecheckerReportsGivenVersion(t *testing.T) {
	for _, tt := range []struct{ name, version, want string }{
		{"given", "v1", "v1"},
		{"empty falls back to dev", "", "dev"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			var agents, clients []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				var m struct {
					Method string `json:"method"`
					ID     any    `json:"id"`
					Params struct {
						ClientInfo struct {
							Version string `json:"version"`
						} `json:"clientInfo"`
					} `json:"params"`
				}
				_ = json.Unmarshal(b, &m)
				mu.Lock()
				agents = append(agents, r.Header.Get("User-Agent"))
				if m.Method == "initialize" {
					clients = append(clients, m.Params.ClientInfo.Version)
				}
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				switch m.Method {
				case "notifications/initialized":
					w.WriteHeader(http.StatusAccepted)
				case "tools/call":
					_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%v,"result":{"content":[{"type":"text","text":"{}"}]}}`, m.ID)
				default:
					_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%v,"result":{"protocolVersion":"2025-06-18"}}`, m.ID)
				}
			}))
			defer srv.Close()

			rc := NewRechecker(slog.New(slog.NewTextHandler(io.Discard, nil)), WithRecheckerVersion(tt.version))
			up := config.Upstream{Name: "tn", URL: srv.URL + "/mcp",
				Validate: &config.Validate{Tool: "t", Timeout: 5 * time.Second, RecheckOnToolError: true}}
			if v := rc.recheck(context.Background(), up, map[string]string{"X-Key": "k"}); v != verdictOK {
				t.Fatalf("verdict = %v, want OK", v)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(agents) == 0 || len(clients) != 1 {
				t.Fatalf("requests = %d, initializes = %d", len(agents), len(clients))
			}
			for _, ua := range agents {
				if ua != "tn-mcp-proxy/"+tt.want {
					t.Errorf("User-Agent = %q", ua)
				}
			}
			if clients[0] != tt.want {
				t.Errorf("clientInfo.version = %q, want %q", clients[0], tt.want)
			}
		})
	}
}

package config

import (
	"strings"
	"testing"
)

func TestProxyLimitsDefaults(t *testing.T) {
	cfg, err := Parse([]byte(base()), ".")
	if err != nil {
		t.Fatal(err)
	}
	want := ProxyLimits{
		IP:                    Limit{DefaultProxyIPPerMinute, DefaultProxyIPBurst},
		Token:                 Limit{DefaultProxyTokenPerMinute, DefaultProxyTokenBurst},
		MaxConcurrentPerToken: DefaultMaxConcurrentPerTok,
		MaxInFlight:           DefaultMaxInFlight,
		MaxRequestBody:        DefaultMaxRequestBody,
	}
	if cfg.Limits != want {
		t.Errorf("Limits = %+v, want %+v", cfg.Limits, want)
	}
}

func TestProxyLimitsExplicit(t *testing.T) {
	y := base() + `
limits:
  ip: { per_minute: 10, burst: 3 }
  token: { per_minute: 20 }
  max_concurrent_per_token: 4
  max_in_flight: -1
  max_request_body: 4096
`
	cfg, err := Parse([]byte(y), ".")
	if err != nil {
		t.Fatal(err)
	}
	want := ProxyLimits{
		IP:                    Limit{10, 3},
		Token:                 Limit{20, DefaultProxyTokenBurst},
		MaxConcurrentPerToken: 4,
		MaxInFlight:           Disable,
		MaxRequestBody:        4096,
	}
	if cfg.Limits != want {
		t.Errorf("Limits = %+v, want %+v", cfg.Limits, want)
	}
}

func TestProxyLimitsDisable(t *testing.T) {
	cfg, err := Parse([]byte(base()+"\nlimits:\n  disabled: true\n"), ".")
	if err != nil {
		t.Fatal(err)
	}
	l := cfg.Limits
	if l.IP.PerMinute != Disable || l.Token.PerMinute != Disable || l.MaxConcurrentPerToken != Disable || l.MaxInFlight != Disable {
		t.Errorf("not all disabled: %+v", l)
	}
	if l.MaxRequestBody != DefaultMaxRequestBody {
		t.Errorf("body cap must stay: %d", l.MaxRequestBody)
	}

	cfg, err = Parse([]byte(base()+"\nlimits:\n  ip: { per_minute: -1 }\n"), ".")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Limits.IP.PerMinute != Disable || cfg.Limits.Token.PerMinute != DefaultProxyTokenPerMinute {
		t.Errorf("single disable: %+v", cfg.Limits)
	}
}

func TestProxyLimitsValidation(t *testing.T) {
	tests := []struct{ name, yaml, want string }{
		{"ip per_minute", "ip: { per_minute: -2 }", "limits.ip.per_minute"},
		{"ip burst", "ip: { burst: -1 }", "limits.ip.burst"},
		{"token per_minute", "token: { per_minute: -5 }", "limits.token.per_minute"},
		{"token burst", "token: { burst: -1 }", "limits.token.burst"},
		{"concurrency", "max_concurrent_per_token: -2", "limits.max_concurrent_per_token"},
		{"in flight", "max_in_flight: -3", "limits.max_in_flight"},
		{"body negative", "max_request_body: -1", "limits.max_request_body"},
		{"body tiny", "max_request_body: 10", "limits.max_request_body"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(base()+"\nlimits:\n  "+tc.yaml+"\n"), ".")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want mention of %s", err, tc.want)
			}
		})
	}
}

func TestProxyLimitsInvalidNotHiddenByDisable(t *testing.T) {
	for name, y := range map[string]string{
		"per_minute": "disabled: true\n  token: { per_minute: -5 }",
		"burst":      "disabled: true\n  ip: { per_minute: -1, burst: -3 }",
		"concurrent": "disabled: true\n  max_concurrent_per_token: -7",
		"burst only": "ip: { per_minute: -1, burst: -3 }",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(base()+"\nlimits:\n  "+y+"\n"), "."); err == nil || !strings.Contains(err.Error(), "limits.") {
				t.Errorf("err = %v, want a limits.* error", err)
			}
		})
	}
}

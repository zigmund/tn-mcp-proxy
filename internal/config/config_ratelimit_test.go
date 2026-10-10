package config

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRateLimitAndTrustedDefaults(t *testing.T) {
	cfg, err := Parse([]byte(base()), ".")
	if err != nil {
		t.Fatal(err)
	}
	rl := cfg.OAuth.RateLimit
	if rl.Disabled {
		t.Error("rate limiting must be enabled by default")
	}
	want := map[string]Limit{
		"register":  {DefaultRegisterPerMinute, DefaultRegisterBurst},
		"authorize": {DefaultAuthorizePerMinute, DefaultAuthorizeBurst},
		"token":     {DefaultTokenPerMinute, DefaultTokenBurst},
	}
	got := map[string]Limit{"register": rl.Register, "authorize": rl.Authorize, "token": rl.Token}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %+v, want %+v", k, got[k], w)
		}
	}
	if len(cfg.TrustedNets) != 2 ||
		cfg.TrustedNets[0] != netip.MustParsePrefix("127.0.0.0/8") || cfg.TrustedNets[1] != netip.MustParsePrefix("::1/128") {
		t.Errorf("TrustedNets = %v, want loopback only", cfg.TrustedNets)
	}
}

func TestRateLimitExplicit(t *testing.T) {
	y := base() + `
oauth:
  rate_limit:
    disabled: true
    register: { per_minute: 5, burst: 2 }
    token: { burst: 7 }
`
	cfg, err := Parse([]byte(y), ".")
	if err != nil {
		t.Fatal(err)
	}
	rl := cfg.OAuth.RateLimit
	if !rl.Disabled || rl.Register != (Limit{5, 2}) {
		t.Errorf("rate_limit = %+v", rl)
	}
	// Partially set: the missing value falls back to its default.
	if rl.Token != (Limit{DefaultTokenPerMinute, 7}) {
		t.Errorf("token = %+v", rl.Token)
	}
}

func TestRateLimitAuthorizeGlobal(t *testing.T) {
	cfg, err := Parse([]byte(base()), ".")
	if err != nil {
		t.Fatal(err)
	}
	// Unset stays zero: the OAuth server derives it from code_ttl.
	if g := cfg.OAuth.RateLimit.AuthorizeGlobal; g != (Limit{}) {
		t.Errorf("default authorize_global = %+v, want zero (derived)", g)
	}
	cfg, err = Parse([]byte(base()+"\noauth:\n  rate_limit:\n    authorize_global: { per_minute: 99 }\n"), ".")
	if err != nil {
		t.Fatal(err)
	}
	if g := cfg.OAuth.RateLimit.AuthorizeGlobal; g != (Limit{PerMinute: 99}) {
		t.Errorf("authorize_global = %+v", g)
	}
}

func TestRateLimitGlobalBurstNeedsPerMinute(t *testing.T) {
	_, err := Parse([]byte(base()+"\noauth:\n  rate_limit:\n    authorize_global: { burst: 5 }\n"), ".")
	if err == nil || !strings.Contains(err.Error(), "oauth.rate_limit.authorize_global.burst") {
		t.Fatalf("err = %v", err)
	}
}

func TestRateLimitNegativeRejected(t *testing.T) {
	y := base() + `
oauth:
  rate_limit:
    register: { per_minute: -1 }
    token: { burst: -5 }
    authorize_global: { per_minute: -1, burst: -2 }
`
	_, err := Parse([]byte(y), ".")
	if err == nil {
		t.Fatal("expected error")
	}
	for _, f := range []string{"oauth.rate_limit.register.per_minute", "oauth.rate_limit.token.burst",
		"oauth.rate_limit.authorize_global.per_minute", "oauth.rate_limit.authorize_global.burst"} {
		if !strings.Contains(err.Error(), f) {
			t.Errorf("error lacks %s: %v", f, err)
		}
	}
}

func TestTrustedProxiesParsing(t *testing.T) {
	y := base() + `
trusted_proxies: ["10.0.0.0/8", "192.0.2.7", " 2001:db8::1 ", "2001:db8:ffff::/48", "10.1.2.3/8"]
`
	cfg, err := Parse([]byte(y), ".")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/8", "192.0.2.7/32", "2001:db8::1/128", "2001:db8:ffff::/48", "10.0.0.0/8"}
	if len(cfg.TrustedNets) != len(want) {
		t.Fatalf("TrustedNets = %v", cfg.TrustedNets)
	}
	for i, w := range want {
		if cfg.TrustedNets[i].String() != w {
			t.Errorf("TrustedNets[%d] = %v, want %s", i, cfg.TrustedNets[i], w)
		}
	}
}

func TestTrustedProxiesInvalid(t *testing.T) {
	for _, bad := range []string{"not-an-ip", "10.0.0.0/33", "10.0.0.0/", "fe80::1%eth0", "::ffff:10.0.0.1", "::ffff:10.0.0.0/104", "", "0.0.0.0/0", "::/0"} {
		y := base() + "trusted_proxies: [\"" + bad + "\"]\n"
		_, err := Parse([]byte(y), ".")
		if err == nil {
			t.Errorf("%q accepted", bad)
			continue
		}
		if !strings.Contains(err.Error(), "trusted_proxies[0]") {
			t.Errorf("%q: error lacks field path: %v", bad, err)
		}
	}
}

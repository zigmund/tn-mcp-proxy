package config

import (
	"strings"
	"testing"
	"time"
)

func TestTTLUpperBounds(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{"code ttl at max", "oauth: {code_ttl: 10m}\n", ""},
		{"code ttl above max", "oauth: {code_ttl: 10m1s}\n", "oauth.code_ttl"},
		{"code ttl far above max", "oauth: {code_ttl: 720h}\n", "oauth.code_ttl"},
		{"access ttl at max", "oauth: {access_token_ttl: 24h}\n", ""},
		{"access ttl above max", "oauth: {access_token_ttl: 25h}\n", "oauth.access_token_ttl"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(base()+tt.yaml), ".")
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) || !strings.Contains(err.Error(), "maximum") {
				t.Fatalf("err = %v, want a maximum error for %s", err, tt.wantErr)
			}
		})
	}
}

func TestTTLDefaultsWithinBounds(t *testing.T) {
	if DefaultCodeTTL > MaxCodeTTL || DefaultAccessTokenTTL > MaxAccessTokenTTL {
		t.Fatal("defaults exceed the maximums")
	}
	if MaxCodeTTL != 10*time.Minute || MaxAccessTokenTTL != 24*time.Hour {
		t.Fatalf("bounds changed: %v %v", MaxCodeTTL, MaxAccessTokenTTL)
	}
}

func TestAuthorizeFormRateLimitDefaultsAndValidation(t *testing.T) {
	cfg, err := Parse([]byte(base()), ".")
	if err != nil {
		t.Fatal(err)
	}
	l := cfg.OAuth.RateLimit.AuthorizeForm
	if l.PerMinute != DefaultAuthorizeFormPerMinute || l.Burst != DefaultAuthorizeFormBurst {
		t.Errorf("default authorize_form = %+v", l)
	}
	if l.PerMinute <= cfg.OAuth.RateLimit.Authorize.PerMinute {
		t.Errorf("authorize_form default %d is not above the POST limit %d", l.PerMinute, cfg.OAuth.RateLimit.Authorize.PerMinute)
	}
	_, err = Parse([]byte(base()+"oauth: {rate_limit: {authorize_form: {per_minute: -1}}}\n"), ".")
	if err == nil || !strings.Contains(err.Error(), "authorize_form.per_minute") {
		t.Errorf("negative authorize_form: err = %v", err)
	}
}

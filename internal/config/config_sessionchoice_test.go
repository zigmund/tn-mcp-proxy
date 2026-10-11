package config

import (
	"strings"
	"testing"
	"time"
)

func parseOAuth(t *testing.T, oauth string) (*Config, error) {
	t.Helper()
	return Parse([]byte(base()+"oauth: {"+oauth+"}\n"), ".")
}

func TestSessionChoicesValid(t *testing.T) {
	cfg, err := parseOAuth(t, "session_choices: [720h, 2160h, 8760h, unlimited], session_default: 2160h")
	if err != nil {
		t.Fatal(err)
	}
	o := cfg.OAuth
	var got []string
	for _, c := range o.Sessions {
		got = append(got, c.String())
	}
	if strings.Join(got, ",") != "720h,2160h,8760h,unlimited" {
		t.Errorf("Sessions = %v", got)
	}
	if o.DefaultSession.String() != "2160h" || o.DefaultSession.Duration != 2160*time.Hour {
		t.Errorf("DefaultSession = %+v", o.DefaultSession)
	}
	if o.MaxSessionTTL != DefaultMaxSessionTTL {
		t.Errorf("max_session_ttl must keep its default: %v", o.MaxSessionTTL)
	}

	// The default falls back to the first entry, and may be the unlimited one.
	cfg, err = parseOAuth(t, "session_choices: [48h, unlimited]")
	if err != nil || cfg.OAuth.DefaultSession.String() != "48h" {
		t.Errorf("default = %+v, err = %v", cfg.OAuth.DefaultSession, err)
	}
	cfg, err = parseOAuth(t, "session_choices: [48h, unlimited], session_default: unlimited")
	if err != nil || !cfg.OAuth.DefaultSession.Unlimited {
		t.Errorf("default = %+v, err = %v", cfg.OAuth.DefaultSession, err)
	}

	// Other spellings of an hour count are accepted and canonicalised.
	cfg, err = parseOAuth(t, "session_choices: [1h, 1440m], session_default: 24h")
	if err != nil || cfg.OAuth.Sessions[1].String() != "24h" || cfg.OAuth.DefaultSession.String() != "24h" {
		t.Errorf("sessions = %+v, err = %v", cfg.OAuth.Sessions, err)
	}

	// Exactly the maximum number of entries.
	cfg, err = parseOAuth(t, "session_choices: [1h, 2h, 3h, 4h, 5h, 6h, 7h, unlimited]")
	if err != nil || len(cfg.OAuth.Sessions) != MaxSessionChoices {
		t.Errorf("len = %d, err = %v", len(cfg.OAuth.Sessions), err)
	}
}

func TestSessionChoicesUnset(t *testing.T) {
	cfg, err := Parse([]byte(base()), ".")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OAuth.Sessions != nil || cfg.OAuth.DefaultSession != (SessionChoice{}) {
		t.Errorf("choices appeared from nowhere: %+v %+v", cfg.OAuth.Sessions, cfg.OAuth.DefaultSession)
	}
	if cfg.OAuth.MaxSessionTTL != DefaultMaxSessionTTL {
		t.Errorf("max_session_ttl = %v", cfg.OAuth.MaxSessionTTL)
	}
}

func TestSessionChoicesInvalid(t *testing.T) {
	nine := "session_choices: [1h, 2h, 3h, 4h, 5h, 6h, 7h, 8h, 9h]"
	for _, tc := range []struct{ name, oauth, want string }{
		{"duplicate", "session_choices: [720h, 720h]", "oauth.session_choices[1]: duplicates [0]"},
		{"duplicate spelling", "session_choices: [720h, 43200m]", "oauth.session_choices[1]: duplicates [0]"},
		{"duplicate unlimited", "session_choices: [unlimited, 24h, unlimited]", "oauth.session_choices[2]: duplicates [0]"},
		{"too many", nine, "9 entries, at most 8"},
		{"below minimum", "session_choices: [30m]", "oauth.session_choices[0]"},
		{"zero", "session_choices: [0s]", "shorter than the minimum"},
		{"negative", "session_choices: [-24h]", "shorter than the minimum"},
		{"fraction of an hour", "session_choices: [90m]", "whole number of hours"},
		{"d unit", "session_choices: [30d]", "no d unit"},
		{"bad literal", "session_choices: [forever]", "oauth.session_choices[0]"},
		{"literal case", "session_choices: [Unlimited]", "oauth.session_choices[0]"},
		{"no unit", "session_choices: [720]", "oauth.session_choices[0]"},
		{"default not listed", "session_choices: [720h], session_default: 24h", "oauth.session_default: 24h is not one of oauth.session_choices"},
		{"unlimited default not listed", "session_choices: [720h], session_default: unlimited", "oauth.session_default: unlimited is not one of"},
		{"bad default", "session_choices: [720h], session_default: forever", "oauth.session_default"},
		{"default without choices", "session_default: 720h", "oauth.session_default: requires oauth.session_choices"},
		{"default with empty choices", "session_choices: [], session_default: 720h", "oauth.session_default: requires oauth.session_choices"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseOAuth(t, tc.oauth)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q (cfg %v)", err, tc.want, cfg != nil)
			}
		})
	}
}

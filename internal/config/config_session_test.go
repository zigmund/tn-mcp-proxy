package config

import (
	"strings"
	"testing"
	"time"
)

func TestMaxSessionTTL(t *testing.T) {
	cfg, err := Parse([]byte(base()), ".")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OAuth.MaxSessionTTL != 2160*time.Hour || DefaultMaxSessionTTL != 2160*time.Hour {
		t.Errorf("default max_session_ttl = %v", cfg.OAuth.MaxSessionTTL)
	}

	cfg, err = Parse([]byte(base()+"oauth: {max_session_ttl: 48h}\n"), ".")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OAuth.MaxSessionTTL != 48*time.Hour {
		t.Errorf("explicit max_session_ttl = %v", cfg.OAuth.MaxSessionTTL)
	}

	_, err = Parse([]byte(base()+"oauth: {max_session_ttl: -1h}\n"), ".")
	if err == nil || !strings.Contains(err.Error(), "oauth.max_session_ttl") {
		t.Errorf("negative max_session_ttl: err = %v", err)
	}
}

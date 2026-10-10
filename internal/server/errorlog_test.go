package server

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestErrorLogLevels(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	el := newErrorLog(l)
	el.Printf("http: TLS handshake error from 192.0.2.1:1234: EOF")
	el.Printf("http: panic serving 192.0.2.1:1234: boom")

	var hs, other string
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if strings.Contains(line, "TLS handshake error") {
			hs = line
		} else {
			other = line
		}
	}
	if !strings.Contains(hs, "level=DEBUG") {
		t.Errorf("handshake error line = %q, want debug", hs)
	}
	if !strings.Contains(other, "level=WARN") || !strings.Contains(other, "panic serving") {
		t.Errorf("other line = %q, want warn", other)
	}
}

func TestErrorLogHandshakeHiddenAtInfo(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	el := newErrorLog(l)
	for range 100 {
		el.Printf("http: TLS handshake error from 192.0.2.1:1234: EOF")
	}
	if buf.Len() != 0 {
		t.Errorf("handshake errors leaked at info level: %q", buf.String())
	}
	el.Printf("http: Accept error: boom; retrying")
	if !strings.Contains(buf.String(), "Accept error") {
		t.Errorf("non-handshake line missing: %q", buf.String())
	}
}

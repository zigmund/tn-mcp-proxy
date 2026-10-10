package server

import (
	"context"
	"log"
	"log/slog"
	"strings"
)

// tlsHandshakeErrorPrefix starts every line net/http writes for a failed TLS
// handshake (port scanners, plain-HTTP clients, aborted connections).
const tlsHandshakeErrorPrefix = "http: TLS handshake error"

// errorLogWriter routes http.Server.ErrorLog lines into slog. Handshake
// failures are triggered by anyone who can open a TCP connection, so they go
// to debug and cannot flood the logs in built-in TLS mode; everything else
// (panics in handlers, accept errors) stays at warn.
type errorLogWriter struct{ log *slog.Logger }

func (w errorLogWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\r\n")
	level := slog.LevelWarn
	if strings.HasPrefix(msg, tlsHandshakeErrorPrefix) {
		level = slog.LevelDebug
	}
	w.log.Log(context.Background(), level, msg)
	return len(p), nil
}

// newErrorLog returns the logger for http.Server.ErrorLog.
func newErrorLog(l *slog.Logger) *log.Logger {
	return log.New(errorLogWriter{l}, "", 0)
}

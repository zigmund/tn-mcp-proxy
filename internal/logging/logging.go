// Package logging builds the process-wide slog logger from config.
package logging

import (
	"io"
	"log/slog"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
)

// New returns a logger writing to w in cfg.Format ("text", otherwise JSON)
// at cfg.SlogLevel(). cfg is assumed to be validated by config.Load/Parse;
// unknown values fall back to JSON and info.
func New(cfg config.Log, w io.Writer) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.SlogLevel()}
	if cfg.Format == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}

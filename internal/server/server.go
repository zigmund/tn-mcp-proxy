// Package server assembles the HTTP service: the OAuth endpoints, one proxy
// handler per upstream and /healthz, wrapped in the access log, plus the
// http.Server lifecycle (timeouts, graceful shutdown, reload signals).
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/httplog"
	"github.com/zigmund/tn-mcp-proxy/internal/oauth"
	"github.com/zigmund/tn-mcp-proxy/internal/proxy"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
)

const (
	// PathHealthz is the liveness endpoint.
	PathHealthz = "/healthz"

	// ReadHeaderTimeout bounds how long a client may take to send request
	// headers (slowloris protection). It does not limit body or response.
	ReadHeaderTimeout = 10 * time.Second

	// IdleTimeout closes keep-alive connections that sit idle. It is above
	// nginx's default upstream keepalive timeout (60s) so nginx, not this
	// server, decides when to drop a reused connection.
	IdleTimeout = 120 * time.Second

	// MaxHeaderBytes caps request headers. Credential values are limited to
	// 4096 bytes each (maxCredLen); a bearer token sealing 3 maximal values
	// is about 17 KiB, so 64 KiB leaves ample headroom for the other headers
	// while staying well below the 1 MiB net/http default.
	MaxHeaderBytes = 64 << 10

	// ShutdownTimeout is how long graceful shutdown waits for in-flight
	// requests. Long-lived SSE streams never finish on their own, so after
	// this the remaining connections are closed forcibly.
	ShutdownTimeout = 15 * time.Second
)

// There is deliberately no ReadTimeout and no WriteTimeout: both are absolute
// deadlines on the whole request/response and would kill SSE streams and slow
// tool calls. The proxy transport applies its own upstream timeouts.

// Server is the assembled HTTP service.
type Server struct {
	http            *http.Server
	log             *slog.Logger
	shutdownTimeout time.Duration

	mu      sync.Mutex
	reloads []reloadHook
}

type reloadHook struct {
	name string
	fn   func() error
}

// New builds the handler tree and http.Server for cfg. It does not listen.
func New(cfg *config.Config, sealer *seal.Sealer, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	h, err := Handler(cfg, sealer, log)
	if err != nil {
		return nil, err
	}
	return &Server{
		http: &http.Server{
			Handler:           h,
			ReadHeaderTimeout: ReadHeaderTimeout,
			IdleTimeout:       IdleTimeout,
			MaxHeaderBytes:    MaxHeaderBytes,
			ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		},
		log:             log,
		shutdownTimeout: ShutdownTimeout,
	}, nil
}

// Handler returns the full request handler: GET/HEAD /healthz (unlogged, so
// probes do not flood the debug access log) and everything else behind httplog.
func Handler(cfg *config.Config, sealer *seal.Sealer, log *slog.Logger) (http.Handler, error) {
	inner := http.NewServeMux()
	oauth.New(cfg, sealer, log).Register(inner)
	for _, up := range cfg.Upstreams {
		ph, err := proxy.New(up, cfg.PublicURL, sealer, log)
		if err != nil {
			return nil, fmt.Errorf("upstream %q: %w", up.Name, err)
		}
		// Exact pattern (no trailing slash): ServeMux then matches only this
		// path; /path/ and /path/x fall through to 404.
		inner.Handle(up.Path, ph)
	}

	logged := httplog.Middleware(log, inner)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == PathHealthz && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			healthz(w, r)
			return
		}
		// Everything else, including ServeMux redirects for non-clean paths,
		// is access-logged. Other methods on /healthz get the mux 404.
		logged.ServeHTTP(w, r)
	}), nil
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte("ok"))
}

// Handler returns the server's root handler (for tests).
func (s *Server) Handler() http.Handler { return s.http.Handler }

// OnReload registers a hook run on every reload request (SIGHUP). Hooks run
// sequentially in registration order; an error is logged and does not stop
// the others. Later tasks (TLS certificate reload) plug in here.
func (s *Server) OnReload(name string, fn func() error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reloads = append(s.reloads, reloadHook{name: name, fn: fn})
}

// Reload runs the registered reload hooks, or logs that there is nothing to
// reload.
func (s *Server) Reload() {
	s.mu.Lock()
	hooks := append([]reloadHook(nil), s.reloads...)
	s.mu.Unlock()
	if len(hooks) == 0 {
		s.log.Info("reload requested, nothing to reload")
		return
	}
	for _, h := range hooks {
		if err := h.fn(); err != nil {
			s.log.Error("reload failed", "hook", h.name, "error", err)
			continue
		}
		s.log.Info("reloaded", "hook", h.name)
	}
}

// WatchReload calls Reload for every value received on sigs until ctx is done
// or sigs is closed. Run it in its own goroutine.
func (s *Server) WatchReload(ctx context.Context, sigs <-chan os.Signal) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-sigs:
			if !ok {
				return
			}
			s.Reload()
		}
	}
}

// Serve accepts connections on ln until ctx is cancelled, then shuts down
// gracefully. If in-flight requests (e.g. SSE streams) outlive the shutdown
// timeout, remaining connections are closed and Serve still returns nil.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	errc := make(chan error, 1)
	go func() { errc <- s.http.Serve(ln) }()

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serving: %w", err)
	case <-ctx.Done():
	}

	s.log.Info("shutting down", "timeout", s.shutdownTimeout.String())
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.shutdownTimeout)
	defer cancel()
	if err := s.http.Shutdown(sctx); err != nil {
		s.log.Warn("graceful shutdown timed out, closing connections", "error", err)
		if cerr := s.http.Close(); cerr != nil {
			s.log.Warn("closing server", "error", cerr)
		}
	}
	// Serve returns ErrServerClosed immediately once Shutdown/Close started.
	<-errc
	return nil
}

// Command tn-mcp-proxy is an OAuth 2.1 authorization server and resource
// server that reverse-proxies MCP traffic to header-authenticated upstreams.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/logging"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
	"github.com/zigmund/tn-mcp-proxy/internal/server"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

const defaultConfigPath = "/etc/tn-mcp-proxy/config.yaml"

var errTLSNotImplemented = errors.New("tls: TLS termination not implemented yet; remove tls.cert_file/tls.key_file and terminate TLS in nginx")

// errUsage marks an error that was already reported (bad command line).
var errUsage = errors.New("invalid command line")

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if !errors.Is(err, errUsage) {
			fmt.Fprintf(os.Stderr, "tn-mcp-proxy: %v\n", err)
		}
		os.Exit(1)
	}
}

// hooks are optional injection points for execute.
type hooks struct {
	reload <-chan os.Signal // reload requests (SIGHUP in production)
	ready  func(net.Addr)   // called with the bound address once listening
	stop   func()           // called once shutdown begins (restores default signal handling)
}

// run wires OS signals to execute: SIGINT/SIGTERM cancel the context (graceful
// shutdown), SIGHUP is delivered as a reload request and never kills the
// process.
func run(args []string, stdout, stderr io.Writer) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	return execute(ctx, args, stdout, stderr, hooks{reload: hup, stop: stop})
}

// execute is the testable entry point. It serves until ctx is cancelled.
// see hooks for the optional injection points.
func execute(ctx context.Context, args []string, stdout, stderr io.Writer, h hooks) error {
	fs := flag.NewFlagSet("tn-mcp-proxy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath, "path to YAML config file")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil // usage already printed
		}
		return errUsage // flag package already printed the error
	}

	if *showVersion {
		_, err := fmt.Fprintln(stdout, version)
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	if cfg.TLSEnabled() {
		return errTLSNotImplemented // fail fast rather than silently serve plain HTTP
	}

	log := logging.New(cfg.Log, stderr)
	sealer, err := seal.New(cfg.Secrets.Keys)
	if err != nil {
		return fmt.Errorf("initializing token sealer: %w", err)
	}
	srv, err := server.New(cfg, sealer, log)
	if err != nil {
		return fmt.Errorf("building server: %w", err)
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", cfg.Listen, err)
	}

	ups := make([]string, 0, len(cfg.Upstreams))
	for _, u := range cfg.Upstreams {
		ups = append(ups, u.Name+"="+u.Path)
	}
	log.Info("starting",
		"version", version,
		"listen", ln.Addr().String(),
		"public_url", cfg.PublicURL,
		"upstreams", ups,
	)
	if h.ready != nil {
		h.ready(ln.Addr())
	}

	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go srv.WatchReload(wctx, h.reload)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-wctx.Done() // ctx cancelled, or Serve returned and cancel ran
		if ctx.Err() == nil {
			return
		}
		log.Info("shutdown signal received; send it again to force exit")
		if h.stop != nil {
			h.stop() // a second SIGINT/SIGTERM now kills the process
		}
	}()

	err = srv.Serve(ctx, ln)
	cancel()
	<-stopped
	if err != nil {
		return err
	}
	log.Info("stopped")
	return nil
}

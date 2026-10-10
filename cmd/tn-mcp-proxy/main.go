// Command tn-mcp-proxy is an OAuth 2.1 authorization server and resource
// server that reverse-proxies MCP traffic to header-authenticated upstreams.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

const defaultConfigPath = "/etc/tn-mcp-proxy/config.yaml"

var errNotImplemented = errors.New("service not implemented yet")

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "tn-mcp-proxy: %v\n", err)
		os.Exit(1)
	}
}

// run is the testable entry point: it parses args and starts the service.
func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("tn-mcp-proxy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath, "path to YAML config file")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *showVersion {
		_, err := fmt.Fprintln(stdout, version)
		return err
	}

	logger := slog.New(slog.NewTextHandler(stderr, nil))
	logger.Info("starting", "version", version, "config", *configPath)

	return errNotImplemented
}

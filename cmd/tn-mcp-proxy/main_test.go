package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testConfig = `
listen: 127.0.0.1:0
public_url: https://mcp.example.com
log: {level: info, format: text}
secrets:
  token_keys: ["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="]
upstreams:
  - name: tn
    path: /tn/mcp
    url: https://upstream.example.com/mcp
    credentials:
      - { header: X-Key, label: Key }
`

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVersion(t *testing.T) {
	var out bytes.Buffer
	if err := execute(context.Background(), []string{"-version"}, &out, &out, hooks{}); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != version {
		t.Errorf("got %q", out.String())
	}
}

func TestStartServeShutdown(t *testing.T) {
	cfg := writeConfig(t, testConfig)
	var stderr syncBuffer
	var stopped atomic.Int32
	addrc := make(chan net.Addr, 1)
	hup := make(chan os.Signal, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- execute(ctx, []string{"-config", cfg}, &stderr, &stderr, hooks{reload: hup, ready: func(a net.Addr) { addrc <- a }, stop: func() { stopped.Add(1) }})
	}()

	var addr net.Addr
	select {
	case addr = <-addrc:
	case err := <-done:
		t.Fatalf("exited early: %v\n%s", err, stderr.String())
	case <-time.After(5 * time.Second):
		t.Fatal("not ready")
	}

	resp, err := http.Get("http://" + addr.String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("healthz %d", resp.StatusCode)
	}

	// SIGHUP hook: delivered through the injected channel, process keeps serving.
	hup <- os.Interrupt
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(stderr.String(), "nothing to reload") {
		if time.Now().After(deadline) {
			t.Fatalf("reload not handled:\n%s", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	resp, err = http.Get("http://" + addr.String() + "/healthz")
	if err != nil {
		t.Fatalf("server died after reload: %v", err)
	}
	_ = resp.Body.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no shutdown")
	}
	if stopped.Load() != 1 {
		t.Errorf("stop hook calls = %d, want 1", stopped.Load())
	}
	logs := stderr.String()
	for _, want := range []string{"version=", "public_url=https://mcp.example.com", "tn=/tn/mcp"} {
		if !strings.Contains(logs, want) {
			t.Errorf("startup log missing %q:\n%s", want, logs)
		}
	}
	if strings.Contains(logs, "AAECAwQF") {
		t.Error("key material in logs")
	}
}

func TestAddressInUse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	cfg := writeConfig(t, strings.Replace(testConfig, "127.0.0.1:0", ln.Addr().String(), 1))
	var stderr syncBuffer
	err = execute(context.Background(), []string{"-config", cfg}, &stderr, &stderr, hooks{})
	if err == nil || !strings.Contains(err.Error(), "listening on") {
		t.Fatalf("err = %v", err)
	}
}

func TestTLSStartupFailsFast(t *testing.T) {
	dir := t.TempDir()
	for name, files := range map[string][2]string{
		"missing": {"nope.pem", "nope-key.pem"},
		"garbage": {"c.pem", "k.pem"},
	} {
		if name == "garbage" {
			for _, f := range files {
				if err := os.WriteFile(filepath.Join(dir, f), []byte("junk"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		cfg := writeConfig(t, testConfig+"tls:\n  cert_file: "+filepath.Join(dir, files[0])+"\n  key_file: "+filepath.Join(dir, files[1])+"\n")
		var stderr syncBuffer
		err := execute(context.Background(), []string{"-config", cfg}, &stderr, &stderr, hooks{})
		if err == nil || !strings.Contains(err.Error(), "loading tls certificate") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func writeCert(t *testing.T, dir, cn string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	c := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	k := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})
	cp, kp := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if err := os.WriteFile(cp, c, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, k, 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	for _, p := range []string{cp, kp} {
		if err := os.Chtimes(p, future, future); err != nil {
			t.Fatal(err)
		}
		future = future.Add(time.Hour)
	}
}

func peerCN(t *testing.T, addr string) string {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test: self-signed
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	return conn.ConnectionState().PeerCertificates[0].Subject.CommonName
}

func TestServeTLSWithSIGHUPReload(t *testing.T) {
	dir := t.TempDir()
	writeCert(t, dir, "cert-a")
	cfg := writeConfig(t, testConfig+"tls:\n  cert_file: "+filepath.Join(dir, "c.pem")+"\n  key_file: "+filepath.Join(dir, "k.pem")+"\n")
	var stderr syncBuffer
	addrc := make(chan net.Addr, 1)
	hup := make(chan os.Signal, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- execute(ctx, []string{"-config", cfg}, &stderr, &stderr, hooks{reload: hup, ready: func(a net.Addr) { addrc <- a }})
	}()
	var addr net.Addr
	select {
	case addr = <-addrc:
	case err := <-done:
		t.Fatalf("exited early: %v\n%s", err, stderr.String())
	case <-time.After(5 * time.Second):
		t.Fatal("not ready")
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // test: self-signed
	resp, err := client.Get("https://" + addr.String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("healthz %d", resp.StatusCode)
	}
	if got := peerCN(t, addr.String()); got != "cert-a" {
		t.Fatalf("CN = %q", got)
	}

	writeCert(t, dir, "cert-b")
	hup <- os.Interrupt
	deadline := time.Now().Add(5 * time.Second)
	for peerCN(t, addr.String()) != "cert-b" {
		if time.Now().After(deadline) {
			t.Fatalf("cert not reloaded:\n%s", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	client.CloseIdleConnections()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown returned %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("no shutdown")
	}
}

func TestServeTLSWatcherReload(t *testing.T) {
	dir := t.TempDir()
	writeCert(t, dir, "cert-a")
	cfg := writeConfig(t, testConfig+"tls:\n  cert_file: "+filepath.Join(dir, "c.pem")+"\n  key_file: "+filepath.Join(dir, "k.pem")+"\n  reload_interval: 20ms\n")
	var stderr syncBuffer
	addrc := make(chan net.Addr, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- execute(ctx, []string{"-config", cfg}, &stderr, &stderr, hooks{ready: func(a net.Addr) { addrc <- a }})
	}()
	var addr net.Addr
	select {
	case addr = <-addrc:
	case err := <-done:
		t.Fatalf("exited early: %v\n%s", err, stderr.String())
	case <-time.After(5 * time.Second):
		t.Fatal("not ready")
	}
	if got := peerCN(t, addr.String()); got != "cert-a" {
		t.Fatalf("CN = %q", got)
	}
	writeCert(t, dir, "cert-b") // no SIGHUP: the periodic watcher must notice
	deadline := time.Now().Add(5 * time.Second)
	for peerCN(t, addr.String()) != "cert-b" {
		if time.Now().After(deadline) {
			t.Fatalf("cert not reloaded:\n%s", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("no shutdown")
	}
}

func TestMissingConfig(t *testing.T) {
	var stderr syncBuffer
	err := execute(context.Background(), []string{"-config", "/nonexistent.yaml"}, &stderr, &stderr, hooks{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExampleConfigLoads(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "listen: 127.0.0.1:8787") {
		t.Fatal("example config no longer sets listen: 127.0.0.1:8787; update this test")
	}
	cfg := writeConfig(t, strings.Replace(string(raw), "listen: 127.0.0.1:8787", "listen: 127.0.0.1:0", 1))

	var stderr syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	readyc := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- execute(ctx, []string{"-config", cfg}, &stderr, &stderr, hooks{ready: func(net.Addr) { close(readyc) }})
	}()
	select {
	case <-readyc:
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	case err := <-done:
		t.Fatalf("example config failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestFlags(t *testing.T) {
	var stderr syncBuffer
	if err := execute(context.Background(), []string{"-h"}, &stderr, &stderr, hooks{}); err != nil {
		t.Errorf("-h returned %v, want nil", err)
	}
	stderr = syncBuffer{}
	err := execute(context.Background(), []string{"-bogus"}, &stderr, &stderr, hooks{})
	if !errors.Is(err, errUsage) {
		t.Errorf("err = %v, want errUsage", err)
	}
	if n := strings.Count(stderr.String(), "flag provided but not defined"); n != 1 {
		t.Errorf("flag error printed %d times:\n%s", n, stderr.String())
	}
}

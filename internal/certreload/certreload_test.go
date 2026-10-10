package certreload

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
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func testLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, nil))
}

// genPair returns PEM-encoded cert and key for a self-signed cert with the CN.
func genPair(t *testing.T, cn string, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
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
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// serverCN dials a TLS server using r and returns the CN of the presented leaf.
func serverCN(t *testing.T, r *Reloader) string {
	t.Helper()
	cfg := &tls.Config{GetCertificate: r.GetCertificate}
	c, s := net.Pipe()
	defer func() { _ = c.Close() }()
	go func() {
		srv := tls.Server(s, cfg)
		_ = srv.Handshake()
		_ = srv.Close()
	}()
	cli := tls.Client(c, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test: self-signed
	if err := cli.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return cli.ConnectionState().PeerCertificates[0].Subject.CommonName
}

func setup(t *testing.T) (dir, certPath, keyPath string, logs *syncBuf, r *Reloader) {
	t.Helper()
	dir = t.TempDir()
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	c, k := genPair(t, "cert-a", time.Now().Add(90*24*time.Hour))
	write(t, certPath, c)
	write(t, keyPath, k)
	logs = &syncBuf{}
	r, err := New(certPath, keyPath, testLogger(logs))
	if err != nil {
		t.Fatal(err)
	}
	return dir, certPath, keyPath, logs, r
}

func TestLoadAndReload(t *testing.T) {
	_, certPath, keyPath, logs, r := setup(t)
	if got := serverCN(t, r); got != "cert-a" {
		t.Fatalf("CN = %q", got)
	}
	if cert, _ := r.GetCertificate(nil); cert.Leaf == nil {
		t.Error("Leaf not set")
	}
	if !strings.Contains(logs.String(), "tls certificate loaded") || !strings.Contains(logs.String(), "not_after=") {
		t.Errorf("load not logged: %s", logs.String())
	}

	// Unchanged files: Check is a no-op.
	before := strings.Count(logs.String(), "tls certificate loaded")
	if err := r.Check(); err != nil {
		t.Fatal(err)
	}
	if strings.Count(logs.String(), "tls certificate loaded") != before {
		t.Error("unchanged files were reloaded")
	}

	c, k := genPair(t, "cert-b", time.Now().Add(90*24*time.Hour))
	write(t, certPath, c)
	write(t, keyPath, k)
	if err := r.Check(); err != nil {
		t.Fatal(err)
	}
	if got := serverCN(t, r); got != "cert-b" {
		t.Fatalf("after reload CN = %q", got)
	}

	// Forced Reload (SIGHUP) works even when nothing changed.
	if err := r.Reload(); err != nil {
		t.Fatal(err)
	}
}

func TestSymlinkSwap(t *testing.T) {
	dir := t.TempDir()
	// letsencrypt layout: live/ symlinks point into archive/ versions.
	arch, live := filepath.Join(dir, "archive"), filepath.Join(dir, "live")
	for _, d := range []string{arch, live} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for i, cn := range []string{"v1", "v2"} {
		c, k := genPair(t, cn, time.Now().Add(90*24*time.Hour))
		n := string(rune('1' + i))
		write(t, filepath.Join(arch, "fullchain"+n+".pem"), c)
		write(t, filepath.Join(arch, "privkey"+n+".pem"), k)
	}
	link := func(n string) {
		for _, p := range [][2]string{{"fullchain", "fullchain" + n + ".pem"}, {"privkey", "privkey" + n + ".pem"}} {
			tmp := filepath.Join(live, p[0]+".tmp")
			_ = os.Remove(tmp)
			if err := os.Symlink(filepath.Join("..", "archive", p[1]), tmp); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(tmp, filepath.Join(live, p[0]+".pem")); err != nil {
				t.Fatal(err)
			}
		}
	}
	link("1")
	r, err := New(filepath.Join(live, "fullchain.pem"), filepath.Join(live, "privkey.pem"), testLogger(io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	if got := serverCN(t, r); got != "v1" {
		t.Fatalf("CN = %q", got)
	}
	link("2")
	if err := r.Check(); err != nil {
		t.Fatal(err)
	}
	if got := serverCN(t, r); got != "v2" {
		t.Fatalf("after swap CN = %q", got)
	}
}

func TestBrokenPairKeepsOld(t *testing.T) {
	_, certPath, keyPath, logs, r := setup(t)
	goodCert, _ := os.ReadFile(certPath)
	goodKey, _ := os.ReadFile(keyPath)

	// Mismatched: new cert with the old key.
	c, _ := genPair(t, "cert-b", time.Now().Add(90*24*time.Hour))
	write(t, certPath, c)
	if err := r.Check(); err == nil {
		t.Fatal("mismatched pair accepted")
	}
	if got := serverCN(t, r); got != "cert-a" {
		t.Fatalf("CN = %q, want cert-a", got)
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "reload failed") {
		t.Errorf("no warning: %s", logs.String())
	}

	// Half-written: truncated key.
	write(t, certPath, goodCert)
	write(t, keyPath, goodKey[:len(goodKey)/2])
	if err := r.Check(); err == nil {
		t.Fatal("truncated key accepted")
	}
	// Missing file.
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := r.Check(); err == nil {
		t.Fatal("missing key accepted")
	}
	if got := serverCN(t, r); got != "cert-a" {
		t.Fatalf("CN = %q, want cert-a", got)
	}

	// A good pair arrives later: retried and picked up.
	c2, k2 := genPair(t, "cert-c", time.Now().Add(90*24*time.Hour))
	write(t, certPath, c2)
	write(t, keyPath, k2)
	if err := r.Check(); err != nil {
		t.Fatal(err)
	}
	if got := serverCN(t, r); got != "cert-c" {
		t.Fatalf("CN = %q, want cert-c", got)
	}
}

func TestStartupFailures(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(filepath.Join(dir, "no.pem"), filepath.Join(dir, "nok.pem"), nil); err == nil {
		t.Error("missing files accepted")
	}
	write(t, filepath.Join(dir, "c.pem"), []byte("junk"))
	write(t, filepath.Join(dir, "k.pem"), []byte("junk"))
	if _, err := New(filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem"), nil); err == nil {
		t.Error("garbage accepted")
	}
}

func TestExpiryWarning(t *testing.T) {
	dir := t.TempDir()
	c, k := genPair(t, "soon", time.Now().Add(48*time.Hour))
	write(t, filepath.Join(dir, "c.pem"), c)
	write(t, filepath.Join(dir, "k.pem"), k)
	logs := &syncBuf{}
	if _, err := New(filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem"), testLogger(logs)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "expires soon") {
		t.Errorf("no expiry warning: %s", logs.String())
	}
}

func TestWatchWarnsDailyNearExpiry(t *testing.T) {
	dir := t.TempDir()
	c, k := genPair(t, "soon", time.Now().Add(48*time.Hour))
	write(t, filepath.Join(dir, "c.pem"), c)
	write(t, filepath.Join(dir, "k.pem"), k)
	logs := &syncBuf{}
	r, err := New(filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem"), testLogger(logs))
	if err != nil {
		t.Fatal(err)
	}
	count := func() int { return strings.Count(logs.String(), "expires soon") }
	now := time.Now()
	r.now = func() time.Time { return now }
	r.warnExpiry() // load warned moments ago in real time; clock is injected now
	base := count()
	r.warnExpiry()
	if count() != base {
		t.Error("warned twice within a day")
	}
	now = now.Add(25 * time.Hour)
	r.warnExpiry()
	if count() != base+1 {
		t.Errorf("no daily re-warn: %d vs %d", count(), base)
	}
}

func TestSameSizeSameMtimeReplacementDetected(t *testing.T) {
	_, certPath, keyPath, _, r := setup(t)
	fi, _ := os.Stat(certPath)
	c, k := genPair(t, "cert-b", time.Now().Add(90*24*time.Hour))
	write(t, certPath, c)
	write(t, keyPath, k)
	for _, p := range []string{certPath, keyPath} {
		_ = os.Chtimes(p, fi.ModTime(), fi.ModTime())
	}
	if err := r.Check(); err != nil {
		t.Fatal(err)
	}
	if got := serverCN(t, r); got != "cert-b" {
		t.Fatalf("CN = %q", got)
	}
}

func TestWatchTicksAndStops(t *testing.T) {
	_, certPath, keyPath, _, r := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Watch(ctx, 5*time.Millisecond)
	}()

	c, k := genPair(t, "cert-b", time.Now().Add(90*24*time.Hour))
	write(t, certPath, c)
	write(t, keyPath, k)
	deadline := time.Now().Add(5 * time.Second)
	for serverCN(t, r) != "cert-b" {
		if time.Now().After(deadline) {
			t.Fatal("watcher did not reload")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not stop")
	}
}

func TestWatchDisabledStopsOnCancel(t *testing.T) {
	_, _, _, _, r := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Watch(ctx, 0)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not stop")
	}
}

// Package certreload keeps a TLS certificate loaded from disk and swaps it
// atomically when the files change, so a renewed certificate (for example from
// certbot) is picked up without restarting the process.
package certreload

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ExpiryWarning is the remaining validity below which a loaded certificate is
// logged at warn level.
const ExpiryWarning = 14 * 24 * time.Hour

// Reloader serves the current certificate via GetCertificate.
type Reloader struct {
	certFile, keyFile string
	log               *slog.Logger
	now               func() time.Time

	cur atomic.Pointer[tls.Certificate]

	mu         sync.Mutex // serializes loads and guards the fields below
	seen       [sha256.Size]byte
	lastWarned time.Time // last expiry warning
}

// New loads the certificate pair. A failure is returned to the caller so the
// service can fail fast at startup.
func New(certFile, keyFile string, log *slog.Logger) (*Reloader, error) {
	if log == nil {
		log = slog.Default()
	}
	r := &Reloader{certFile: certFile, keyFile: keyFile, log: log, now: time.Now}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// GetCertificate implements tls.Config.GetCertificate.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.cur.Load(), nil
}

// Reload unconditionally re-reads the pair. On failure the previously loaded
// certificate stays in use and the error is returned.
func (r *Reloader) Reload() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	data, sum, err := r.read()
	if err != nil {
		return err
	}
	return r.load(data, sum)
}

// Check reloads only if the content of either file changed since the last
// successful load (the files are small, so a hash decides, not the mtime). A
// failed attempt is not remembered, so it is retried on the next call.
// Failures are logged at warn level and returned.
func (r *Reloader) Check() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	data, sum, err := r.read()
	if err == nil && sum == r.seen {
		return nil
	}
	if err == nil {
		err = r.load(data, sum)
	}
	if err != nil {
		r.log.Warn("tls certificate reload failed, keeping current certificate", "error", err)
	}
	return err
}

// Watch calls Check every interval until ctx is done and re-warns daily when
// the current certificate is close to expiry (for example because renewal is
// broken). The config layer turns 0 into its default interval; Watch itself
// treats a non-positive interval as "no periodic check" and only waits for
// ctx. Run it in its own goroutine.
func (r *Reloader) Watch(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		<-ctx.Done()
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = r.Check() // already logged
			r.warnExpiry()
		}
	}
}

// warnExpiry warns if the current certificate expires within ExpiryWarning and
// no warning was logged in the last 24 hours.
func (r *Reloader) warnExpiry() {
	r.mu.Lock()
	defer r.mu.Unlock()
	cert := r.cur.Load()
	now := r.now()
	if cert == nil || cert.Leaf == nil || now.Sub(r.lastWarned) < 24*time.Hour {
		return
	}
	if left := cert.Leaf.NotAfter.Sub(now); left < ExpiryWarning {
		r.lastWarned = now
		r.log.Warn("tls certificate expires soon", "not_after", cert.Leaf.NotAfter.UTC().Format(time.RFC3339), "remaining", left.Round(time.Minute).String())
	}
}

// read returns both files' contents (cert, key) and a hash over them.
// os.ReadFile follows symlinks (letsencrypt live/).
func (r *Reloader) read() ([2][]byte, [sha256.Size]byte, error) {
	var data [2][]byte
	var sum [sha256.Size]byte
	h := sha256.New()
	for i, path := range []string{r.certFile, r.keyFile} {
		b, err := os.ReadFile(path)
		if err != nil {
			return data, sum, fmt.Errorf("tls: %w", err)
		}
		data[i] = b
		_, _ = fmt.Fprintf(h, "%d:", len(b)) // length-prefix so the boundary is unambiguous
		_, _ = h.Write(b)                    // hash.Hash writes never fail
	}
	h.Sum(sum[:0])
	return data, sum, nil
}

// load must be called with r.mu held.
func (r *Reloader) load(data [2][]byte, sum [sha256.Size]byte) error {
	cert, err := tls.X509KeyPair(data[0], data[1])
	if err != nil {
		return fmt.Errorf("tls: loading key pair: %w", err)
	}
	if len(cert.Certificate) == 0 {
		return errors.New("tls: certificate file has no certificates")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("tls: parsing leaf certificate: %w", err)
	}
	cert.Leaf = leaf
	r.cur.Store(&cert)
	r.seen = sum

	r.log.Info("tls certificate loaded",
		"subject", leaf.Subject.String(),
		"dns_names", strings.Join(leaf.DNSNames, ","),
		"not_after", leaf.NotAfter.UTC().Format(time.RFC3339),
	)
	r.lastWarned = time.Time{}
	if left := leaf.NotAfter.Sub(r.now()); left < ExpiryWarning {
		r.lastWarned = r.now()
		r.log.Warn("tls certificate expires soon", "not_after", leaf.NotAfter.UTC().Format(time.RFC3339), "remaining", left.Round(time.Minute).String())
	}
	return nil
}

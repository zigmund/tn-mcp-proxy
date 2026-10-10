package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestServeTLS(t *testing.T) {
	cert := selfSigned(t)
	s := newTestServer(t, io.Discard)
	// GetCertificate only (no Certificates), as the reloader provides it.
	s.EnableTLS(&tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()

	pool := x509.NewCertPool()
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	pool.AddCert(leaf)
	addr := ln.Addr().String()

	// HTTP/2 is negotiated over TLS.
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: pool, ServerName: "localhost"},
		ForceAttemptHTTP2: true,
	}}
	resp, err := client.Get("https://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "ok" || resp.ProtoMajor != 2 {
		t.Fatalf("got %d %q proto %s", resp.StatusCode, body, resp.Proto)
	}

	// HTTP/1.1 fallback still works.
	h1 := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"}}}
	resp, err = h1.Get("https://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.ProtoMajor != 1 {
		t.Errorf("proto %s", resp.Proto)
	}

	// TLS 1.1 is rejected.
	_, err = tls.Dial("tcp", addr, &tls.Config{
		RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11,
	})
	if err == nil {
		t.Error("TLS 1.1 handshake succeeded")
	}

	// Plain HTTP is not served on a TLS listener.
	if r, err := http.Get("http://" + addr + "/healthz"); err == nil {
		defer func() { _ = r.Body.Close() }()
		if r.StatusCode == 200 {
			t.Error("plain HTTP served on TLS port")
		}
	}

	client.CloseIdleConnections()
	h1.CloseIdleConnections()
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

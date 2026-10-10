package proxy

import "testing"

// Credentials travel in headers, so the
// upstream transport must ignore HTTP(S)_PROXY.
func TestTransportIgnoresEnvironmentProxy(t *testing.T) {
	if newTransport(0).Proxy != nil {
		t.Error("upstream transport has a Proxy func; environment proxies would see the credentials")
	}
}

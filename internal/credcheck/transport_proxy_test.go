package credcheck

import (
	"net/http"
	"testing"
)

// The check carries credential headers, so
// it must ignore HTTP(S)_PROXY.
func TestCheckerIgnoresEnvironmentProxy(t *testing.T) {
	tr, ok := New().client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("checker transport is not an *http.Transport")
	}
	if tr.Proxy != nil {
		t.Error("checker transport has a Proxy func; environment proxies would see the credentials")
	}
}

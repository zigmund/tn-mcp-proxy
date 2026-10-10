package oauth

import (
	"net/http"
	"sync"
	"testing"
)

// fakeVerdicts is a RejectionSource with a fixed answer that records lookups.
type fakeVerdicts struct {
	mu       sync.Mutex
	rejected bool
	calls    []string
	creds    []map[string]string
}

func (f *fakeVerdicts) Rejected(upstream string, creds map[string]string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, upstream)
	f.creds = append(f.creds, creds)
	return f.rejected
}

// After the re-check confirmed rejected
// credentials the refresh grant must not hand out another token pair.
func TestTokenRefreshRefusedOnRejectedVerdict(t *testing.T) {
	e := newTK(t)
	fv := &fakeVerdicts{}
	WithRejectionSource(fv)(e.srv)
	_, rt := e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))

	// No verdict / accepted: refresh works.
	_, rt2 := e.wantOK(t, e.do(e.refreshForm(e.none, rt)))

	fv.mu.Lock()
	fv.rejected = true
	fv.mu.Unlock()
	e.wantErr(t, e.do(e.refreshForm(e.none, rt2)), http.StatusBadRequest, "invalid_grant")

	if len(fv.calls) == 0 || fv.calls[len(fv.calls)-1] != "tn" {
		t.Errorf("verdict looked up for %v, want the token's upstream", fv.calls)
	}
	if got := fv.creds[len(fv.creds)-1]["X-Api-Key"]; got != "sekret" {
		t.Errorf("verdict looked up with creds %v, want the token's credentials", fv.creds[len(fv.creds)-1])
	}

	// The verdict expires (the source stops reporting it): the same, still
	// unspent refresh token works again, because the refusal spent nothing.
	fv.mu.Lock()
	fv.rejected = false
	fv.mu.Unlock()
	e.wantOK(t, e.do(e.refreshForm(e.none, rt2)))
}

func TestTokenRefreshWithoutRejectionSource(t *testing.T) {
	e := newTK(t)
	_, rt := e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))
	WithRejectionSource(nil)(e.srv) // nil is ignored
	e.wantOK(t, e.do(e.refreshForm(e.none, rt)))
}

// The code exchange is not affected: a fresh authorization already validated
// the credentials.
func TestTokenCodeExchangeIgnoresVerdicts(t *testing.T) {
	e := newTK(t)
	WithRejectionSource(&fakeVerdicts{rejected: true})(e.srv)
	e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))
}

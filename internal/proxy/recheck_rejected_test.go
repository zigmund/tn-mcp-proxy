package proxy

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestRecheckerRejectedReadsOnlyTheCache(t *testing.T) {
	clock := new(atomic.Int64)
	clock.Store(1_000)
	rc := quietRechecker()
	rc.now = func() time.Time { return time.Unix(clock.Load(), 0) }
	e := newRecheckEnv(t, jsonReply(toolErrBody), valReject, WithRechecker(rc))

	if rc.Rejected("tn", goodCreds()) {
		t.Fatal("rejected before any check")
	}
	wantRejected(t, e.post(t, "identity"))
	before := e.validations()
	if !rc.Rejected("tn", goodCreds()) {
		t.Fatal("not rejected after a confirmed rejection")
	}
	other := goodCreds()
	other["X-Tn-Api-Key"] = "key-other"
	if rc.Rejected("tn", other) || rc.Rejected("other-upstream", goodCreds()) {
		t.Error("verdict leaked to other credentials or upstream")
	}
	// Header names are canonicalised like in the re-check cache.
	if !rc.Rejected("tn", map[string]string{"x-tn-api-key": "key-123", "X-TN-API-SECRET": "secret-456", "x-tn-sid": "sid-789"}) {
		t.Error("lookup not keyed like the re-check cache")
	}
	if e.validations() != before {
		t.Error("Rejected contacted the upstream")
	}
	clock.Add(int64(recheckTTL/time.Second) + 1)
	if rc.Rejected("tn", goodCreds()) {
		t.Error("expired verdict still reported")
	}
}

func TestRecheckerAcceptedAndUnknownAreNotRejected(t *testing.T) {
	rc := quietRechecker()
	e := newRecheckEnv(t, jsonReply(toolErrBody), valStatus(500), WithRechecker(rc))
	wantPassthrough(t, e.post(t, "identity"), []byte(toolErrBody))
	if rc.Rejected("tn", goodCreds()) {
		t.Error("\"no verdict\" reported as rejected")
	}
}

// During an outage "no verdict" is remembered as long as
// a real verdict, so one token costs at most one session per minute.
func TestRecheckUnavailableBoundsSessionsPerMinute(t *testing.T) {
	if unavailableTTL < time.Minute {
		t.Fatalf("unavailableTTL = %v, want >= 1m", unavailableTTL)
	}
}

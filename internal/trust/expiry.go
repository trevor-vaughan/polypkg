package trust

import (
	"fmt"
	"time"
)

// expirySkew bounds acceptable consumer clock drift when enforcing metadata
// expiry (D13). Rejection triggers only when now exceeds expires by more than
// this tolerance.
const expirySkew = 5 * time.Minute

// timeNow is indirected for tests.
var timeNow = time.Now

// SetTimeNowForTesting overrides the clock CheckExpiry consults and returns a
// restore func. Test-only: it exists so out-of-package specs (the planner's
// freshness scenarios) can advance time deterministically instead of sleeping
// through a real validity window. Production code must never call it.
func SetTimeNowForTesting(f func() time.Time) (restore func()) {
	prev := timeNow
	timeNow = f
	return func() { timeNow = prev }
}

// CheckExpiry enforces the freshness bound on signed metadata: an empty or
// unparseable expires is itself a hard failure (v2 metadata always carries
// one), and a past expires (beyond skew) normally rejects the document. This
// closes the TUF freeze attack: a mirror cannot pin clients on a stale-but-
// validly-signed serial forever.
//
// acceptUntil is an optional per-source RFC3339 freshness-grace deadline
// (phase 2e-1, spec §10.9 E-3). When the document is expired but now is at or
// before acceptUntil, the document is ACCEPTED and graced is true — the
// wall-clock bound is relaxed for a frozen air-gap mirror. Grace relaxes
// wall-clock ONLY; the caller's monotonic serial-floor check is a separate
// gate that still refuses a rollback. An empty or unparseable acceptUntil
// grants NO grace (fail closed: a malformed ceiling must never mean "forever").
func CheckExpiry(what, expires, acceptUntil string) (graced bool, err error) {
	if expires == "" {
		return false, fmt.Errorf("%s has no expires field", what)
	}
	t, err := time.Parse(time.RFC3339, expires)
	if err != nil {
		return false, fmt.Errorf("%s expires %q is not RFC3339: %w", what, expires, err)
	}
	if !timeNow().After(t.Add(expirySkew)) {
		return false, nil // still fresh
	}
	// Expired. Grace only if the operator set a valid ceiling and we are at or
	// before it.
	if acceptUntil != "" {
		if deadline, perr := time.Parse(time.RFC3339, acceptUntil); perr == nil {
			if !timeNow().After(deadline) {
				return true, nil // graced: expired but within accept_expiry_until
			}
		}
	}
	return false, fmt.Errorf("%s expired at %s (stale metadata refused; set accept_expiry_until to grace a frozen mirror, or the publisher must re-sign)", what, expires)
}

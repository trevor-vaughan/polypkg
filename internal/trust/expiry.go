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
// one), and a past expires (beyond skew) rejects the document. This closes
// the TUF freeze attack: a mirror cannot pin clients on a stale-but-validly-
// signed serial forever.
func CheckExpiry(what, expires string) error {
	if expires == "" {
		return fmt.Errorf("%s has no expires field", what)
	}
	t, err := time.Parse(time.RFC3339, expires)
	if err != nil {
		return fmt.Errorf("%s expires %q is not RFC3339: %w", what, expires, err)
	}
	if timeNow().After(t.Add(expirySkew)) {
		return fmt.Errorf("%s expired at %s (stale metadata refused; the publisher must re-sign)", what, expires)
	}
	return nil
}

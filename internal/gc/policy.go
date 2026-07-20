// Package gc implements polypkg's pure mark-and-sweep retention algorithm
// for generations. It is substrate-agnostic: callers supply []Generation and
// a Policy, and receive a Decision describing which IDs to keep vs. remove.
package gc

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Policy is the retention threshold pair. A generation survives if it falls
// under EITHER threshold (count OR age window), so both can be specified
// without one disabling the other. See apply-semantics §4.3.
type Policy struct {
	Count int           // minimum generations retained; must be >= 1
	Age   time.Duration // generations committed within this window are also retained; >= 0
}

// Validate checks that the policy is well-formed. Count must be at least 1
// (zero would sweep everything including current); Age must be non-negative.
func (p Policy) Validate() error {
	if p.Count < 1 {
		return fmt.Errorf("retention count must be >= 1, got %d", p.Count)
	}
	if p.Age < 0 {
		return fmt.Errorf("retention age must be >= 0, got %v", p.Age)
	}
	return nil
}

// ParseAge accepts every form `time.ParseDuration` accepts (ns/us/ms/s/m/h)
// plus "d" (24h) and "w" (168h). It rejects months and years because those
// require calendar arithmetic the retention model does not perform.
//
// Mixed forms with d/w (e.g. "1d12h") are NOT supported: the helper handles
// either a pure d/w expression or a time.ParseDuration expression, not a
// concatenation.
func ParseAge(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	// Detect bare d/w forms: digits followed by a single 'd' or 'w'.
	if n := len(s); n >= 2 && (s[n-1] == 'd' || s[n-1] == 'w') {
		num := s[:n-1]
		// reject negative
		if strings.HasPrefix(num, "-") {
			return 0, fmt.Errorf("negative duration not allowed: %q", s)
		}
		v, err := strconv.Atoi(num)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		if v < 0 {
			return 0, fmt.Errorf("negative duration not allowed: %q", s)
		}
		switch s[n-1] {
		case 'd':
			return time.Duration(v) * 24 * time.Hour, nil
		case 'w':
			return time.Duration(v) * 7 * 24 * time.Hour, nil
		}
	}
	// Fall back to time.ParseDuration for s/m/h forms. This intentionally
	// rejects calendar units like 'y' and 'M' because time.ParseDuration
	// itself rejects them.
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", s, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("negative duration not allowed: %q", s)
	}
	return d, nil
}

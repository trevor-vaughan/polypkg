//go:build !linux

package starlarkeval

import "errors"

// sampleRSS is unsupported off Linux; the memory limit degrades to GOMEMLIMIT
// plus the step and wall-clock caps.
func sampleRSS(pid int) (uint64, error) {
	return 0, errors.New("rss sampling unsupported on this OS")
}

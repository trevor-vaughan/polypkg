//go:build linux

package starlarkeval

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// sampleRSS returns the resident set size of pid in bytes, read from /proc.
func sampleRSS(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", pid))
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0, fmt.Errorf("unexpected statm format")
	}
	residentPages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, err
	}
	//nolint:gosec // G115: os.Getpagesize() is a small positive system constant.
	return residentPages * uint64(os.Getpagesize()), nil
}

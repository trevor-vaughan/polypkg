package starlarkeval

import (
	"context"
	"testing"
	"time"
)

func FuzzRun(f *testing.F) {
	f.Add(`return "x"`)
	f.Add(`return host.os`)
	f.Add(`return 1`)
	f.Add("x =")
	f.Add("")
	f.Add(`return "a" * 1000`)
	lim := Limits{MaxSteps: 100_000, Timeout: time.Second, MaxMemoryBytes: 64 << 20, MaxOutputBytes: 4096}
	f.Fuzz(func(t *testing.T, src string) {
		// Must never panic and must always return within the step cap.
		_, _ = Run(context.Background(), src, Inputs{}, lim)
	})
}

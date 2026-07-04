package starlarkeval

import (
	"context"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func testLimits() Limits {
	// 120s wall-clock: subprocess startup under `go test -race ./...` races with
	// dozens of other packages and can take several seconds on a loaded machine.
	// Tests that care about the wall-clock timeout override this field explicitly.
	return Limits{MaxSteps: 1_000_000, Timeout: 120 * time.Second, MaxMemoryBytes: 64 << 20, MaxOutputBytes: 64 << 10}
}

var _ = Describe("Run", func() {
	It("evaluates a happy-path snippet and returns the string result", func() {
		in := Inputs{}
		in.Package.Name, in.Package.Version = "hello", "1.0.0"
		in.Host.OS, in.Host.Arch = "linux", "amd64"
		got, err := Run(context.Background(), `return "p/" + host.arch + "/" + package.name`, in, testLimits())
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal("p/amd64/hello"))
	})

	It("rejects a non-string result", func() {
		_, err := Run(context.Background(), `return 42`, Inputs{}, testLimits())
		Expect(err).To(MatchError(ContainSubstring("must be a string")))
	})

	It("enforces the output cap", func() {
		lim := testLimits()
		lim.MaxOutputBytes = 8
		_, err := Run(context.Background(), `return "x" * 100`, Inputs{}, lim)
		Expect(err).To(MatchError(ContainSubstring("output")))
	})

	It("maps syntax errors back to snippet.star line numbers", func() {
		_, err := Run(context.Background(), "x =", Inputs{}, testLimits())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("snippet.star:1:"))
	})

	It("returns an error on runtime failure", func() {
		_, err := Run(context.Background(), `return undefined_name`, Inputs{}, testLimits())
		Expect(err).To(HaveOccurred())
	})

	It("fails when the step cap is exceeded", func() {
		lim := testLimits()
		lim.MaxSteps = 100
		_, err := Run(context.Background(), `
total = 0
for i in range(1000000):
    total += i
return str(total)`, Inputs{}, lim)
		Expect(err).To(HaveOccurred())
		Expect(strings.ToLower(err.Error())).To(ContainSubstring("step"))
	})

	It("fails immediately when the context is already cancelled", func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := Run(ctx, `return "x"`, Inputs{}, testLimits())
		Expect(err).To(HaveOccurred())
	})

	It("stops execution when the context is cancelled mid-run", func() {
		lim := testLimits()
		lim.MaxSteps = 0 // unlimited steps, so only the context cancel can stop it
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, err := Run(ctx, `
n = 0
for i in range(1000000000):
    n += i
return str(n)`, Inputs{}, lim)
		Expect(err).To(HaveOccurred())
	})

	It("handles nested indentation", func() {
		got, err := Run(context.Background(), `
parts = []
for c in ["a", "b"]:
    if c == "b":
        parts.append(c)
return "/".join(parts)`, Inputs{}, testLimits())
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal("b"))
	})

	It("treats a zero output cap as unlimited", func() {
		lim := testLimits()
		lim.MaxOutputBytes = 0 // unlimited
		got, err := Run(context.Background(), `return "x" * 1000`, Inputs{}, lim)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HaveLen(1000))
	})
})

package starlarkeval

import (
	"context"
	"runtime"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Evaluate", func() {
	It("round-trips a snippet through the subprocess", func() {
		in := Inputs{}
		in.Host.OS, in.Host.Arch = "linux", "amd64"
		got, err := Evaluate(context.Background(), `return "v-" + host.arch`, in, testLimits())
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal("v-amd64"))
	})

	It("fails when the wall-clock timeout fires", func() {
		lim := testLimits()
		lim.Timeout = 50 * time.Millisecond
		lim.MaxSteps = 0 // unlimited steps, so the wall-clock is what fires
		_, err := Evaluate(context.Background(), `
total = 0
for i in range(100000000):
    total += i
return str(total)`, Inputs{}, lim)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("timed out"))
	})

	It("fails when the memory cap is exceeded", func() {
		if runtime.GOOS != "linux" {
			Skip("hard memory cap (RSS monitor) is Linux-only; elsewhere bounded by GOMEMLIMIT+timeout")
		}
		lim := testLimits()
		lim.MaxMemoryBytes = 48 << 20 // 48 MiB
		lim.Timeout = 5 * time.Second
		lim.MaxSteps = 0
		_, err := Evaluate(context.Background(), `
acc = []
for i in range(100000):
    acc.append("x" * 100000)
return "done"`, Inputs{}, lim)
		Expect(err).To(HaveOccurred())
		Expect(strings.ToLower(err.Error())).To(ContainSubstring("memory"))
	})

	It("fails when the caller's context is cancelled", func() {
		lim := testLimits()
		lim.Timeout = 5 * time.Second // long, so the ctx cancellation is what fires
		lim.MaxSteps = 0              // unlimited steps
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_, err := Evaluate(ctx, `
total = 0
for i in range(100000000):
    total += i
return str(total)`, Inputs{}, lim)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("cancelled"))
	})

	It("propagates non-string result errors from the subprocess", func() {
		_, err := Evaluate(context.Background(), `return 7`, Inputs{}, testLimits())
		Expect(err).To(MatchError(ContainSubstring("must be a string")))
	})
})

var _ = Describe("Evaluator", func() {
	It("caches identical source+package and only evaluates once", func() {
		calls := 0
		ev := &Evaluator{lim: testLimits(), cache: map[string]string{}, backend: func(_ context.Context, src string, _ Inputs, _ Limits) (string, error) {
			calls++
			return "r", nil
		}}
		in := Inputs{}
		in.Package.Name = "p"
		_, _ = ev.Eval(context.Background(), "return 1", in)
		_, _ = ev.Eval(context.Background(), "return 1", in)
		Expect(calls).To(Equal(1), "identical source+package should be evaluated once")
	})
})

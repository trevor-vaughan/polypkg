package cli

import (
	"errors"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/source"
)

var _ = Describe("planExecError source translation", func() {
	Describe("network failure", func() {
		It("frames a single-line unreachable-source CLIError with a network hint", func() {
			fe := &source.FetchError{
				Source:  "native",
				BaseURL: "http://127.0.0.1:9",
				URL:     "http://127.0.0.1:9/trust.json",
				Network: true,
				Err:     errors.New("dial tcp 127.0.0.1:9: connect: connection refused"),
			}
			// As surfaced from the planner.
			got := planExecError(fmt.Errorf("fetch trust document: %w", fe))
			var ce *CLIError
			Expect(errors.As(got, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", got, got)
			Expect(ce.Msg).To(Equal(`cannot reach source "native" at http://127.0.0.1:9: connection refused`))
			Expect(ce.Hint).To(ContainSubstring("source url in your profile"))
			Expect(ce.Hint).To(ContainSubstring("network connection"))
			// The URL appears exactly once in the user message.
			Expect(ce.Msg).NotTo(ContainSubstring("trust.json"))
			Expect(ce.Msg).NotTo(ContainSubstring("Get \""))
		})

		It("preserves the raw transport reason when it has no recognizable connect suffix", func() {
			fe := &source.FetchError{
				Source:  "native",
				BaseURL: "http://example.invalid",
				URL:     "http://example.invalid/index.json",
				Network: true,
				Err:     errors.New("dial tcp: lookup example.invalid: no such host"),
			}
			got := planExecError(fmt.Errorf("fetch index: %w", fe))
			var ce *CLIError
			Expect(errors.As(got, &ce)).To(BeTrue())
			Expect(ce.Msg).To(ContainSubstring(`cannot reach source "native" at http://example.invalid`))
			Expect(ce.Msg).To(ContainSubstring("no such host"))
		})
	})

	Describe("status failure", func() {
		It("keeps the artifact 404 message and adds the mid-update hint", func() {
			fe := &source.FetchError{
				Source:  "native",
				BaseURL: "http://host",
				URL:     "http://host/hello-1.0.0.tar.zst",
				Status:  404,
			}
			got := planExecError(fmt.Errorf("fetch hello-1.0.0: %w", fe))
			var ce *CLIError
			Expect(errors.As(got, &ce)).To(BeTrue())
			Expect(ce.Msg).To(ContainSubstring("status 404"))
			Expect(ce.Msg).To(ContainSubstring("hello-1.0.0.tar.zst"))
			Expect(ce.Hint).To(ContainSubstring("index lists this artifact but the server does not serve it"))
		})

		It("does not attach the artifact hint to a repo-metadata 404", func() {
			fe := &source.FetchError{
				Source:  "native",
				BaseURL: "http://host",
				URL:     "http://host/index.json",
				Status:  404,
			}
			got := planExecError(fmt.Errorf("fetch index: %w", fe))
			var ce *CLIError
			Expect(errors.As(got, &ce)).To(BeTrue())
			Expect(ce.Msg).To(ContainSubstring("status 404"))
			Expect(ce.Hint).To(BeEmpty())
		})
	})
})

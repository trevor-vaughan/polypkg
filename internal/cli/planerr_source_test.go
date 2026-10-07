package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

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

var _ = Describe("planExecError stall and redirect translation", func() {
	It("frames an idle stall as a stall naming the URL, without Go internals", func() {
		fe := &source.FetchError{
			Source:  "native",
			BaseURL: "https://host",
			URL:     "https://host/index.json",
			Network: true,
			Err:     &source.StallError{Limit: time.Minute},
		}
		got := planExecError(fmt.Errorf("fetch index: %w", fe))
		var ce *CLIError
		Expect(errors.As(got, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", got, got)
		Expect(ce.Msg).To(Equal("fetch https://host/index.json: server stalled: no data received for 1m0s"))
		Expect(ce.Msg).NotTo(ContainSubstring("context"))
		Expect(ce.Msg).NotTo(ContainSubstring("cannot reach"))
		Expect(ce.Hint).To(ContainSubstring("retry"))
		Expect(errors.Is(got, fe)).To(BeTrue())
	})

	It("frames a metadata whole-request timeout as a stall", func() {
		fe := &source.FetchError{
			Source:  "native",
			BaseURL: "https://host",
			URL:     "https://host/trust.json",
			Network: true,
			Err:     &source.StallError{Limit: 5 * time.Minute, Overall: true},
		}
		got := planExecError(fmt.Errorf("fetch trust document: %w", fe))
		var ce *CLIError
		Expect(errors.As(got, &ce)).To(BeTrue())
		Expect(ce.Msg).To(Equal("fetch https://host/trust.json: server stalled: response not complete after 5m0s"))
	})

	It("frames a refused https to http redirect with its own hint", func() {
		fe := &source.FetchError{
			Source:  "native",
			BaseURL: "https://host",
			URL:     "https://host/index.json",
			Network: true,
			Err:     fmt.Errorf("%w: http://evil/index.json", source.ErrInsecureRedirect),
		}
		got := planExecError(fmt.Errorf("fetch index: %w", fe))
		var ce *CLIError
		Expect(errors.As(got, &ce)).To(BeTrue())
		Expect(ce.Msg).To(Equal("fetch https://host/index.json: refused redirect from https to a non-https URL: http://evil/index.json"))
		Expect(ce.Msg).NotTo(ContainSubstring("cannot reach"))
		Expect(ce.Hint).To(ContainSubstring("non-https"))
	})
})

// A source URL with credentials must not leak through the plan/apply error
// mapping. Real failing fetches, so the whole source -> CLIError chain is used.
var _ = Describe("planExecError credential redaction", func() {
	expectNoSecret := func(err error) {
		GinkgoHelper()
		Expect(err).To(HaveOccurred())
		got := planExecError(fmt.Errorf("fetch index: %w", err))
		Expect(got.Error()).NotTo(ContainSubstring("secret"))
		var ce *CLIError
		Expect(errors.As(got, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", got, got)
		Expect(ce.Msg).NotTo(ContainSubstring("secret"))
		Expect(ce.Hint).NotTo(ContainSubstring("secret"))
	}

	It("redacts on a refused connection", func() {
		b := source.NewNativeBackend(source.NativeBackendOpts{URL: "https://user:secret@127.0.0.1:9", CacheDir: GinkgoT().TempDir()})
		_, _, err := b.FetchIndex(context.Background())
		expectNoSecret(err)
	})

	It("redacts on a 404", func() {
		srv := httptest.NewServer(http.NotFoundHandler())
		defer srv.Close()
		b := source.NewNativeBackend(source.NativeBackendOpts{
			URL:      strings.Replace(srv.URL, "http://", "http://user:secret@", 1),
			CacheDir: GinkgoT().TempDir(),
		})
		_, _, err := b.FetchIndex(context.Background())
		expectNoSecret(err)
	})
})

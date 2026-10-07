package source

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("FetchError", func() {
	Describe("network failure", func() {
		It("collapses the http client's Get \"url\": prefix to a single clean cause", func() {
			// Port 9 (discard) refuses connections; the client returns a *url.Error
			// whose String() embeds the redundant Get "<url>": prefix.
			b := NewNativeBackend(NativeBackendOpts{
				URL:      "http://127.0.0.1:9",
				CacheDir: GinkgoT().TempDir(),
			})
			_, _, err := b.FetchTrustDoc(context.Background())
			Expect(err).To(HaveOccurred())

			var fe *FetchError
			Expect(errors.As(err, &fe)).To(BeTrue(), "expected *FetchError, got %T: %v", err, err)
			Expect(fe.Source).To(Equal("native"))
			Expect(fe.BaseURL).To(Equal("http://127.0.0.1:9"))
			Expect(fe.Status).To(Equal(0))
			Expect(fe.Network).To(BeTrue())
			// The message names the reason without the doubled Get "url": tail.
			Expect(fe.Reason()).To(ContainSubstring("connection refused"))
			Expect(fe.Reason()).NotTo(ContainSubstring("Get \""))
			Expect(fe.Error()).NotTo(ContainSubstring("Get \""))
		})
	})

	Describe("status failure", func() {
		It("keeps the clean fetch <url>: status N form and is not a network error", func() {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			}))
			defer srv.Close()

			b := NewNativeBackend(NativeBackendOpts{
				URL:      srv.URL,
				CacheDir: GinkgoT().TempDir(),
			})
			_, err := b.Fetch(context.Background(), "hello-1.0.0.tar.zst")
			Expect(err).To(HaveOccurred())

			var fe *FetchError
			Expect(errors.As(err, &fe)).To(BeTrue(), "expected *FetchError, got %T: %v", err, err)
			Expect(fe.Status).To(Equal(http.StatusNotFound))
			Expect(fe.Network).To(BeFalse())
			Expect(fe.Error()).To(ContainSubstring("status 404"))
			Expect(fe.Error()).To(ContainSubstring(srv.URL + "/hello-1.0.0.tar.zst"))
		})
	})
})

// A source URL may carry credentials (https://user:secret@host/...). They must
// never reach an error string, which ends up on a terminal, in CI logs and in
// --format json output. The raw URL stays on the FetchError fields.
var _ = Describe("FetchError credential redaction", func() {
	expectRedacted := func(err error) *FetchError {
		GinkgoHelper()
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).NotTo(ContainSubstring("secret"))
		var fe *FetchError
		Expect(errors.As(err, &fe)).To(BeTrue(), "expected *FetchError, got %T: %v", err, err)
		Expect(fe.Error()).NotTo(ContainSubstring("secret"))
		return fe
	}

	It("redacts the password on a refused connection", func() {
		b := NewNativeBackend(NativeBackendOpts{URL: "https://user:secret@127.0.0.1:9", CacheDir: GinkgoT().TempDir()})
		_, _, err := b.FetchTrustDoc(context.Background())
		fe := expectRedacted(err)
		Expect(fe.Network).To(BeTrue())
		Expect(fe.Error()).To(ContainSubstring("https://xxxxx@127.0.0.1:9/trust.json"))
		Expect(fe.URL).To(ContainSubstring("secret"), "the raw URL stays available programmatically")
	})

	It("redacts the password on a 404", func() {
		srv := httptest.NewServer(http.NotFoundHandler())
		defer srv.Close()
		withCreds := strings.Replace(srv.URL, "http://", "http://user:secret@", 1)
		b := NewNativeBackend(NativeBackendOpts{URL: withCreds, CacheDir: GinkgoT().TempDir()})
		_, _, err := b.FetchIndex(context.Background())
		fe := expectRedacted(err)
		Expect(fe.Status).To(Equal(http.StatusNotFound))
		Expect(fe.Error()).To(ContainSubstring("://xxxxx@127.0.0.1:"))
	})

	It("does not echo the credentials of a URL that does not parse", func() {
		b := NewNativeBackend(NativeBackendOpts{URL: "https://user:secret@127.0.0.1:9/%zz", CacheDir: GinkgoT().TempDir()})
		_, _, err := b.FetchTrustDoc(context.Background())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).NotTo(ContainSubstring("secret"))
		Expect(err.Error()).NotTo(ContainSubstring("user"))
	})
})

var _ = Describe("RedactURL", func() {
	// Each case lists the strings that must not survive: tokens, passwords, and
	// for a fail-closed render anything that sat before the last '@'.
	DescribeTable("never renders credentials",
		func(raw, want string, secrets ...string) {
			got := RedactURL(raw)
			Expect(got).To(Equal(want))
			for _, sec := range secrets {
				Expect(got).NotTo(ContainSubstring(sec))
			}
		},
		Entry("user and password", "https://user:secret@host/repo", "https://xxxxx@host/repo", "user", "secret"),
		Entry("username-only token", "https://ghp_TOKEN@host/r", "https://xxxxx@host/r", "ghp_TOKEN"),
		Entry("unparseable, '/' in the password", "https://user:se/cret@host/%zz", "https://<redacted>", "user", "se/cret", "cret"),
		Entry("unparseable, '#' in the password", "https://user:pa#ss@host/r", "https://<redacted>", "user", "pa#ss", "ss@"),
		Entry("opaque, no scheme separator", "user:secret@host/%zz", "<redacted>", "user", "secret"),
		Entry("unparseable escape in the password", "https://user:p%zzw@host/r", "https://<redacted>", "user", "p%zzw"),
		Entry("scheme-less token", "ghp_TOKEN@host/r", "<redacted>", "ghp_TOKEN"),
	)

	It("leaves a URL without credentials, or a plain path, alone", func() {
		Expect(RedactURL("https://host/repo")).To(Equal("https://host/repo"))
		Expect(RedactURL("https://host/a@b")).To(Equal("https://host/a@b"))
		Expect(RedactURL("/srv/repo")).To(Equal("/srv/repo"))
	})
})

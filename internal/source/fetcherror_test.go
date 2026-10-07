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
				Source:   "zeta",
				CacheDir: GinkgoT().TempDir(),
			})
			_, _, err := b.FetchTrustDoc(context.Background())
			Expect(err).To(HaveOccurred())

			var fe *FetchError
			Expect(errors.As(err, &fe)).To(BeTrue(), "expected *FetchError, got %T: %v", err, err)
			Expect(fe.Source).To(Equal("zeta"), "the error names the source it was fetched for")
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
			Expect(fe.NotFound()).To(BeTrue())
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
		Entry("a query token", "https://host/r?token=abc123", "https://host/r?token=xxxxx", "abc123"),
		Entry("an access_token among other parameters", "https://host/r?page=2&access_token=abc123",
			"https://host/r?page=xxxxx&access_token=xxxxx", "abc123"),
		Entry("a presigned URL", "https://bucket.s3.example/key?X-Amz-Credential=AKIA1&X-Amz-Signature=deadbeef&sig=c2ln",
			"https://bucket.s3.example/key?X-Amz-Credential=xxxxx&X-Amz-Signature=xxxxx&sig=xxxxx", "AKIA1", "deadbeef", "c2ln"),
		Entry("a bare query value", "https://host/r?SECRETVALUE", "https://host/r?xxxxx", "SECRETVALUE"),
		Entry("userinfo and a query", "https://user:secret@host/r?token=abc123", "https://xxxxx@host/r?token=xxxxx", "user", "secret", "abc123"),
		Entry("a query on a local path", "/srv/repo?token=abc123", "/srv/repo?token=xxxxx", "abc123"),
		Entry("a fragment token", "https://host/r#access_token=abc123", "https://host/r#xxxxx", "access_token", "abc123"),
		Entry("a query and a fragment", "https://host/r?sig=c2ln#tok", "https://host/r?sig=xxxxx#xxxxx", "c2ln", "tok"),
	)

	It("leaves a URL without credentials, or a plain path, alone", func() {
		Expect(RedactURL("https://host/repo")).To(Equal("https://host/repo"))
		Expect(RedactURL("https://host/a@b")).To(Equal("https://host/a@b"))
		Expect(RedactURL("/srv/repo")).To(Equal("/srv/repo"))
	})
})

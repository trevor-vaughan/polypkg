package ghrelease

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	ginkgo "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// digestA is a well-formed sha256 asset digest.
var digestA = "sha256:" + strings.Repeat("ab", 32)

// releaseJSON renders a release API response with the given tag and assets.
func releaseJSON(tag string, prerelease bool, assets ...map[string]any) string {
	b, err := json.Marshal(map[string]any{"tag_name": tag, "prerelease": prerelease, "assets": assets})
	Expect(err).NotTo(HaveOccurred())
	return string(b)
}

// asset renders one release asset for releaseJSON. A nil digest is sent as
// JSON null, as GitHub does for assets uploaded before it computed digests.
func asset(name string, size int64, digest any, url string) map[string]any {
	return map[string]any{"name": name, "size": size, "digest": digest, "browser_download_url": url}
}

// serveRelease starts an API server answering every request with body, and
// returns its URL and recorder.
func serveRelease(body string) (string, *recorder) {
	srv, rec := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	})
	return srv.URL, rec
}

var _ = ginkgo.Describe("Release", func() {
	ginkgo.It("fetches the latest release when no tag is given", func() {
		api, rec := serveRelease(releaseJSON("v1.2.3", false,
			asset("tool-linux-amd64.tar.gz", 1234, digestA, "https://github.com/o/r/releases/download/v1.2.3/tool-linux-amd64.tar.gz"),
			asset("checksums.txt", 99, nil, "https://github.com/o/r/releases/download/v1.2.3/checksums.txt"),
		))
		rel, err := newTestClient(api).Release(context.Background(), "o", "r", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(rec.requests()[0].URL.Path).To(Equal("/repos/o/r/releases/latest"))
		Expect(rec.auths()).To(Equal([]string{"Bearer " + testToken}))
		Expect(rel).To(Equal(&Release{Tag: "v1.2.3", Assets: []Asset{
			{Name: "tool-linux-amd64.tar.gz", Size: 1234, Digest: digestA,
				URL: "https://github.com/o/r/releases/download/v1.2.3/tool-linux-amd64.tar.gz"},
			{Name: "checksums.txt", Size: 99,
				URL: "https://github.com/o/r/releases/download/v1.2.3/checksums.txt"},
		}}))
	})

	ginkgo.It("fetches a tagged release and reports a prerelease", func() {
		api, rec := serveRelease(releaseJSON("v2.0.0-rc1", true))
		rel, err := newTestClient(api).Release(context.Background(), "o", "r", "v2.0.0-rc1")
		Expect(err).NotTo(HaveOccurred())
		Expect(rec.requests()[0].URL.Path).To(Equal("/repos/o/r/releases/tags/v2.0.0-rc1"))
		Expect(rel.Tag).To(Equal("v2.0.0-rc1"))
		Expect(rel.Prerelease).To(BeTrue())
		Expect(rel.Assets).To(BeEmpty())
	})

	ginkgo.It("escapes a slash in a tag rather than adding a path segment", func() {
		api, rec := serveRelease(releaseJSON("release/1.0", false))
		_, err := newTestClient(api).Release(context.Background(), "o", "r", "release/1.0")
		Expect(err).NotTo(HaveOccurred())
		Expect(rec.requests()[0].URL.EscapedPath()).To(Equal("/repos/o/r/releases/tags/release%2F1.0"))
	})

	ginkgo.DescribeTable("refuses a dot-segment tag before any request",
		func(tag string) {
			api, rec := serveRelease(releaseJSON(tag, false))
			_, err := newTestClient(api).Release(context.Background(), "o", "r", tag)
			Expect(err).To(MatchError(ContainSubstring("invalid release tag")))
			Expect(rec.requests()).To(BeEmpty())
		},
		ginkgo.Entry("dot", "."),
		ginkgo.Entry("dot-dot", ".."),
	)

	ginkgo.It("refuses a response for a different tag", func() {
		api, _ := serveRelease(releaseJSON("v9.9.9", false))
		_, err := newTestClient(api).Release(context.Background(), "o", "r", "v1.0.0")
		Expect(err).To(MatchError(ContainSubstring(`asked for tag "v1.0.0", got "v9.9.9"`)))
	})

	ginkgo.It("never puts the token in an error when the response echoes it JSON-escaped", func() {
		// \u0067 is 'g': the raw body never contains the token's bytes, but
		// the decoded tag, which the tag-mismatch error quotes, does.
		escaped := `\u0067` + strings.TrimPrefix(testToken, "g")
		api, _ := serveRelease(`{"tag_name":"` + escaped + `","assets":[]}`)
		_, err := newTestClient(api).Release(context.Background(), "o", "r", "v1.0.0")
		Expect(err).To(MatchError(ContainSubstring("echoed the API token")))
		Expect(err.Error()).NotTo(ContainSubstring(testToken))
	})

	ginkgo.It("refuses a release without a tag name", func() {
		api, _ := serveRelease(releaseJSON("", false))
		_, err := newTestClient(api).Release(context.Background(), "o", "r", "")
		Expect(err).To(MatchError(ContainSubstring("has no tag name")))
	})

	ginkgo.It("reports a missing release as a *NotFoundError", func() {
		srv, _ := newRecordedServer(http.NotFound)
		_, err := newTestClient(srv.URL).Release(context.Background(), "o", "r", "v1.0.0")
		var nf *NotFoundError
		Expect(errors.As(err, &nf)).To(BeTrue())
	})

	ginkgo.DescribeTable("refuses an asset name that is not a safe single path segment",
		func(name string) {
			api, _ := serveRelease(releaseJSON("v1", false, asset(name, 1, nil, "https://example.com/a")))
			_, err := newTestClient(api).Release(context.Background(), "o", "r", "")
			Expect(err).To(MatchError(ContainSubstring("is not a safe file name")))
		},
		ginkgo.Entry("empty", ""),
		ginkgo.Entry("dot", "."),
		ginkgo.Entry("dot-dot", ".."),
		ginkgo.Entry("a parent traversal", "../../etc/passwd"),
		ginkgo.Entry("a slash", "bin/tool"),
		ginkgo.Entry("a backslash", `bin\tool`),
		ginkgo.Entry("a NUL", "tool\x00.tar.gz"),
		ginkgo.Entry("a newline", "tool\n.tar.gz"),
		ginkgo.Entry("a right-to-left override", "tool\u202egz.rat"),
		ginkgo.Entry("a zero-width space", "tool\u200b.tar.gz"),
		ginkgo.Entry("a byte order mark", "\ufefftool.tar.gz"),
		ginkgo.Entry("over 255 bytes", strings.Repeat("a", 256)),
	)

	ginkgo.It("accepts a 255-byte asset name with dots and non-ASCII letters", func() {
		name := "ünïcode.v1.." + strings.Repeat("a", 255-len("ünïcode.v1.."))
		api, _ := serveRelease(releaseJSON("v1", false, asset(name, 1, nil, "https://example.com/a")))
		rel, err := newTestClient(api).Release(context.Background(), "o", "r", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(rel.Assets[0].Name).To(Equal(name))
	})

	ginkgo.It("refuses an asset name listed twice", func() {
		api, _ := serveRelease(releaseJSON("v1", false,
			asset("a.tar.gz", 1, nil, "https://example.com/1"),
			asset("a.tar.gz", 2, nil, "https://example.com/2")))
		_, err := newTestClient(api).Release(context.Background(), "o", "r", "")
		Expect(err).To(MatchError(ContainSubstring(`asset "a.tar.gz" is listed twice`)))
	})

	ginkgo.It("quotes the release tag in an asset refusal", func() {
		api, _ := serveRelease(releaseJSON("v1\x1b[31mRED", false, asset("a", -1, nil, "https://example.com/a")))
		_, err := newTestClient(api).Release(context.Background(), "o", "r", "")
		Expect(err).To(MatchError(HavePrefix(`release "v1\x1b[31mRED": asset "a" has negative size`)))
	})

	ginkgo.It("refuses a negative asset size", func() {
		api, _ := serveRelease(releaseJSON("v1", false, asset("a", -1, nil, "https://example.com/a")))
		_, err := newTestClient(api).Release(context.Background(), "o", "r", "")
		Expect(err).To(MatchError(ContainSubstring("negative size")))
	})

	ginkgo.DescribeTable("refuses an asset without a usable download URL",
		func(u string) {
			api, _ := serveRelease(releaseJSON("v1", false, asset("a", 1, nil, u)))
			_, err := newTestClient(api).Release(context.Background(), "o", "r", "")
			Expect(err).To(MatchError(ContainSubstring("has no usable download URL")))
		},
		ginkgo.Entry("empty", ""),
		ginkgo.Entry("relative", "/o/r/releases/download/v1/a"),
		ginkgo.Entry("a file URL", "file:///etc/passwd"),
		ginkgo.Entry("unparseable", "https://example.com/%zz"),
	)

	ginkgo.It("requires https asset download URLs from an https API", func() {
		body := releaseJSON("v1", false, asset("a", 1, nil, "http://example.com/a"))
		srv, _ := newRecordedTLSServer(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		})
		_, err := newTLSTestClient(srv).Release(context.Background(), "o", "r", "")
		Expect(err).To(MatchError(ContainSubstring(`asset "a" download URL is not https`)))
	})

	ginkgo.It("accepts https asset download URLs from an https API", func() {
		body := releaseJSON("v1", false, asset("a", 1, nil, "https://example.com/a"))
		srv, _ := newRecordedTLSServer(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		})
		rel, err := newTLSTestClient(srv).Release(context.Background(), "o", "r", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(rel.Assets[0].URL).To(Equal("https://example.com/a"))
	})

	ginkgo.It("accepts an http asset download URL from an http API", func() {
		api, _ := serveRelease(releaseJSON("v1", false, asset("a", 1, nil, "http://example.com/a")))
		rel, err := newTestClient(api).Release(context.Background(), "o", "r", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(rel.Assets[0].URL).To(Equal("http://example.com/a"))
	})

	ginkgo.DescribeTable("normalises an asset's digest",
		func(digest any, want string) {
			api, _ := serveRelease(releaseJSON("v1", false, asset("a", 1, digest, "https://example.com/a")))
			rel, err := newTestClient(api).Release(context.Background(), "o", "r", "")
			Expect(err).NotTo(HaveOccurred())
			Expect(rel.Assets[0].Digest).To(Equal(want))
		},
		ginkgo.Entry("sha256 is kept", digestA, digestA),
		ginkgo.Entry("null is none", nil, ""),
		ginkgo.Entry("empty is none", "", ""),
		ginkgo.Entry("another algorithm is none", "sha512:"+strings.Repeat("ab", 64), ""),
	)

	ginkgo.DescribeTable("refuses a malformed digest",
		func(digest string) {
			api, _ := serveRelease(releaseJSON("v1", false, asset("a", 1, digest, "https://example.com/a")))
			_, err := newTestClient(api).Release(context.Background(), "o", "r", "")
			Expect(err).To(MatchError(ContainSubstring("malformed")))
		},
		ginkgo.Entry("no algorithm", strings.Repeat("ab", 32)),
		ginkgo.Entry("an empty algorithm", ":"+strings.Repeat("ab", 32)),
		ginkgo.Entry("short hex", "sha256:abcd"),
		ginkgo.Entry("upper-case hex", "sha256:"+strings.Repeat("AB", 32)),
		ginkgo.Entry("non-hex", "sha256:"+strings.Repeat("zz", 32)),
	)

	ginkgo.It("refuses a response that echoes the token in a server-chosen string", func() {
		srv, _ := newRecordedServer(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(releaseJSON("v1", false,
				asset(r.Header.Get("Authorization"), 1, nil, "https://example.com/a"))))
		})
		_, err := newTestClient(srv.URL).Release(context.Background(), "o", "r", "")
		Expect(err).To(MatchError(ContainSubstring("echoed the API token")))
		Expect(err.Error()).NotTo(ContainSubstring(testToken))
	})

	ginkgo.It("refuses a response whose decoded asset name is the JSON-escaped token", func() {
		escaped := `\u0067` + strings.TrimPrefix(testToken, "g")
		api, _ := serveRelease(`{"tag_name":"v1","assets":[{"name":"` + escaped +
			`","size":1,"browser_download_url":"https://example.com/a"}]}`)
		rel, err := newTestClient(api).Release(context.Background(), "o", "r", "")
		Expect(err).To(MatchError(ContainSubstring("echoed the API token")))
		Expect(err.Error()).NotTo(ContainSubstring(testToken))
		Expect(rel).To(BeNil())
	})
})

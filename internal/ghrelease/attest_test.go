package ghrelease

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/klauspost/compress/snappy"
	ginkgo "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// artifactHex is the SHA-256 the attestation specs ask about.
var artifactHex = strings.Repeat("cd", 32)

// attestationsPath is the API path for artifactHex in o/r.
var attestationsPath = "/repos/o/r/attestations/sha256:" + artifactHex

// bundleJSON is a stand-in sigstore bundle; the client does not parse it.
func bundleJSON(n int) string {
	return fmt.Sprintf(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","n":%d}`, n)
}

// paddedBundle is a JSON bundle of exactly n bytes (n >= 8).
func paddedBundle(n int) string {
	return `{"p":"` + strings.Repeat("x", n-8) + `"}`
}

// attestationsPage renders one page of the attestations endpoint. Each
// entry is either an inline bundle (JSON text) or, prefixed "url:", a
// bundle_url with "bundle": null, as GitHub sends today.
func attestationsPage(entries ...string) string {
	list := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		if u, ok := strings.CutPrefix(e, "url:"); ok {
			list = append(list, map[string]any{"bundle": nil, "bundle_url": u})
			continue
		}
		list = append(list, map[string]any{"bundle": json.RawMessage(e)})
	}
	b, err := json.Marshal(map[string]any{"attestations": list})
	Expect(err).NotTo(HaveOccurred())
	return string(b)
}

// serveBlob starts a blob-storage server answering every request with body.
func serveBlob(body []byte) (string, *recorder) {
	srv, rec := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	})
	return srv.URL, rec
}

var _ = ginkgo.Describe("Attestations", func() {
	ginkgo.It("returns an inline bundle, asking for 100 per page with the token", func() {
		api, rec := serveRelease(attestationsPage(bundleJSON(1)))
		got, err := newTestClient(api).Attestations(context.Background(), "o", "r", artifactHex)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HaveLen(1))
		Expect(got[0]).To(MatchJSON(bundleJSON(1)))
		reqs := rec.requests()
		Expect(reqs).To(HaveLen(1))
		Expect(reqs[0].URL.Path).To(Equal(attestationsPath))
		Expect(reqs[0].URL.Query().Get("per_page")).To(Equal("100"))
		Expect(rec.auths()).To(Equal([]string{"Bearer " + testToken}))
	})

	ginkgo.It("downloads and snappy-decodes a bundle_url without the token", func() {
		blob, blobRec := serveBlob(snappy.Encode(nil, []byte(bundleJSON(2))))
		api, _ := serveRelease(attestationsPage("url:" + blob + "/bundle"))
		got, err := newTestClient(api).Attestations(context.Background(), "o", "r", artifactHex)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HaveLen(1))
		Expect(got[0]).To(MatchJSON(bundleJSON(2)))
		Expect(blobRec.auths()).To(Equal([]string{""}))
	})

	ginkgo.It("follows Link rel=next across pages, keeping order and the token", func() {
		var api string
		srv, rec := newRecordedServer(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Query().Get("after") {
			case "":
				w.Header().Set("Link", fmt.Sprintf(`<%s%s?per_page=100&after=c2>; rel="next"`, api, attestationsPath))
				_, _ = w.Write([]byte(attestationsPage(bundleJSON(1), bundleJSON(2))))
			case "c2":
				w.Header().Add("Link", fmt.Sprintf(`<%s%s?per_page=100>; rel="first"`, api, attestationsPath))
				w.Header().Add("Link", fmt.Sprintf(`<%s?per_page=100&after=c3>; rel="next"`, attestationsPath))
				_, _ = w.Write([]byte(attestationsPage(bundleJSON(3))))
			default:
				_, _ = w.Write([]byte(attestationsPage(bundleJSON(4))))
			}
		})
		api = srv.URL
		got, err := newTestClient(api).Attestations(context.Background(), "o", "r", artifactHex)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HaveLen(4))
		for i, b := range got {
			Expect(b).To(MatchJSON(bundleJSON(i + 1)))
		}
		Expect(rec.requests()).To(HaveLen(3))
		Expect(rec.requests()[2].URL.Query().Get("after")).To(Equal("c3"))
		Expect(rec.auths()).To(HaveEach("Bearer " + testToken))
	})

	ginkgo.It("refuses a next link that leaves the API origin, without following it", func() {
		elsewhere, elsewhereRec := serveRelease(attestationsPage())
		srv, _ := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Link", fmt.Sprintf(`<%s/page2>; rel="next"`, elsewhere))
			_, _ = w.Write([]byte(attestationsPage(bundleJSON(1))))
		})
		_, err := newTestClient(srv.URL).Attestations(context.Background(), "o", "r", artifactHex)
		Expect(err).To(MatchError(ContainSubstring("leaves the GitHub API origin")))
		Expect(elsewhereRec.requests()).To(BeEmpty())
	})

	ginkgo.It("never puts the token in an error when a next link echoes it", func() {
		srv, _ := newRecordedServer(func(w http.ResponseWriter, r *http.Request) {
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			// In the path, where URL redaction keeps it: the scrub must catch it.
			w.Header().Set("Link", `<https://elsewhere.invalid/`+token+`/page2>; rel="next"`)
			_, _ = w.Write([]byte(attestationsPage(bundleJSON(1))))
		})
		_, err := newTestClient(srv.URL).Attestations(context.Background(), "o", "r", artifactHex)
		Expect(err).To(MatchError(ContainSubstring("echoed the API token")))
		Expect(err.Error()).NotTo(ContainSubstring(testToken))
	})

	ginkgo.It("redacts a token a next link echoes in its query", func() {
		srv, _ := newRecordedServer(func(w http.ResponseWriter, r *http.Request) {
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			w.Header().Set("Link", `<https://elsewhere.invalid/page2?t=`+token+`>; rel="next"`)
			_, _ = w.Write([]byte(attestationsPage(bundleJSON(1))))
		})
		_, err := newTestClient(srv.URL).Attestations(context.Background(), "o", "r", artifactHex)
		Expect(err).To(MatchError("pagination link https://elsewhere.invalid/page2?t=xxxxx leaves the GitHub API origin"))
		Expect(err.Error()).NotTo(ContainSubstring(testToken))
	})

	ginkgo.It("refuses a bundle_url carrying the JSON-escaped token, without fetching it", func() {
		blob, blobRec := serveBlob(snappy.Encode(nil, []byte(bundleJSON(1))))
		escaped := `\u0067` + strings.TrimPrefix(testToken, "g")
		api, _ := serveRelease(`{"attestations":[{"bundle":null,"bundle_url":"` + blob + `/b?t=` + escaped + `"}]}`)
		_, err := newTestClient(api).Attestations(context.Background(), "o", "r", artifactHex)
		Expect(err).To(MatchError(ContainSubstring("echoed the API token")))
		Expect(err.Error()).NotTo(ContainSubstring(testToken))
		Expect(blobRec.requests()).To(BeEmpty())
	})

	ginkgo.It("stops a server that never stops paginating", func() {
		var api string
		srv, rec := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Link", fmt.Sprintf(`<%s%s?after=more>; rel="next"`, api, attestationsPath))
			_, _ = w.Write([]byte(attestationsPage()))
		})
		api = srv.URL
		_, err := newTestClient(api).Attestations(context.Background(), "o", "r", artifactHex)
		Expect(err).To(MatchError(ContainSubstring("more than 20 pages")))
		Expect(rec.requests()).To(HaveLen(maxAttestationPages))
	})

	ginkgo.It("returns no bundles and no error for a 404", func() {
		srv, _ := newRecordedServer(http.NotFound)
		got, err := newTestClient(srv.URL).Attestations(context.Background(), "o", "r", artifactHex)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(BeEmpty())
	})

	ginkgo.It("returns no bundles and no error for an empty list", func() {
		api, _ := serveRelease(attestationsPage())
		got, err := newTestClient(api).Attestations(context.Background(), "o", "r", artifactHex)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(BeEmpty())
	})

	ginkgo.It("reports a rate limit rather than treating it as no attestations", func() {
		srv, _ := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.WriteHeader(http.StatusForbidden)
		})
		_, err := newTestClient(srv.URL).Attestations(context.Background(), "o", "r", artifactHex)
		var rl *RateLimitError
		Expect(errors.As(err, &rl)).To(BeTrue())
	})

	ginkgo.It("reports a 404 on a later page as an error", func() {
		var api string
		srv, _ := newRecordedServer(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("after") != "" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Link", fmt.Sprintf(`<%s%s?after=x>; rel="next"`, api, attestationsPath))
			_, _ = w.Write([]byte(attestationsPage(bundleJSON(1))))
		})
		api = srv.URL
		_, err := newTestClient(api).Attestations(context.Background(), "o", "r", artifactHex)
		var nf *NotFoundError
		Expect(errors.As(err, &nf)).To(BeTrue())
	})

	ginkgo.DescribeTable("refuses an artifact digest that is not 64 lower-case hex, before any request",
		func(hex string) {
			api, rec := serveRelease(attestationsPage())
			_, err := newTestClient(api).Attestations(context.Background(), "o", "r", hex)
			Expect(err).To(MatchError(ContainSubstring("invalid artifact digest")))
			Expect(rec.requests()).To(BeEmpty())
		},
		ginkgo.Entry("empty", ""),
		ginkgo.Entry("prefixed", "sha256:"+artifactHex),
		ginkgo.Entry("short", artifactHex[:63]),
		ginkgo.Entry("upper case", strings.ToUpper(artifactHex)),
		ginkgo.Entry("a path", "../../x"),
	)

	ginkgo.It("refuses a bundle_url body over 16 MiB", func() {
		blob, _ := serveBlob(make([]byte, maxBundleDownload+1))
		api, _ := serveRelease(attestationsPage("url:" + blob + "/bundle"))
		_, err := newTestClient(api).Attestations(context.Background(), "o", "r", artifactHex)
		Expect(err).To(MatchError(ContainSubstring("exceeds the 16777216-byte limit")))
	})

	ginkgo.It("refuses a snappy block declaring more than 64 MiB before decoding it", func() {
		bomb := binary.AppendUvarint(nil, maxBundleBytes+1)
		bomb = append(bomb, 0x00)
		blob, _ := serveBlob(bomb)
		api, _ := serveRelease(attestationsPage("url:" + blob + "/bundle"))
		_, err := newTestClient(api).Attestations(context.Background(), "o", "r", artifactHex)
		Expect(err).To(MatchError(ContainSubstring("decoded size 67108865 would take the bundles past the 67108864-byte total limit")))
	})

	ginkgo.It("refuses decoded bundles that together exceed 64 MiB, before decoding the one that would", func() {
		blob, blobRec := serveBlob(snappy.Encode(nil, []byte(paddedBundle(40<<20))))
		api, _ := serveRelease(attestationsPage("url:"+blob+"/a", "url:"+blob+"/b"))
		_, err := newTestClient(api).Attestations(context.Background(), "o", "r", artifactHex)
		Expect(err).To(MatchError(ContainSubstring("would take the bundles past the 67108864-byte total limit")))
		Expect(blobRec.requests()).To(HaveLen(2))
	})

	ginkgo.It("counts inline bundles against the 64 MiB total", func() {
		blob, _ := serveBlob(snappy.Encode(nil, []byte(paddedBundle(60<<20))))
		api, _ := serveRelease(attestationsPage("url:"+blob+"/a", paddedBundle(5<<20)))
		_, err := newTestClient(api).Attestations(context.Background(), "o", "r", artifactHex)
		Expect(err).To(MatchError(ContainSubstring("would take the bundles past the 67108864-byte total limit")))
	})

	ginkgo.It("refuses more than 100 attestations across pages", func() {
		page := func(n int) string {
			entries := make([]string, n)
			for i := range entries {
				entries[i] = bundleJSON(i)
			}
			return attestationsPage(entries...)
		}
		var api string
		srv, _ := newRecordedServer(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("after") == "" {
				w.Header().Set("Link", fmt.Sprintf(`<%s%s?after=p2>; rel="next"`, api, attestationsPath))
			}
			_, _ = w.Write([]byte(page(maxAttestations/2 + 1)))
		})
		api = srv.URL
		_, err := newTestClient(api).Attestations(context.Background(), "o", "r", artifactHex)
		Expect(err).To(MatchError(ContainSubstring("more than 100 attestations")))
	})

	ginkgo.It("accepts exactly 100 attestations", func() {
		entries := make([]string, maxAttestations)
		for i := range entries {
			entries[i] = bundleJSON(i)
		}
		api, _ := serveRelease(attestationsPage(entries...))
		got, err := newTestClient(api).Attestations(context.Background(), "o", "r", artifactHex)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HaveLen(maxAttestations))
	})

	ginkgo.DescribeTable("refuses a bundle_url body that is not a snappy-compressed JSON bundle",
		func(body []byte, want string) {
			blob, _ := serveBlob(body)
			api, _ := serveRelease(attestationsPage("url:" + blob + "/bundle"))
			_, err := newTestClient(api).Attestations(context.Background(), "o", "r", artifactHex)
			Expect(err).To(MatchError(ContainSubstring(want)))
		},
		ginkgo.Entry("empty", []byte{}, "snappy header"),
		ginkgo.Entry("uncompressed JSON", []byte(bundleJSON(1)), "snappy"),
		ginkgo.Entry("a truncated block", snappy.Encode(nil, []byte(bundleJSON(1)))[:10], "snappy decode"),
		ginkgo.Entry("snappy stream format", streamEncoded([]byte(bundleJSON(1))), "snappy"),
		ginkgo.Entry("compressed non-JSON", snappy.Encode(nil, []byte("not json")), "is not JSON"),
	)

	ginkgo.DescribeTable("refuses an inline bundle that is not a JSON object",
		func(inline string) {
			api, _ := serveRelease(attestationsPage(inline))
			_, err := newTestClient(api).Attestations(context.Background(), "o", "r", artifactHex)
			Expect(err).To(MatchError(ContainSubstring("inline bundle is not a JSON object")))
		},
		ginkgo.Entry("an array", `[1]`),
		ginkgo.Entry("a string", `"x"`),
		ginkgo.Entry("a number", `42`),
		ginkgo.Entry("a boolean", `true`),
	)

	ginkgo.It("requires an https bundle_url from an https API, without fetching it", func() {
		blob, blobRec := serveBlob(snappy.Encode(nil, []byte(bundleJSON(1))))
		body := attestationsPage("url:" + blob + "/bundle")
		srv, _ := newRecordedTLSServer(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		})
		_, err := newTLSTestClient(srv).Attestations(context.Background(), "o", "r", artifactHex)
		Expect(err).To(MatchError(ContainSubstring("is not an https URL")))
		Expect(blobRec.requests()).To(BeEmpty())
	})

	ginkgo.It("downloads an https bundle_url from an https API", func() {
		blob, _ := newRecordedTLSServer(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(snappy.Encode(nil, []byte(bundleJSON(1))))
		})
		body := attestationsPage("url:" + blob.URL + "/bundle")
		srv, _ := newRecordedTLSServer(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		})
		got, err := newTLSTestClient(srv).Attestations(context.Background(), "o", "r", artifactHex)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HaveLen(1))
		Expect(got[0]).To(MatchJSON(bundleJSON(1)))
	})

	ginkgo.It("refuses an attestation with neither an inline bundle nor a bundle_url", func() {
		api, _ := serveRelease(`{"attestations":[{"bundle":null}]}`)
		_, err := newTestClient(api).Attestations(context.Background(), "o", "r", artifactHex)
		Expect(err).To(MatchError(ContainSubstring("neither an inline bundle nor a bundle_url")))
	})

	ginkgo.It("reports a missing bundle_url as a *NotFoundError", func() {
		blob, _ := newRecordedServer(http.NotFound)
		api, _ := serveRelease(attestationsPage("url:" + blob.URL + "/gone"))
		_, err := newTestClient(api).Attestations(context.Background(), "o", "r", artifactHex)
		var nf *NotFoundError
		Expect(errors.As(err, &nf)).To(BeTrue())
	})
})

// streamEncoded compresses b in snappy's framed stream format, which the
// bundle_url decoder must not accept as block format.
func streamEncoded(b []byte) []byte {
	var buf strings.Builder
	w := snappy.NewBufferedWriter(&buf)
	_, err := w.Write(b)
	Expect(err).NotTo(HaveOccurred())
	Expect(w.Close()).To(Succeed())
	return []byte(buf.String())
}

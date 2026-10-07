package ghrelease

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	ginkgo "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/source"
)

// testToken is the API token every spec's client carries, so any spec can
// assert it never reaches a non-API handler or an error message.
const testToken = "ghp_TESTTOKEN0123456789abcdef"

// newTestClient returns a client for the API at apiURL with testToken and a
// source.NewHTTPClient whose idle deadline is short enough for tests.
func newTestClient(apiURL string) *Client {
	return New(apiURL, testToken, source.NewHTTPClient(source.WithIdleTimeout(5*time.Second)))
}

// recorder is a handler wrapper that records a copy of every request
// it serves, so a spec can assert on the headers each server received.
type recorder struct {
	mu   sync.Mutex
	reqs []*http.Request
	next http.HandlerFunc
}

func (rec *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec.mu.Lock()
	rec.reqs = append(rec.reqs, r.Clone(context.Background()))
	rec.mu.Unlock()
	rec.next(w, r)
}

// requests returns the requests served so far.
func (rec *recorder) requests() []*http.Request {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return slices.Clone(rec.reqs)
}

// auths returns the Authorization header of each request served so far.
func (rec *recorder) auths() []string {
	reqs := rec.requests()
	out := make([]string, 0, len(reqs))
	for _, r := range reqs {
		out = append(out, r.Header.Get("Authorization"))
	}
	return out
}

// newRecordedServer starts a plain-http test server for h, wrapped in a
// recorder, and closes it when the spec ends.
func newRecordedServer(h http.HandlerFunc) (*httptest.Server, *recorder) {
	rec := &recorder{next: h}
	srv := httptest.NewServer(rec)
	ginkgo.DeferCleanup(srv.Close)
	return srv, rec
}

// newRecordedTLSServer is newRecordedServer over https.
func newRecordedTLSServer(h http.HandlerFunc) (*httptest.Server, *recorder) {
	rec := &recorder{next: h}
	srv := httptest.NewTLSServer(rec)
	ginkgo.DeferCleanup(srv.Close)
	return srv, rec
}

// newTLSTestClient returns a client with testToken whose API is the TLS test
// server srv. httptest's TLS servers share one certificate, so the client
// trusts every one of them through srv's transport; the redirect policy is
// source.NewHTTPClient's.
func newTLSTestClient(srv *httptest.Server) *Client {
	hc := &http.Client{Transport: srv.Client().Transport, CheckRedirect: source.NewHTTPClient().CheckRedirect}
	return New(srv.URL, testToken, hc)
}

var _ = ginkgo.Describe("New", func() {
	ginkgo.DescribeTable("defers an unusable API URL to the first API call",
		func(apiURL string) {
			_, err := newTestClient(apiURL).Repo(context.Background(), "o", "r")
			Expect(err).To(MatchError(ContainSubstring("invalid GitHub API URL")))
			Expect(err.Error()).NotTo(ContainSubstring("s3cret"))
		},
		ginkgo.Entry("no scheme", "api.github.com"),
		ginkgo.Entry("a non-http scheme", "ftp://api.github.com"),
		ginkgo.Entry("no host", "https:///api"),
		ginkgo.Entry("credentials", "https://user:s3cret@api.github.com"),
		ginkgo.Entry("a query", "https://api.github.com/?x=1"),
		ginkgo.Entry("a fragment", "https://api.github.com/#x"),
		ginkgo.Entry("unparseable", "https://api.github.com/%zz"),
	)

	ginkgo.DescribeTable("refuses a token for a plain-http API URL off loopback, before any request",
		func(apiURL string) {
			_, err := newTestClient(apiURL).Repo(context.Background(), "o", "r")
			Expect(err).To(MatchError(ContainSubstring("refusing to send the API token over plain http")))
			Expect(err.Error()).NotTo(ContainSubstring(testToken))
		},
		ginkgo.Entry("a public host", "http://api.example.com"),
		ginkgo.Entry("a private address", "http://10.0.0.1:8080/api/v3"),
		ginkgo.Entry("a name merely starting with 127", "http://127.example.com"),
		ginkgo.Entry("a localhost subdomain", "http://localhost.example.com"),
	)

	ginkgo.DescribeTable("accepts an API URL that keeps the token off the network in clear",
		func(apiURL, token string) {
			Expect(New(apiURL, token, source.NewHTTPClient()).apiErr).NotTo(HaveOccurred())
		},
		ginkgo.Entry("https with a token", "https://ghe.example.com/api/v3", testToken),
		ginkgo.Entry("http without a token", "http://ghe.example.com/api/v3", ""),
		ginkgo.Entry("http to 127.0.0.1", "http://127.0.0.1:8080", testToken),
		ginkgo.Entry("http to elsewhere in 127/8", "http://127.8.9.10", testToken),
		ginkgo.Entry("http to ::1", "http://[::1]:8080", testToken),
		ginkgo.Entry("http to localhost", "http://localhost:8080", testToken),
		ginkgo.Entry("http to LOCALHOST", "http://LOCALHOST", testToken),
	)

	// refusal is "" for an accepted URL, "plaintext" for a token refused over
	// plain http, and "invalid" for a URL that is not an API root.
	ginkgo.DescribeTable("CheckAPIURL applies exactly New's rules",
		func(apiURL, token, refusal string) {
			checked := CheckAPIURL(apiURL, token != "")
			Expect(New(apiURL, token, source.NewHTTPClient()).apiErr != nil).To(Equal(refusal != ""), "New(%q)", apiURL)
			if refusal == "" {
				Expect(checked).NotTo(HaveOccurred())
				return
			}
			var ae *APIURLError
			Expect(errors.As(checked, &ae)).To(BeTrue(), "CheckAPIURL(%q) = %v", apiURL, checked)
			Expect(ae.Plaintext).To(Equal(refusal == "plaintext"))
			Expect(checked.Error()).NotTo(ContainSubstring("s3cret"))
		},
		ginkgo.Entry("https with a token", "https://api.github.com", testToken, ""),
		ginkgo.Entry("http to LOCALHOST with a token", "http://LOCALHOST:8080", testToken, ""),
		ginkgo.Entry("http to 127.0.0.1 with a token", "http://127.0.0.1:8080", testToken, ""),
		ginkgo.Entry("http off loopback without a token", "http://ghe.example.com/api/v3", "", ""),
		ginkgo.Entry("http off loopback with a token", "http://ghe.example.com/api/v3", testToken, "plaintext"),
		ginkgo.Entry("a localhost subdomain with a token", "http://localhost.example.com", testToken, "plaintext"),
		ginkgo.Entry("credentials", "https://user:s3cret@api.github.com", "", "invalid"),
		ginkgo.Entry("no scheme", "api.github.com", "", "invalid"),
		ginkgo.Entry("a query", "https://api.github.com/?x=1", "", "invalid"),
	)

	ginkgo.It("uses source.NewHTTPClient when given no client", func() {
		srv, rec := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"description":"x"}`))
		})
		got, err := New(srv.URL, testToken, nil).Repo(context.Background(), "o", "r")
		Expect(err).NotTo(HaveOccurred())
		Expect(got.Description).To(Equal("x"))
		Expect(rec.auths()).To(Equal([]string{"Bearer " + testToken}))
	})

	ginkgo.It("leaves the caller's client and its redirect policy untouched", func() {
		hc := source.NewHTTPClient()
		policy := reflect.ValueOf(hc.CheckRedirect).Pointer()
		c := New("https://api.github.com", testToken, hc)
		Expect(reflect.ValueOf(hc.CheckRedirect).Pointer()).To(Equal(policy))
		Expect(c.hc).NotTo(BeIdenticalTo(hc))
	})
})

var _ = ginkgo.Describe("Repo", func() {
	ginkgo.It("fetches /repos/OWNER/REPO with the token and REST API headers", func() {
		srv, rec := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"description":"A fast grep"}`))
		})
		got, err := newTestClient(srv.URL).Repo(context.Background(), "BurntSushi", "ripgrep")
		Expect(err).NotTo(HaveOccurred())
		Expect(got.Description).To(Equal("A fast grep"))
		reqs := rec.requests()
		Expect(reqs).To(HaveLen(1))
		Expect(reqs[0].URL.Path).To(Equal("/repos/BurntSushi/ripgrep"))
		Expect(reqs[0].Header.Get("Accept")).To(Equal("application/vnd.github+json"))
		Expect(reqs[0].Header.Get("X-GitHub-Api-Version")).To(Equal("2022-11-28"))
		Expect(reqs[0].Header.Get("Authorization")).To(Equal("Bearer " + testToken))
	})

	ginkgo.It("keeps a GitHub Enterprise path prefix and ignores a trailing slash", func() {
		srv, rec := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"description":"x"}`))
		})
		_, err := newTestClient(srv.URL+"/api/v3/").Repo(context.Background(), "o", "r")
		Expect(err).NotTo(HaveOccurred())
		Expect(rec.requests()[0].URL.Path).To(Equal("/api/v3/repos/o/r"))
	})

	ginkgo.It("reads a null description as empty", func() {
		srv, _ := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"description":null}`))
		})
		got, err := newTestClient(srv.URL).Repo(context.Background(), "o", "r")
		Expect(err).NotTo(HaveOccurred())
		Expect(got.Description).To(BeEmpty())
	})

	ginkgo.It("sends no Authorization header without a token", func() {
		srv, rec := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{}`))
		})
		_, err := New(srv.URL, "", source.NewHTTPClient()).Repo(context.Background(), "o", "r")
		Expect(err).NotTo(HaveOccurred())
		Expect(rec.auths()).To(Equal([]string{""}))
	})

	ginkgo.DescribeTable("refuses an owner or repo that is not a GitHub name, before any request",
		func(owner, repo string) {
			srv, rec := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{}`))
			})
			_, err := newTestClient(srv.URL).Repo(context.Background(), owner, repo)
			Expect(err).To(MatchError(ContainSubstring("invalid GitHub repository")))
			Expect(len(rec.requests())).To(BeZero())
		},
		ginkgo.Entry("empty owner", "", "r"),
		ginkgo.Entry("empty repo", "o", ""),
		ginkgo.Entry("dot-dot owner", "..", "r"),
		ginkgo.Entry("an owner with a dot, which no GitHub account has", "o.x", "r"),
		ginkgo.Entry("an owner starting with a hyphen", "-o", "r"),
		ginkgo.Entry("dot repo", "o", "."),
		ginkgo.Entry("a slash", "o", "r/../../x"),
		ginkgo.Entry("an escape", "o", "r%2F.."),
		ginkgo.Entry("whitespace", "o", "r x"),
	)

	ginkgo.It("accepts a repository name starting with a dot", func() {
		srv, _ := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{}`))
		})
		_, err := newTestClient(srv.URL).Repo(context.Background(), "o", ".github")
		Expect(err).NotTo(HaveOccurred())
	})

	ginkgo.It("reports a 404 as a *NotFoundError", func() {
		srv, _ := newRecordedServer(http.NotFound)
		_, err := newTestClient(srv.URL).Repo(context.Background(), "o", "r")
		var nf *NotFoundError
		Expect(errors.As(err, &nf)).To(BeTrue())
		Expect(nf.URL).To(Equal(srv.URL + "/repos/o/r"))
	})

	ginkgo.It("reports a primary rate limit as a *RateLimitError with its reset time", func() {
		srv, _ := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", "1767225600")
			w.WriteHeader(http.StatusForbidden)
		})
		_, err := newTestClient(srv.URL).Repo(context.Background(), "o", "r")
		var rl *RateLimitError
		Expect(errors.As(err, &rl)).To(BeTrue())
		Expect(rl.Reset).To(BeTemporally("==", time.Unix(1767225600, 0)))
		Expect(rl.Authenticated).To(BeTrue())
		Expect(err).To(MatchError(ContainSubstring("2026-01-01T00:00:00Z")))
	})

	ginkgo.It("reports a secondary rate limit (429 with Retry-After) as a *RateLimitError", func() {
		srv, _ := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
		})
		before := time.Now()
		_, err := New(srv.URL, "", source.NewHTTPClient()).Repo(context.Background(), "o", "r")
		var rl *RateLimitError
		Expect(errors.As(err, &rl)).To(BeTrue())
		Expect(rl.Authenticated).To(BeFalse())
		Expect(rl.Reset).To(BeTemporally("~", before.Add(time.Minute), 5*time.Second))
	})

	ginkgo.It("does not treat a 403 without rate-limit headers as a rate limit", func() {
		srv, _ := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		})
		_, err := newTestClient(srv.URL).Repo(context.Background(), "o", "r")
		var rl *RateLimitError
		Expect(errors.As(err, &rl)).To(BeFalse())
		Expect(err).To(MatchError(ContainSubstring("HTTP 403")))
	})

	ginkgo.It("refuses a response whose decoded description is the JSON-escaped token", func() {
		// \u0067 is 'g', so the raw body never contains the token's bytes.
		escaped := `\u0067` + strings.TrimPrefix(testToken, "g")
		srv, _ := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"description":"` + escaped + `"}`))
		})
		got, err := newTestClient(srv.URL).Repo(context.Background(), "o", "r")
		Expect(err).To(MatchError(ContainSubstring("echoed the API token")))
		Expect(err.Error()).NotTo(ContainSubstring(testToken))
		Expect(got).To(BeNil())
	})

	ginkgo.It("refuses an API response over the size cap", func() {
		srv, _ := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"description":"` + strings.Repeat("x", maxAPIResponse) + `"}`))
		})
		_, err := newTestClient(srv.URL).Repo(context.Background(), "o", "r")
		Expect(err).To(MatchError(ContainSubstring("exceeds the 16777216-byte limit")))
	})

	ginkgo.It("drops the token on a redirect to another port of the API host", func() {
		other, otherRec := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"description":"moved"}`))
		})
		api, apiRec := newRecordedServer(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL+"/repos/o/r", http.StatusFound)
		})
		got, err := newTestClient(api.URL).Repo(context.Background(), "o", "r")
		Expect(err).NotTo(HaveOccurred())
		Expect(got.Description).To(Equal("moved"))
		Expect(apiRec.auths()).To(Equal([]string{"Bearer " + testToken}))
		Expect(otherRec.auths()).To(Equal([]string{""}))
	})

	ginkgo.It("refuses an https→http redirect on an API call without contacting the http host", func() {
		plain, plainRec := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{}`))
		})
		api, _ := newRecordedTLSServer(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, plain.URL+"/repos/o/r", http.StatusFound)
		})
		_, err := newTLSTestClient(api).Repo(context.Background(), "o", "r")
		Expect(errors.Is(err, source.ErrInsecureRedirect)).To(BeTrue())
		Expect(err.Error()).NotTo(ContainSubstring(testToken))
		Expect(plainRec.requests()).To(BeEmpty())
	})

	ginkgo.It("drops the token on a redirect to the API host and port under another scheme", func() {
		// httptest cannot serve http and https on one port, so this drives
		// the redirect policy directly. http→https passes the base policy.
		c := New("http://127.0.0.1:8080", testToken, nil)
		from, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/repos/o/r", http.NoBody)
		Expect(err).NotTo(HaveOccurred())
		to, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:8080/repos/o/r", http.NoBody)
		Expect(err).NotTo(HaveOccurred())
		to.Header.Set("Authorization", "Bearer "+testToken)
		Expect(c.hc.CheckRedirect(to, []*http.Request{from})).To(Succeed())
		Expect(to.Header.Get("Authorization")).To(BeEmpty())
	})

	ginkgo.It("sends the token again only once a redirect that left the API origin returns to it", func() {
		// net/http copies the first request's headers onto every hop; the
		// redirect policy strips Authorization off the API origin only, so
		// the other host never sees the token and the API sees it again.
		var api *httptest.Server
		other, otherRec := newRecordedServer(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, api.URL+"/back", http.StatusFound)
		})
		api, apiRec := newRecordedServer(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/repos/o/r" {
				http.Redirect(w, r, other.URL+"/out", http.StatusFound)
				return
			}
			_, _ = w.Write([]byte(`{"description":"back"}`))
		})
		got, err := newTestClient(api.URL).Repo(context.Background(), "o", "r")
		Expect(err).NotTo(HaveOccurred())
		Expect(got.Description).To(Equal("back"))
		Expect(otherRec.auths()).To(Equal([]string{""}))
		Expect(apiRec.auths()).To(Equal([]string{"Bearer " + testToken, "Bearer " + testToken}))
	})

	ginkgo.It("keeps the token on a redirect within the API origin", func() {
		var srv *httptest.Server
		srv, rec := newRecordedServer(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/repos/o/r" {
				http.Redirect(w, r, srv.URL+"/repositories/42", http.StatusMovedPermanently)
				return
			}
			_, _ = w.Write([]byte(`{"description":"renamed"}`))
		})
		got, err := newTestClient(srv.URL).Repo(context.Background(), "o", "r")
		Expect(err).NotTo(HaveOccurred())
		Expect(got.Description).To(Equal("renamed"))
		Expect(rec.auths()).To(Equal([]string{"Bearer " + testToken, "Bearer " + testToken}))
	})

	ginkgo.It("never puts the token in an error when a redirect's Location echoes it unparseably", func() {
		srv, _ := newRecordedServer(func(w http.ResponseWriter, r *http.Request) {
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			w.Header().Set("Location", "%zz"+token)
			w.WriteHeader(http.StatusFound)
		})
		_, err := newTestClient(srv.URL).Repo(context.Background(), "o", "r")
		Expect(err).To(MatchError(ContainSubstring("echoed the API token")))
		Expect(err.Error()).NotTo(ContainSubstring(testToken))
	})

	ginkgo.DescribeTable("never puts the token in an error, even when the server echoes it",
		func(status int, header map[string]string, body string) {
			srv, _ := newRecordedServer(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range header {
					w.Header().Set(k, v)
				}
				w.Header().Set("X-Echo", r.Header.Get("Authorization"))
				w.WriteHeader(status)
				_, _ = w.Write([]byte(strings.ReplaceAll(body, "TOKEN", r.Header.Get("Authorization"))))
			})
			_, err := newTestClient(srv.URL).Repo(context.Background(), "o", "r")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).NotTo(ContainSubstring(testToken))
		},
		ginkgo.Entry("not found", http.StatusNotFound, nil, `{"message":"TOKEN not found"}`),
		ginkgo.Entry("rate limited", http.StatusForbidden, map[string]string{"X-RateLimit-Remaining": "0"}, `{"message":"TOKEN"}`),
		ginkgo.Entry("server error", http.StatusInternalServerError, nil, `TOKEN`),
		ginkgo.Entry("unauthorized", http.StatusUnauthorized, nil, `{"message":"bad credentials: TOKEN"}`),
		ginkgo.Entry("malformed JSON", http.StatusOK, nil, `{"description": TOKEN`),
		ginkgo.Entry("wrong JSON type", http.StatusOK, nil, `{"description": ["TOKEN"]}`),
		ginkgo.Entry("a successful body", http.StatusOK, nil, `{"description": "TOKEN"}`),
	)
})

var _ = ginkgo.Describe("Download", func() {
	ginkgo.It("returns the body without the token, even from the API host", func() {
		srv, rec := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("asset bytes"))
		})
		got, err := newTestClient(srv.URL).Download(context.Background(), srv.URL+"/o/r/releases/download/v1/a.tar.gz", 1024)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal("asset bytes"))
		Expect(rec.auths()).To(Equal([]string{""}))
		Expect(rec.requests()[0].Header.Get("Accept")).To(Equal("application/octet-stream"))
	})

	ginkgo.It("follows a cross-host redirect to blob storage without the token", func() {
		blob, blobRec := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("blob"))
		})
		assets, assetRec := newRecordedServer(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, blob.URL+"/x", http.StatusFound)
		})
		api, _ := newRecordedServer(http.NotFound)
		got, err := newTestClient(api.URL).Download(context.Background(), assets.URL+"/a", 1024)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal("blob"))
		Expect(assetRec.auths()).To(Equal([]string{""}))
		Expect(blobRec.auths()).To(Equal([]string{""}))
	})

	ginkgo.It("accepts a body of exactly the cap", func() {
		srv, _ := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("x", 64)))
		})
		got, err := newTestClient(srv.URL).Download(context.Background(), srv.URL+"/a", 64)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HaveLen(64))
	})

	ginkgo.It("reads a declared-length body into one buffer of that size", func() {
		const size = 16 << 20
		body := bytes.Repeat([]byte("0123456789abcdef"), size/16)
		srv, _ := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(size))
			_, _ = w.Write(body)
		})
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		got, err := newTestClient(srv.URL).Download(context.Background(), srv.URL+"/a", size)
		runtime.ReadMemStats(&after)
		Expect(err).NotTo(HaveOccurred())
		Expect(bytes.Equal(got, body)).To(BeTrue())
		// Growing a buffer by doubling allocates about twice the body; one
		// buffer sized from Content-Length allocates it once.
		Expect(after.TotalAlloc - before.TotalAlloc).To(BeNumerically("<", size*3/2))
	})

	ginkgo.It("bounds what a lying Content-Length can make it allocate", func() {
		const declared = 512 << 20
		srv, _ := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(declared))
			_, _ = w.Write([]byte("tiny"))
		})
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		_, err := newTestClient(srv.URL).Download(context.Background(), srv.URL+"/a", declared)
		runtime.ReadMemStats(&after)
		Expect(err).To(MatchError(ContainSubstring("read body")))
		Expect(after.TotalAlloc - before.TotalAlloc).To(BeNumerically("<", 72<<20))
	})

	ginkgo.It("refuses a body shorter than its declared Content-Length", func() {
		srv, _ := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "64")
			_, _ = w.Write([]byte(strings.Repeat("x", 32)))
		})
		_, err := newTestClient(srv.URL).Download(context.Background(), srv.URL+"/a", 64)
		Expect(err).To(MatchError(ContainSubstring("read body")))
	})

	ginkgo.It("refuses a declared Content-Length over the cap", func() {
		srv, _ := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("x", 65)))
		})
		_, err := newTestClient(srv.URL).Download(context.Background(), srv.URL+"/a", 64)
		Expect(err).To(MatchError(ContainSubstring("exceeds the 64-byte limit")))
	})

	ginkgo.It("refuses a body over the cap that declares no length, counting bytes read", func() {
		srv, _ := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
			// Flushing before the body is complete forces chunked encoding,
			// so the client learns the size only by reading.
			_, _ = w.Write([]byte(strings.Repeat("x", 40)))
			w.(http.Flusher).Flush()
			_, _ = w.Write([]byte(strings.Repeat("x", 40)))
		})
		_, err := newTestClient(srv.URL).Download(context.Background(), srv.URL+"/a", 64)
		Expect(err).To(MatchError(ContainSubstring("response exceeds the 64-byte limit")))
	})

	ginkgo.It("reports a 404 as a *NotFoundError", func() {
		srv, _ := newRecordedServer(http.NotFound)
		_, err := newTestClient(srv.URL).Download(context.Background(), srv.URL+"/gone", 64)
		var nf *NotFoundError
		Expect(errors.As(err, &nf)).To(BeTrue())
	})

	ginkgo.It("refuses an https→http redirect without contacting the http host", func() {
		plain, plainRec := newRecordedServer(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("downgraded"))
		})
		secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, plain.URL+"/a", http.StatusFound)
		}))
		ginkgo.DeferCleanup(secure.Close)
		// The test server's certificate is trusted through its own
		// transport; the redirect policy is source.NewHTTPClient's.
		hc := &http.Client{Transport: secure.Client().Transport, CheckRedirect: source.NewHTTPClient().CheckRedirect}
		_, err := New("https://api.github.com", testToken, hc).Download(context.Background(), secure.URL+"/a", 64)
		Expect(errors.Is(err, source.ErrInsecureRedirect)).To(BeTrue())
		Expect(len(plainRec.requests())).To(BeZero())
	})
})

var _ = ginkgo.Describe("ValidateRepository", func() {
	ginkgo.DescribeTable("applies GitHub's account and repository name rules",
		func(owner, repo string, wantErr string) {
			err := ValidateRepository(owner, repo)
			if wantErr == "" {
				Expect(err).NotTo(HaveOccurred())
				return
			}
			var rn *RepositoryNameError
			Expect(errors.As(err, &rn)).To(BeTrue(), "%v", err)
			Expect(rn.Owner).To(Equal(owner))
			Expect(rn.Repo).To(Equal(repo))
			Expect(err).To(MatchError(ContainSubstring(wantErr)))
		},
		ginkgo.Entry("cli/cli", "cli", "cli", ""),
		ginkgo.Entry("a repository with dots and underscores", "acme", "my_tool.go", ""),
		ginkgo.Entry("a 39-character owner", strings.Repeat("a", 39), "r", ""),
		ginkgo.Entry("a 40-character owner", strings.Repeat("a", 40), "r", "not a valid account name"),
		ginkgo.Entry("an owner with a dot", "o.x", "r", "not a valid account name"),
		ginkgo.Entry("an Enterprise Managed User owner with an underscore", "octocat_acme", "r", ""),
		ginkgo.Entry("an owner with a trailing hyphen", "o-", "r", ""),
		ginkgo.Entry("an owner starting with a hyphen", "-o", "r", "not a valid account name"),
		ginkgo.Entry("an owner starting with an underscore", "_o", "r", "not a valid account name"),
		ginkgo.Entry("an owner with a slash", "o/x", "r", "not a valid account name"),
		ginkgo.Entry("an empty owner", "", "r", "not a valid account name"),
		ginkgo.Entry("an empty repository", "o", "", "not a valid repository name"),
		ginkgo.Entry("a dot-dot repository", "o", "..", "not a valid repository name"),
		ginkgo.Entry("a 101-character repository", "o", strings.Repeat("r", 101), "not a valid repository name"),
		ginkgo.Entry("a repository with a slash", "o", "r/x", "not a valid repository name"),
	)
})

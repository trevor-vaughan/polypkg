package source

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// newTestHTTPBackend builds an HTTP NativeBackend with an injected client
// and metadata deadline, so stall tests run in milliseconds without touching
// the production defaults NewNativeBackend sets. The idle deadline is the
// client's: pass NewHTTPClient(WithIdleTimeout(...)) to shorten it.
func newTestHTTPBackend(base string, client *http.Client, metadata time.Duration) *NativeBackend {
	return &NativeBackend{
		transport: &httpTransport{
			base:            base,
			client:          client,
			metadataTimeout: metadata,
		},
		cacheDir: GinkgoT().TempDir(),
	}
}

// tlsTestClient is NewHTTPClient with its underlying transport swapped for
// one that trusts httptest's TLS certificate. The idle wrapper and redirect
// policy are kept. Every httptest TLS server presents the same certificate,
// so the client trusts all of them.
func tlsTestClient(srv *httptest.Server, opts ...ClientOption) *http.Client {
	c := NewHTTPClient(opts...)
	c.Transport.(*idleTransport).base = srv.Client().Transport
	return c
}

// newProtoServer starts a server for h and returns it with a
// NewHTTPClient(opts...) that reaches it. With useHTTP2 the server speaks
// HTTP/2 over TLS, which is what real https sources negotiate; otherwise
// HTTP/1.1 over plain http. net/http's two client transports surface a
// canceled request differently, so stall handling is checked on both.
// protoMajor reports the protocol version of the last request served.
func newProtoServer(h http.HandlerFunc, useHTTP2 bool, opts ...ClientOption) (srv *httptest.Server, client *http.Client, protoMajor func() int32) {
	var proto atomic.Int32
	recorded := func(w http.ResponseWriter, r *http.Request) {
		proto.Store(int32(r.ProtoMajor))
		h(w, r)
	}
	if !useHTTP2 {
		srv = httptest.NewServer(http.HandlerFunc(recorded))
		return srv, NewHTTPClient(opts...), proto.Load
	}
	srv = httptest.NewUnstartedServer(http.HandlerFunc(recorded))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	return srv, tlsTestClient(srv, opts...), proto.Load
}

// dripHandler writes one byte every interval, flushing each so the client
// sees steady progress. chunks < 0 drips until the client goes away.
func dripHandler(chunks int, interval time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		for i := 0; chunks < 0 || i < chunks; i++ {
			if _, err := w.Write([]byte{'x'}); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
			select {
			case <-r.Context().Done():
				return
			case <-time.After(interval):
			}
		}
	}
}

// stallHandler sends one byte, then goes silent until the client disconnects.
func stallHandler(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte{'x'})
	_ = http.NewResponseController(w).Flush()
	select {
	case <-r.Context().Done():
	case <-time.After(5 * time.Second):
	}
}

// zeroReader returns no bytes and no error on every Read.
type zeroReader struct{}

func (zeroReader) Read([]byte) (int, error) { return 0, nil }

// ctxReader blocks until ctx is done and then fails with ctx's plain error,
// as a body read on a canceled request does.
type ctxReader struct{ ctx context.Context }

func (r ctxReader) Read([]byte) (int, error) {
	<-r.ctx.Done()
	return 0, r.ctx.Err()
}

var _ = Describe("NativeBackend HTTP hardening", func() {
	Describe("production defaults", func() {
		It("sets the idle and metadata deadlines and the redirect policy", func() {
			b := NewNativeBackend(NativeBackendOpts{URL: "https://example.invalid", CacheDir: GinkgoT().TempDir()})
			ht, ok := b.transport.(*httpTransport)
			Expect(ok).To(BeTrue(), "expected *httpTransport, got %T", b.transport)
			Expect(ht.metadataTimeout).To(Equal(metadataFetchTimeout))
			Expect(ht.client.CheckRedirect).NotTo(BeNil())
			it, ok := ht.client.Transport.(*idleTransport)
			Expect(ok).To(BeTrue(), "expected *idleTransport, got %T", ht.client.Transport)
			Expect(it.limit).To(Equal(IdleReadTimeout))
			tr, ok := it.base.(*http.Transport)
			Expect(ok).To(BeTrue())
			Expect(tr.ResponseHeaderTimeout).To(Equal(30 * time.Second))
		})
	})

	Describe("idle body", func() {
		// recordingCancel cancels ctx like the CancelCauseFunc it wraps and
		// also reports every cause it is called with, so a spec can tell a
		// stall cancel apart from the plain cancel that Close performs.
		recordingCancel := func() (context.Context, context.CancelCauseFunc, <-chan error) {
			ctx, cancel := context.WithCancelCause(context.Background())
			causes := make(chan error, 16)
			return ctx, func(cause error) {
				causes <- cause
				cancel(cause)
			}, causes
		}

		It("stops the idle timer on Close, so no stall cancel follows", func() {
			ctx, cancel, causes := recordingCancel()
			body := newIdleBody(ctx, io.NopCloser(strings.NewReader("data")), 50*time.Millisecond, cancel)

			Expect(body.Close()).To(Succeed())
			Expect(<-causes).To(BeNil(), "Close must cancel with no cause")
			Consistently(causes, 200*time.Millisecond).ShouldNot(Receive())
			Expect(context.Cause(ctx)).To(MatchError(context.Canceled))
		})

		It("does not reset the idle timer on a zero-byte Read", func() {
			ctx, cancel, _ := recordingCancel()
			body := newIdleBody(ctx, io.NopCloser(zeroReader{}), 100*time.Millisecond, cancel)
			defer func() { _ = body.Close() }()

			// Zero-byte reads every 10ms would keep the timer from ever firing
			// if they reset it.
			deadline := time.Now().Add(time.Second)
			for ctx.Err() == nil && time.Now().Before(deadline) {
				n, err := body.Read(make([]byte, 8))
				Expect(n).To(BeZero())
				Expect(err).NotTo(HaveOccurred())
				time.Sleep(10 * time.Millisecond)
			}
			var se *StallError
			Expect(errors.As(context.Cause(ctx), &se)).To(BeTrue(), "expected a stall cancel, got %v", context.Cause(ctx))
			Expect(se.Limit).To(Equal(100 * time.Millisecond))
		})

		It("reports a read that fails after a stall as the *StallError", func() {
			ctx, cancel, _ := recordingCancel()
			body := newIdleBody(ctx, io.NopCloser(ctxReader{ctx}), 50*time.Millisecond, cancel)
			defer func() { _ = body.Close() }()

			_, err := body.Read(make([]byte, 8))
			var se *StallError
			Expect(errors.As(err, &se)).To(BeTrue(), "expected *StallError, got %T: %v", err, err)
			Expect(se.Overall).To(BeFalse())
		})
	})

	Describe("idle-read deadline", func() {
		DescribeTable("fails a body that stops making progress, naming the URL",
			func(useHTTP2 bool, wantProto int32) {
				srv, client, protoMajor := newProtoServer(stallHandler, useHTTP2, WithIdleTimeout(100*time.Millisecond))
				defer srv.Close()
				b := newTestHTTPBackend(srv.URL, client, time.Minute)

				start := time.Now()
				_, err := b.Fetch(context.Background(), "hello-1.0.0.tar.zst")
				Expect(time.Since(start)).To(BeNumerically("<", 2*time.Second))
				Expect(err).To(HaveOccurred())
				Expect(protoMajor()).To(Equal(wantProto))

				var fe *FetchError
				Expect(errors.As(err, &fe)).To(BeTrue(), "expected *FetchError, got %T: %v", err, err)
				Expect(fe.Network).To(BeTrue())
				var se *StallError
				Expect(errors.As(err, &se)).To(BeTrue(), "expected *StallError in chain, got %v", err)
				Expect(se.Overall).To(BeFalse())
				Expect(err.Error()).To(ContainSubstring("server stalled"))
				Expect(err.Error()).To(ContainSubstring(srv.URL + "/hello-1.0.0.tar.zst"))
				Expect(err.Error()).NotTo(ContainSubstring("context canceled"))
			},
			Entry("over HTTP/1.1", false, int32(1)),
			Entry("over HTTP/2", true, int32(2)),
		)

		It("does not trip on a slow body that keeps making progress", func() {
			// 20 bytes at 25ms each take ~500ms: longer than the 250ms idle
			// limit, so this passes only if each byte resets the timer. The
			// 100ms metadata limit proves artifact fetches are exempt from it.
			srv := httptest.NewServer(dripHandler(20, 25*time.Millisecond))
			defer srv.Close()
			b := newTestHTTPBackend(srv.URL, NewHTTPClient(WithIdleTimeout(250*time.Millisecond)), 100*time.Millisecond)

			got, err := b.Fetch(context.Background(), "hello-1.0.0.tar.zst")
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(HaveLen(20))
		})

		It("does not report the caller's own cancellation as a stall", func() {
			srv := httptest.NewServer(http.HandlerFunc(stallHandler))
			defer srv.Close()
			b := newTestHTTPBackend(srv.URL, NewHTTPClient(WithIdleTimeout(5*time.Second)), time.Minute)

			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			_, err := b.Fetch(ctx, "hello-1.0.0.tar.zst")
			Expect(err).To(HaveOccurred())
			var se *StallError
			Expect(errors.As(err, &se)).To(BeFalse(), "caller cancellation misreported as stall: %v", err)
		})
	})

	Describe("metadata whole-request deadline", func() {
		It("fails a metadata fetch that drips forever within the idle limit", func() {
			srv := httptest.NewServer(dripHandler(-1, 20*time.Millisecond))
			defer srv.Close()
			b := newTestHTTPBackend(srv.URL, NewHTTPClient(WithIdleTimeout(time.Second)), 300*time.Millisecond)
			// The caller's 5s deadline only stops a broken implementation from
			// hanging the suite; it must not be what ends the fetch.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			start := time.Now()
			_, _, err := b.FetchIndex(ctx)
			Expect(time.Since(start)).To(BeNumerically("<", 2*time.Second))
			Expect(err).To(HaveOccurred())

			var fe *FetchError
			Expect(errors.As(err, &fe)).To(BeTrue(), "expected *FetchError, got %T: %v", err, err)
			var se *StallError
			Expect(errors.As(err, &se)).To(BeTrue(), "expected *StallError in chain, got %v", err)
			Expect(se.Overall).To(BeTrue())
			Expect(err.Error()).To(ContainSubstring(srv.URL + "/index.json"))
		})

		DescribeTable("fails a metadata fetch whose headers do not arrive within the deadline",
			func(useHTTP2 bool, wantProto int32) {
				srv, client, protoMajor := newProtoServer(func(w http.ResponseWriter, r *http.Request) {
					select {
					case <-r.Context().Done():
					case <-time.After(5 * time.Second):
					}
					_, _ = w.Write([]byte("late"))
				}, useHTTP2)
				defer srv.Close()
				// NewHTTPClient's 30s header timeout is far above the 100ms metadata
				// deadline, so only the metadata deadline can end this fetch, and it
				// expires inside client.Do rather than during the body read.
				b := newTestHTTPBackend(srv.URL, client, 100*time.Millisecond)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				start := time.Now()
				_, _, err := b.FetchIndex(ctx)
				Expect(time.Since(start)).To(BeNumerically("<", 2*time.Second))
				Expect(err).To(HaveOccurred())
				Expect(protoMajor()).To(Equal(wantProto))

				var fe *FetchError
				Expect(errors.As(err, &fe)).To(BeTrue(), "expected *FetchError, got %T: %v", err, err)
				Expect(fe.Network).To(BeTrue())
				var se *StallError
				Expect(errors.As(err, &se)).To(BeTrue(), "expected *StallError in chain, got %v", err)
				Expect(se.Overall).To(BeTrue())
				Expect(err.Error()).To(Equal("fetch " + srv.URL + "/index.json: server stalled: response not complete after 100ms"))
			},
			Entry("over HTTP/1.1", false, int32(1)),
			Entry("over HTTP/2", true, int32(2)),
		)
	})

	Describe("redirect policy", func() {
		It("refuses an https to http redirect without contacting the http host", func() {
			var plainHits atomic.Int32
			plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				plainHits.Add(1)
				_, _ = w.Write([]byte("downgraded"))
			}))
			defer plain.Close()
			secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, plain.URL+r.URL.Path, http.StatusFound)
			}))
			defer secure.Close()
			b := newTestHTTPBackend(secure.URL, tlsTestClient(secure), time.Minute)

			_, err := b.Fetch(context.Background(), "hello-1.0.0.tar.zst")
			Expect(err).To(HaveOccurred())
			Expect(errors.Is(err, ErrInsecureRedirect)).To(BeTrue(), "got %v", err)
			var fe *FetchError
			Expect(errors.As(err, &fe)).To(BeTrue())
			Expect(fe.Reason()).To(ContainSubstring(plain.URL))
			// FetchError.Error already names the requested URL, so the reason
			// names only the refused destination.
			Expect(err.Error()).To(Equal("fetch " + secure.URL + "/hello-1.0.0.tar.zst: " +
				"refused redirect from https to a non-https URL: " + plain.URL + "/hello-1.0.0.tar.zst"))
			Expect(plainHits.Load()).To(BeZero())
		})

		It("follows a cross-host https to https redirect", func() {
			cdn := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("from the cdn"))
			}))
			defer cdn.Close()
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, cdn.URL+r.URL.Path, http.StatusFound)
			}))
			defer origin.Close()
			b := newTestHTTPBackend(origin.URL, tlsTestClient(origin), time.Minute)

			got, err := b.Fetch(context.Background(), "hello-1.0.0.tar.zst")
			Expect(err).NotTo(HaveOccurred())
			Expect(string(got)).To(Equal("from the cdn"))
		})

		It("follows an http to http redirect (no downgrade involved)", func() {
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("moved"))
			}))
			defer target.Close()
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
			}))
			defer origin.Close()
			b := newTestHTTPBackend(origin.URL, NewHTTPClient(), time.Minute)

			got, err := b.Fetch(context.Background(), "hello-1.0.0.tar.zst")
			Expect(err).NotTo(HaveOccurred())
			Expect(string(got)).To(Equal("moved"))
		})

		It("stops after 10 redirects", func() {
			var hits atomic.Int32
			var loop *httptest.Server
			loop = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				http.Redirect(w, r, loop.URL+r.URL.Path, http.StatusFound)
			}))
			defer loop.Close()
			b := newTestHTTPBackend(loop.URL, tlsTestClient(loop), time.Minute)

			_, err := b.Fetch(context.Background(), "hello-1.0.0.tar.zst")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("stopped after 10 redirects"))
			Expect(hits.Load()).To(Equal(int32(10)))
		})
	})
})

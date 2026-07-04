package source

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("readLimited", func() {
	DescribeTable("byte-count limits",
		func(size, limit int, expectErr bool, expectLen int) {
			data, err := readLimited(bytes.NewReader(make([]byte, size)), int64(limit))
			if expectErr {
				Expect(err).To(HaveOccurred())
				return
			}
			Expect(err).NotTo(HaveOccurred())
			Expect(data).To(HaveLen(expectLen))
		},
		Entry("under limit returns all bytes", 50, 100, false, 50),
		Entry("exactly at limit is allowed", 100, 100, false, 100),
		Entry("over limit is rejected", 101, 100, true, 0),
	)
})

var _ = Describe("NativeBackend", func() {
	Describe("Fetch", func() {
		It("downloads an artifact and caches it under its base name", func() {
			content := []byte("fake package contents")
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(content)
			}))
			defer srv.Close()

			cacheDir := GinkgoT().TempDir()
			b := NewNativeBackend(NativeBackendOpts{
				URL:      srv.URL,
				CacheDir: cacheDir,
			})

			got, err := b.Fetch(context.Background(), "hello-1.0.0.tar.zst")
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(content))

			// Verify the file was cached under the artifact's base name.
			cachedPath := filepath.Join(cacheDir, "hello-1.0.0.tar.zst")
			_, err = os.Stat(cachedPath)
			Expect(err).NotTo(HaveOccurred())
		})

		It("serves an existing cached artifact without hitting the network", func() {
			cacheDir := GinkgoT().TempDir()
			cachedContent := []byte("cached content")
			cachedPath := filepath.Join(cacheDir, "hello-1.0.0.tar.zst")
			Expect(os.WriteFile(cachedPath, cachedContent, 0o644)).To(Succeed())

			// Use a URL that would fail if called.
			b := NewNativeBackend(NativeBackendOpts{
				URL:      "http://invalid.invalid",
				CacheDir: cacheDir,
			})

			got, err := b.Fetch(context.Background(), "hello-1.0.0.tar.zst")
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(cachedContent))
		})
	})

	Describe("RefetchArtifact", func() {
		It("evicts a poisoned cache entry and rewrites it with fresh bytes", func() {
			fresh := []byte("fresh republished bytes")
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(fresh)
			}))
			defer srv.Close()

			cacheDir := GinkgoT().TempDir()
			cachedPath := filepath.Join(cacheDir, "hello-1.0.0.tar.zst")
			Expect(os.WriteFile(cachedPath, []byte("stale poisoned bytes"), 0o644)).To(Succeed())

			b := NewNativeBackend(NativeBackendOpts{URL: srv.URL, CacheDir: cacheDir})

			got, err := b.RefetchArtifact(context.Background(), "hello-1.0.0.tar.zst")
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(fresh))

			cached, err := os.ReadFile(cachedPath)
			Expect(err).NotTo(HaveOccurred())
			Expect(cached).To(Equal(fresh), "cache must hold the refetched bytes")
		})

		It("fetches normally when no cache entry exists", func() {
			content := []byte("never cached")
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(content)
			}))
			defer srv.Close()

			b := NewNativeBackend(NativeBackendOpts{URL: srv.URL, CacheDir: GinkgoT().TempDir()})
			got, err := b.RefetchArtifact(context.Background(), "hello-1.0.0.tar.zst")
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(content))
		})

		It("returns the fetch error and does not resurrect the evicted entry", func() {
			cacheDir := GinkgoT().TempDir()
			cachedPath := filepath.Join(cacheDir, "hello-1.0.0.tar.zst")
			Expect(os.WriteFile(cachedPath, []byte("stale poisoned bytes"), 0o644)).To(Succeed())

			b := NewNativeBackend(NativeBackendOpts{URL: "http://invalid.invalid", CacheDir: cacheDir})
			_, err := b.RefetchArtifact(context.Background(), "hello-1.0.0.tar.zst")
			Expect(err).To(HaveOccurred())

			_, statErr := os.Stat(cachedPath)
			Expect(statErr).To(MatchError(os.ErrNotExist),
				"the poisoned entry must stay evicted so the next Fetch goes to the network")
		})
	})

	Describe("FetchSignature", func() {
		It("downloads the .minisig sidecar for an artifact", func() {
			const sigContent = "untrusted comment: signature from minisign\nRWQ...\n"
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/hello-1.0.0.tar.zst.minisig":
					_, _ = w.Write([]byte(sigContent))
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			cacheDir := GinkgoT().TempDir()
			b := NewNativeBackend(NativeBackendOpts{
				URL:      srv.URL,
				CacheDir: cacheDir,
			})

			got, err := b.FetchSignature(context.Background(), "hello-1.0.0.tar.zst")
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(sigContent))
		})
	})

	Describe("FetchIndex", func() {
		It("returns both the raw index body and its signature", func() {
			mux := http.NewServeMux()
			mux.HandleFunc("/index.json", func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"schema":"polypkg.index/v2","expires":"2099-01-01T00:00:00Z","packages":{}}`))
			})
			mux.HandleFunc("/index.json.minisig", func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("untrusted comment: x\nSIGDATA\n"))
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()

			b := NewNativeBackend(NativeBackendOpts{URL: srv.URL, CacheDir: GinkgoT().TempDir()})
			raw, sig, err := b.FetchIndex(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.Contains(string(raw), "polypkg.index/v2")).To(BeTrue(), "raw = %q", raw)
			Expect(strings.Contains(sig, "SIGDATA")).To(BeTrue(), "sig = %q", sig)
		})

		It("rejects a backend that does not serve an index", func() {
			srv := httptest.NewServer(http.NotFoundHandler())
			defer srv.Close()
			b := NewNativeBackend(NativeBackendOpts{URL: srv.URL, CacheDir: GinkgoT().TempDir()})
			_, _, err := b.FetchIndex(context.Background())
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("FetchTrustDoc", func() {
		It("returns both the raw trust doc and its signature", func() {
			mux := http.NewServeMux()
			mux.HandleFunc("/trust.json", func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"schema":"polypkg.trust/v2","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z","keys":[]}`))
			})
			mux.HandleFunc("/trust.json.minisig", func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("untrusted comment: x\nSIGDATA\n"))
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()

			b := NewNativeBackend(NativeBackendOpts{URL: srv.URL, CacheDir: GinkgoT().TempDir()})
			raw, sig, err := b.FetchTrustDoc(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.Contains(string(raw), "polypkg.trust/v2")).To(BeTrue(), "raw = %q", raw)
			Expect(strings.Contains(sig, "SIGDATA")).To(BeTrue(), "sig = %q", sig)
		})

		It("rejects a backend that does not serve a trust doc", func() {
			srv := httptest.NewServer(http.NotFoundHandler())
			defer srv.Close()
			b := NewNativeBackend(NativeBackendOpts{URL: srv.URL, CacheDir: GinkgoT().TempDir()})
			_, _, err := b.FetchTrustDoc(context.Background())
			Expect(err).To(HaveOccurred())
		})
	})
})

package source

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"

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

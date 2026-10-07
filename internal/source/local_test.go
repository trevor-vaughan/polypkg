package source

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("isLocalSourceURL", func() {
	DescribeTable("URL classification",
		func(rawURL, wantRoot string, wantOK bool) {
			root, ok := isLocalSourceURL(rawURL)
			Expect(ok).To(Equal(wantOK), "ok mismatch for %q", rawURL)
			Expect(root).To(Equal(wantRoot), "root mismatch for %q", rawURL)
		},
		Entry("file:// absolute path", "file:///tmp/x", "/tmp/x", true),
		Entry("bare absolute path", "/abs/path", "/abs/path", true),
		Entry("https URL", "https://h/x", "", false),
		Entry("http URL", "http://h", "", false),
		Entry("bare relative path", "relative/path", "", false),
		Entry("empty string", "", "", false),
	)
})

var _ = Describe("localTransport", func() {
	var (
		root string
		lt   *localTransport
		ctx  context.Context
	)

	BeforeEach(func() {
		root = GinkgoT().TempDir()
		lt = &localTransport{root: root}
		ctx = context.Background()
	})

	Describe("get", func() {
		It("returns file contents within the size cap", func() {
			content := []byte("hello from local repo")
			Expect(os.WriteFile(filepath.Join(root, "index.json"), content, 0o644)).To(Succeed())

			got, err := lt.get(ctx, "index.json", maxIndexBytes, metadataFetch)
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal(content))
		})

		It("returns a FetchError wrapping 404 for a missing file", func() {
			_, err := lt.get(ctx, "nonexistent.json", maxIndexBytes, metadataFetch)
			Expect(err).To(HaveOccurred())

			var fe *FetchError
			Expect(errors.As(err, &fe)).To(BeTrue(), "expected *FetchError, got %T: %v", err, err)
			Expect(fe.Status).To(Equal(404))
		})

		It("blocks path traversal that would escape root", func() {
			// Write a file one level above root so we can confirm it is NOT read.
			parent := filepath.Dir(root)
			secret := filepath.Join(parent, "secret.txt")
			Expect(os.WriteFile(secret, []byte("secret"), 0o644)).To(Succeed())
			DeferCleanup(func() { _ = os.Remove(secret) })

			_, err := lt.get(ctx, "../secret.txt", maxIndexBytes, metadataFetch)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("escapes"))
		})

		It("rejects content that exceeds the size cap", func() {
			// Write 10 bytes but pass a limit of 5.
			Expect(os.WriteFile(filepath.Join(root, "big.bin"), make([]byte, 10), 0o644)).To(Succeed())

			_, err := lt.get(ctx, "big.bin", 5, metadataFetch)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("limit"))
		})
	})
})

var _ = Describe("NativeBackend (local source)", func() {
	Describe("Fetch", func() {
		It("reads directly from the local dir and bypasses cache on rebuild", func() {
			root := GinkgoT().TempDir()
			artifact := "hello-1.0.0.tar.zst"
			artPath := filepath.Join(root, artifact)

			Expect(os.WriteFile(artPath, []byte("v1"), 0o644)).To(Succeed())

			b := NewNativeBackend(NativeBackendOpts{URL: root, CacheDir: GinkgoT().TempDir()})

			got, err := b.Fetch(context.Background(), artifact)
			Expect(err).NotTo(HaveOccurred())
			Expect(got).To(Equal([]byte("v1")))

			// Overwrite the file in the local dir — a cached backend would return
			// the stale "v1" bytes; a cache-bypassed one returns "v2".
			Expect(os.WriteFile(artPath, []byte("v2"), 0o644)).To(Succeed())

			got2, err := b.Fetch(context.Background(), artifact)
			Expect(err).NotTo(HaveOccurred())
			Expect(got2).To(Equal([]byte("v2")), "local backend must not serve stale cached bytes")
		})
	})

	Describe("FetchIndex", func() {
		It("returns raw index and signature from local dir", func() {
			root := GinkgoT().TempDir()
			indexContent := []byte(`{"schema":"polypkg.index/v3","expires":"2099-01-01T00:00:00Z","packages":{}}`)
			sigContent := []byte("untrusted comment: x\nSIGDATA\n")
			Expect(os.WriteFile(filepath.Join(root, "index.json"), indexContent, 0o644)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(root, "index.json.minisig"), sigContent, 0o644)).To(Succeed())

			b := NewNativeBackend(NativeBackendOpts{URL: root, CacheDir: GinkgoT().TempDir()})
			raw, sig, err := b.FetchIndex(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(raw).To(Equal(indexContent))
			Expect(sig).To(Equal(string(sigContent)))
		})
	})

	Describe("file:// URL form", func() {
		It("resolves a file:// URL to the local directory", func() {
			root := GinkgoT().TempDir()
			content := []byte("via file url")
			Expect(os.WriteFile(filepath.Join(root, "index.json"), content, 0o644)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(root, "index.json.minisig"), []byte("sig"), 0o644)).To(Succeed())

			fileURL := "file://" + root
			b := NewNativeBackend(NativeBackendOpts{URL: fileURL, CacheDir: GinkgoT().TempDir()})
			raw, _, err := b.FetchIndex(context.Background())
			Expect(err).NotTo(HaveOccurred())
			Expect(raw).To(Equal(content))
		})
	})
})

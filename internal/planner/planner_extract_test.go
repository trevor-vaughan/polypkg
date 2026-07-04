package planner

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"time"

	"github.com/klauspost/compress/zstd"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func tarZst(files map[string]string) []byte {
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	Expect(err).NotTo(HaveOccurred())
	tw := tar.NewWriter(zw)
	for name, body := range files {
		Expect(tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))})).To(Succeed())
		_, err := tw.Write([]byte(body))
		Expect(err).NotTo(HaveOccurred())
	}
	Expect(tw.Close()).To(Succeed())
	Expect(zw.Close()).To(Succeed())
	return buf.Bytes()
}

var _ = Describe("ensureExtracted", func() {
	var dir string

	BeforeEach(func() {
		dir = filepath.Join(GinkgoT().TempDir(), "pkg-extract", "demo-1.0.0+aabbccddeeff0011")
	})

	It("extracts a fresh artifact", func() {
		Expect(ensureExtracted(tarZst(map[string]string{"polypkg.yaml": "a: 1\n"}), dir)).To(Succeed())
		Expect(filepath.Join(dir, "polypkg.yaml")).To(BeARegularFile())
	})

	It("never rewrites an existing dir (content-addressed reuse)", func() {
		Expect(ensureExtracted(tarZst(map[string]string{"polypkg.yaml": "original\n"}), dir)).To(Succeed())
		// Same dir, different bytes: must be a no-op, not a rewrite. (In
		// production the hash key makes this impossible; the guarantee the
		// planner relies on is "existing dir is never touched".)
		Expect(ensureExtracted(tarZst(map[string]string{"polypkg.yaml": "rewritten\n"}), dir)).To(Succeed())
		raw, err := os.ReadFile(filepath.Join(dir, "polypkg.yaml"))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(raw)).To(Equal("original\n"))
	})

	It("leaves no partial dir behind on a corrupt archive", func() {
		Expect(ensureExtracted([]byte("not a zstd stream"), dir)).NotTo(Succeed())
		Expect(dir).NotTo(BeADirectory())
		entries, err := os.ReadDir(filepath.Dir(dir))
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(BeEmpty(), "no .extract-* temp left behind")
	})

	It("refreshes dir mtime on reuse so the sweep grace window stays valid", func() {
		// Extract once to create the dir.
		Expect(ensureExtracted(tarZst(map[string]string{"polypkg.yaml": "v: 1\n"}), dir)).To(Succeed())

		// Back-date the dir so it looks stale to the sweep.
		old := time.Now().Add(-2 * time.Hour)
		Expect(os.Chtimes(dir, old, old)).To(Succeed())
		info, err := os.Stat(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.ModTime()).To(BeTemporally("~", old, 2*time.Second), "back-date applied")

		// Call ensureExtracted again (content-addressed reuse path).
		Expect(ensureExtracted(tarZst(map[string]string{"polypkg.yaml": "v: 2\n"}), dir)).To(Succeed())

		// The dir's mtime must now be recent (within the last minute).
		info, err = os.Stat(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.ModTime()).To(BeTemporally(">", time.Now().Add(-time.Minute)),
			"reuse must refresh mtime so sweep does not evict an in-flight dir")
	})
})

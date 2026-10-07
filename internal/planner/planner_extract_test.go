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

	It("reuses a tree that still matches its artifact without re-extracting", func() {
		data := tarZst(map[string]string{"polypkg.yaml": "original\n"})
		Expect(ensureExtracted(data, dir)).To(Succeed())
		before, err := os.Stat(filepath.Join(dir, "polypkg.yaml"))
		Expect(err).NotTo(HaveOccurred())

		Expect(ensureExtracted(data, dir)).To(Succeed())
		after, err := os.Stat(filepath.Join(dir, "polypkg.yaml"))
		Expect(err).NotTo(HaveOccurred())
		Expect(os.SameFile(before, after)).To(BeTrue(), "a matching tree must be reused in place")
	})

	It("replaces a tree modified since extraction with the artifact's bytes", func() {
		data := tarZst(map[string]string{"polypkg.yaml": "original\n"})
		Expect(ensureExtracted(data, dir)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte("tampered\n"), 0o644)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(dir, "planted"), []byte("x"), 0o644)).To(Succeed())

		Expect(ensureExtracted(data, dir)).To(Succeed())
		raw, err := os.ReadFile(filepath.Join(dir, "polypkg.yaml"))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(raw)).To(Equal("original\n"))
		Expect(filepath.Join(dir, "planted")).NotTo(BeAnExistingFile())
		entries, err := os.ReadDir(filepath.Dir(dir))
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(HaveLen(1), "no .extract-* temp left behind")
		Expect(entries[0].Name()).To(Equal(filepath.Base(dir)))
	})

	It("replaces an existing dir that holds a different artifact's tree", func() {
		// In production the hash key makes this impossible; here it stands in
		// for any tree that does not match the bytes being installed.
		Expect(ensureExtracted(tarZst(map[string]string{"polypkg.yaml": "original\n"}), dir)).To(Succeed())
		Expect(ensureExtracted(tarZst(map[string]string{"polypkg.yaml": "rewritten\n"}), dir)).To(Succeed())
		raw, err := os.ReadFile(filepath.Join(dir, "polypkg.yaml"))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(raw)).To(Equal("rewritten\n"))
	})

	DescribeTable("repairs a cache dir that is no longer a real directory",
		func(replace func(data []byte)) {
			data := tarZst(map[string]string{"polypkg.yaml": "original\n"})
			Expect(ensureExtracted(data, dir)).To(Succeed())
			Expect(os.RemoveAll(dir)).To(Succeed())
			replace(data)

			Expect(ensureExtracted(data, dir)).To(Succeed())
			info, err := os.Lstat(dir)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.IsDir()).To(BeTrue(), "the cache dir must be a real directory again")
			raw, err := os.ReadFile(filepath.Join(dir, "polypkg.yaml"))
			Expect(err).NotTo(HaveOccurred())
			Expect(string(raw)).To(Equal("original\n"))
		},
		Entry("a regular file", func([]byte) {
			Expect(os.WriteFile(dir, []byte("x"), 0o644)).To(Succeed())
		}),
		Entry("a symlink to an identical tree elsewhere", func(data []byte) {
			// It verifies clean through the link, but whoever owns the target
			// can change it after verification.
			elsewhere := filepath.Join(GinkgoT().TempDir(), "elsewhere")
			Expect(ensureExtracted(data, elsewhere)).To(Succeed())
			Expect(os.Symlink(elsewhere, dir)).To(Succeed())
		}),
		Entry("a dangling symlink", func([]byte) {
			Expect(os.Symlink(filepath.Join(GinkgoT().TempDir(), "missing"), dir)).To(Succeed())
		}),
	)

	It("refreshes dir mtime before verifying, so a slow verification cannot look stale to the sweep", func() {
		// Planning runs before apply.lock, so a concurrent gc may sweep while
		// verification is still hashing. Observable order: even when
		// verification then fails, the refresh has already happened.
		Expect(ensureExtracted(tarZst(map[string]string{"polypkg.yaml": "v: 1\n"}), dir)).To(Succeed())
		old := time.Now().Add(-2 * time.Hour)
		Expect(os.Chtimes(dir, old, old)).To(Succeed())

		Expect(ensureExtracted([]byte("not a zstd stream"), dir)).NotTo(Succeed())
		info, err := os.Stat(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.ModTime()).To(BeTemporally(">", time.Now().Add(-time.Minute)))
	})

	It("fails without touching an existing tree when the artifact cannot be read", func() {
		Expect(ensureExtracted(tarZst(map[string]string{"polypkg.yaml": "original\n"}), dir)).To(Succeed())
		Expect(ensureExtracted([]byte("not a zstd stream"), dir)).NotTo(Succeed())
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
		data := tarZst(map[string]string{"polypkg.yaml": "v: 1\n"})
		Expect(ensureExtracted(data, dir)).To(Succeed())

		// Back-date the dir so it looks stale to the sweep.
		old := time.Now().Add(-2 * time.Hour)
		Expect(os.Chtimes(dir, old, old)).To(Succeed())
		info, err := os.Stat(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.ModTime()).To(BeTemporally("~", old, 2*time.Second), "back-date applied")

		// Call ensureExtracted again (content-addressed reuse path).
		Expect(ensureExtracted(data, dir)).To(Succeed())

		// The dir's mtime must now be recent (within the last minute).
		info, err = os.Stat(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.ModTime()).To(BeTemporally(">", time.Now().Add(-time.Minute)),
			"reuse must refresh mtime so sweep does not evict an in-flight dir")
	})
})

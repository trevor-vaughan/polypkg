package substrate

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("payload durability", func() {
	It("fsyncs every regular file and directory under a payload tree, without following symlinks", func() {
		root := GinkgoT().TempDir()
		s, err := NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		calls := recordSyncs(s)

		payload := filepath.Join(root, "payload")
		Expect(os.MkdirAll(filepath.Join(payload, "pkg", "bin"), 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(payload, "pkg", "bin", "tool"), []byte("x"), 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(payload, "pkg", "README"), []byte("y"), 0o644)).To(Succeed())
		outside := filepath.Join(root, "outside")
		Expect(os.WriteFile(outside, []byte("z"), 0o644)).To(Succeed())
		Expect(os.Symlink(outside, filepath.Join(payload, "pkg", "link"))).To(Succeed())

		Expect(s.syncTreeWalk(payload)).To(Succeed())

		got := syncedPaths(*calls)
		sort.Strings(got)
		Expect(got).To(Equal([]string{
			payload,
			filepath.Join(payload, "pkg"),
			filepath.Join(payload, "pkg", "README"),
			filepath.Join(payload, "pkg", "bin"),
			filepath.Join(payload, "pkg", "bin", "tool"),
		}))
	})

	It("makes the payload durable before the manifest is written", func() {
		root := GinkgoT().TempDir()
		s, err := NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		Expect(s.BeginTransaction("tx-payload")).To(Succeed())
		calls := recordSyncs(s)
		syncfsAt := -1
		s.syncfs = func(*os.File) error {
			syncfsAt = len(*calls)
			return nil
		}

		m := &schema.Manifest{Schema: "polypkg.manifest/v2", Generation: 1, Scope: "user", Entries: []schema.ManifestEntry{}}
		_, err = s.CommitGeneration("tx-payload", m, emptyOwnership(), nil)
		Expect(err).NotTo(HaveOccurred())

		genDir := filepath.Join(root, "generations", "1")
		paths := syncedPaths(*calls)
		manifestAt := indexOf(paths, filepath.Join(genDir, "manifest.json.tmp"))
		Expect(manifestAt).To(BeNumerically(">=", 0), "manifest fsync not recorded: %v", paths)

		if runtime.GOOS == "linux" {
			Expect(syncfsAt).To(BeNumerically(">=", 0), "syncfs was not called")
			Expect(syncfsAt).To(BeNumerically("<=", manifestAt), "payload must be durable before the manifest")
		} else {
			activeAt := indexOf(paths, filepath.Join(genDir, "active"))
			Expect(activeAt).To(BeNumerically(">=", 0), "payload walk not recorded: %v", paths)
			Expect(activeAt).To(BeNumerically("<", manifestAt))
		}
	})

	It("does not write the manifest when the payload sync fails", func() {
		root := GinkgoT().TempDir()
		s, err := NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		Expect(s.BeginTransaction("tx-fail")).To(Succeed())
		boom := errors.New("boom")
		s.syncfs = func(*os.File) error { return boom }
		s.fsync = func(f *os.File) error {
			if filepath.Base(f.Name()) == "active" {
				return boom
			}
			return f.Sync()
		}

		m := &schema.Manifest{Schema: "polypkg.manifest/v2", Generation: 1, Scope: "user", Entries: []schema.ManifestEntry{}}
		_, cerr := s.CommitGeneration("tx-fail", m, emptyOwnership(), nil)
		Expect(cerr).To(MatchError(ContainSubstring("sync package payload")))
		_, statErr := os.Stat(filepath.Join(root, "generations", "1", "manifest.json"))
		Expect(os.IsNotExist(statErr)).To(BeTrue(), "manifest must not exist after a failed payload sync")
	})
})

func indexOf(paths []string, want string) int {
	for i, p := range paths {
		if p == want {
			return i
		}
	}
	return -1
}

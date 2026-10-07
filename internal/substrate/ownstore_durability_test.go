package substrate

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// syncCall records one fsync the store issued: the synced path, and where the
// active pointer pointed at that moment ("" when it did not exist yet).
type syncCall struct {
	path   string
	active string
}

// recordSyncs replaces s.fsync with a recorder that still performs the real
// fsync, and returns the slice it appends to.
func recordSyncs(s *OwnStore) *[]syncCall {
	calls := &[]syncCall{}
	s.fsync = func(f *os.File) error {
		target, _ := os.Readlink(filepath.Join(s.root, "active"))
		*calls = append(*calls, syncCall{path: f.Name(), active: target})
		return f.Sync()
	}
	return calls
}

// expectAfter asserts that want was synced at some index after the index
// after, and returns the first such index. Pass -1 to search from the start.
// Asserting order rather than an exact sequence keeps the tests to the
// protocol's invariants, so a new barrier elsewhere does not break them.
func expectAfter(paths []string, want string, after int) int {
	GinkgoHelper()
	for i := after + 1; i < len(paths); i++ {
		if paths[i] == want {
			return i
		}
	}
	Fail(fmt.Sprintf("no fsync of %s after index %d in %v", want, after, paths))
	return -1
}

func syncedPaths(calls []syncCall) []string {
	out := make([]string, 0, len(calls))
	for _, c := range calls {
		out = append(out, c.path)
	}
	return out
}

var _ = Describe("CommitGeneration durability", func() {
	It("fsyncs ownership, the gen dir, the manifest, then the dirs before the swap, and the root after it", func() {
		root := GinkgoT().TempDir()
		s, err := NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		Expect(s.BeginTransaction("tx-1")).To(Succeed())
		calls := recordSyncs(s)

		m := &schema.Manifest{Schema: "polypkg.manifest/v2", Generation: 1, Scope: "user", Entries: []schema.ManifestEntry{}}
		gen, err := s.CommitGeneration("tx-1", m, emptyOwnership(), nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(gen).To(Equal(1))

		genDir := filepath.Join(root, "generations", "1")
		paths := syncedPaths(*calls)
		own := expectAfter(paths, filepath.Join(genDir, "ownership.json.tmp"), -1)
		barrier := expectAfter(paths, genDir, own)
		manifest := expectAfter(paths, filepath.Join(genDir, "manifest.json.tmp"), barrier)
		genPost := expectAfter(paths, genDir, manifest)
		gens := expectAfter(paths, filepath.Join(root, "generations"), genPost)
		rootPre := expectAfter(paths, root, gens)
		rootPost := expectAfter(paths, root, rootPre)
		Expect((*calls)[rootPre].active).To(BeEmpty(), "the pre-swap root fsync must run before active exists")
		Expect((*calls)[rootPost].active).To(Equal(filepath.Join("generations", "1", "active")),
			"the final root fsync must run after the swap")
	})

	It("fsyncs config-base snapshots and their directories before the manifest", func() {
		root := GinkgoT().TempDir()
		s, err := NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		Expect(s.BeginTransaction("tx-1")).To(Succeed())
		calls := recordSyncs(s)

		m := &schema.Manifest{Schema: "polypkg.manifest/v2", Generation: 1, Scope: "user", Entries: []schema.ManifestEntry{}}
		_, err = s.CommitGeneration("tx-1", m, emptyOwnership(), map[string][]byte{"blake3:aa11": []byte("base\n")})
		Expect(err).NotTo(HaveOccurred())

		genDir := filepath.Join(root, "generations", "1")
		paths := syncedPaths(*calls)
		base := expectAfter(paths, filepath.Join(genDir, "config-base", "aa", "aa11.tmp"), -1)
		fanout := expectAfter(paths, filepath.Join(genDir, "config-base", "aa"), base)
		configBase := expectAfter(paths, filepath.Join(genDir, "config-base"), fanout)
		barrier := expectAfter(paths, genDir, configBase)
		expectAfter(paths, filepath.Join(genDir, "manifest.json.tmp"), barrier)
	})

	It("leaves nothing on disk and the previous generation active when a post-manifest fsync fails and the caller aborts", func() {
		root := GinkgoT().TempDir()
		s, err := NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		Expect(s.BeginTransaction("tx-1")).To(Succeed())
		m := &schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}}
		_, err = s.CommitGeneration("tx-1", m, emptyOwnership(), nil)
		Expect(err).NotTo(HaveOccurred())

		Expect(s.BeginTransaction("tx-2")).To(Succeed())
		gen2 := filepath.Join(root, "generations", "2")
		s.fsync = func(f *os.File) error {
			if f.Name() == gen2 {
				if _, serr := os.Stat(filepath.Join(gen2, "manifest.json")); serr == nil {
					return errors.New("injected EIO")
				}
			}
			return f.Sync()
		}
		_, err = s.CommitGeneration("tx-2", m, emptyOwnership(), nil)
		Expect(err).To(MatchError(ContainSubstring("injected EIO")))

		// The runner aborts a transaction whose commit failed.
		Expect(s.Abort("tx-2")).To(Succeed())
		_, statErr := os.Stat(gen2)
		Expect(errors.Is(statErr, fs.ErrNotExist)).To(BeTrue(), "the aborted generation must be removed")
		ids, err := s.GenerationIDs()
		Expect(err).NotTo(HaveOccurred())
		Expect(ids).To(Equal([]int{1}))
		cur, err := s.CurrentGeneration()
		Expect(err).NotTo(HaveOccurred())
		Expect(cur).To(Equal(1))
	})

	It("does not swap active when an fsync before the switch fails", func() {
		root := GinkgoT().TempDir()
		s, err := NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		Expect(s.BeginTransaction("tx-1")).To(Succeed())
		errSync := errors.New("injected EIO")
		s.fsync = func(f *os.File) error {
			if strings.HasSuffix(f.Name(), "manifest.json.tmp") {
				return errSync
			}
			return f.Sync()
		}

		m := &schema.Manifest{Schema: "polypkg.manifest/v2", Generation: 1, Scope: "user", Entries: []schema.ManifestEntry{}}
		_, err = s.CommitGeneration("tx-1", m, emptyOwnership(), nil)
		Expect(err).To(MatchError(errSync))
		_, lerr := os.Readlink(filepath.Join(root, "active"))
		Expect(os.IsNotExist(lerr)).To(BeTrue(), "active must not exist after a failed pre-swap fsync")
		_, merr := os.Stat(filepath.Join(root, "generations", "1", "manifest.json"))
		Expect(os.IsNotExist(merr)).To(BeTrue(), "an unsynced manifest must never be renamed into place")
	})

	It("keeps the commit when only the post-swap root fsync fails", func() {
		root := GinkgoT().TempDir()
		s, err := NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		Expect(s.BeginTransaction("tx-1")).To(Succeed())
		s.fsync = func(f *os.File) error {
			if f.Name() == root {
				if _, lerr := os.Readlink(filepath.Join(root, "active")); lerr == nil {
					return errors.New("injected EIO")
				}
			}
			return f.Sync()
		}

		m := &schema.Manifest{Schema: "polypkg.manifest/v2", Generation: 1, Scope: "user", Entries: []schema.ManifestEntry{}}
		gen, err := s.CommitGeneration("tx-1", m, emptyOwnership(), nil)
		Expect(err).NotTo(HaveOccurred(), "the swap is irrevocable; reporting failure would make the runner abort a live generation")
		Expect(gen).To(Equal(1))
		cur, err := s.CurrentGeneration()
		Expect(err).NotTo(HaveOccurred())
		Expect(cur).To(Equal(1))
	})
})

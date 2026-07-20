package drift

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	ginkgo "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"lukechampine.com/blake3"
)

func blake3Hex(b []byte) string {
	h := blake3.New(32, nil)
	_, _ = h.Write(b)
	return "blake3:" + hex.EncodeToString(h.Sum(nil))
}

func statOf(t testing.TB, path string) schema.StatInfo {
	t.Helper()
	g := NewWithT(t)
	info, err := os.Lstat(path)
	g.Expect(err).NotTo(HaveOccurred())
	si := schema.StatInfo{Size: info.Size(), MtimeNs: info.ModTime().UnixNano()}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		si.Inode = st.Ino
	}
	return si
}

var _ = ginkgo.Describe("Inspect (install action)", func() {
	ginkgo.It("reports no drift when a copied file is clean", func() {
		t := ginkgo.GinkgoTB()
		content := []byte("payload")
		root := setupTree(t, fsEntry{Path: "hello/bin/hi", Type: "file", Mode: 0o644, Content: content})
		stat := statOf(t, filepath.Join(root, "hello/bin/hi"))
		prior := &schema.Ownership{Entries: []schema.OwnershipEntry{{
			Path: "hello/bin/hi", Action: "install",
			Expected: schema.Expected{FileType: "regular", ContentHash: blake3Hex(content)},
			Stat:     stat,
		}}}
		got, err := Inspect(prior, root)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(BeEmpty())
	})

	ginkgo.It("reports ReasonMissing for an absent installed file", func() {
		t := ginkgo.GinkgoTB()
		root := setupTree(t)
		prior := &schema.Ownership{Entries: []schema.OwnershipEntry{{
			Path: "hello/bin/hi", Action: "install",
			Expected: schema.Expected{FileType: "regular", ContentHash: "blake3:00"},
		}}}
		got, err := Inspect(prior, root)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HaveLen(1))
		Expect(got[0].Reason).To(Equal(ReasonMissing))
	})

	ginkgo.It("reports ReasonFileType when an expected symlink is now a regular file", func() {
		t := ginkgo.GinkgoTB()
		content := []byte("payload")
		root := setupTree(t, fsEntry{Path: "hello/bin/hi", Type: "file", Mode: 0o644, Content: content})
		prior := &schema.Ownership{Entries: []schema.OwnershipEntry{{
			Path: "hello/bin/hi", Action: "install",
			Expected: schema.Expected{FileType: "symlink", ContentHash: blake3Hex(content)},
		}}}
		got, err := Inspect(prior, root)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HaveLen(1))
		Expect(got[0].Reason).To(Equal(ReasonFileType))
		Expect(got[0].Observed).To(Equal("regular"))
	})

	ginkgo.It("reports ReasonContent when a regular file's content has changed", func() {
		t := ginkgo.GinkgoTB()
		// Recorded ContentHash is for "original", but the live file is "tampered".
		// Stat will also have changed (different size), so incremental does not skip.
		root := setupTree(t, fsEntry{Path: "hello/bin/hi", Type: "file", Mode: 0o644, Content: []byte("tampered")})
		prior := &schema.Ownership{Entries: []schema.OwnershipEntry{{
			Path: "hello/bin/hi", Action: "install",
			Expected: schema.Expected{FileType: "regular", ContentHash: blake3Hex([]byte("original"))},
			Stat:     schema.StatInfo{Size: 8, MtimeNs: 1, Inode: 1}, // intentionally not matching live
		}}}
		got, err := Inspect(prior, root)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HaveLen(1))
		Expect(got[0].Reason).To(Equal(ReasonContent))
		Expect(got[0].Observed).To(Equal(blake3Hex([]byte("tampered"))))
	})

	ginkgo.It("incrementally skips the content check when stat is unchanged", func() {
		t := ginkgo.GinkgoTB()
		// Live content matches what is on disk; recorded ContentHash is intentionally
		// WRONG ("blake3:nope"). If incremental skip works, the recorded stat matches
		// the live stat, so the inspector skips re-hashing and reports no drift even
		// though the recorded hash would not match a real hash.
		content := []byte("payload")
		root := setupTree(t, fsEntry{Path: "hello/bin/hi", Type: "file", Mode: 0o644, Content: content})
		stat := statOf(t, filepath.Join(root, "hello/bin/hi"))
		prior := &schema.Ownership{Entries: []schema.OwnershipEntry{{
			Path: "hello/bin/hi", Action: "install",
			Expected: schema.Expected{FileType: "regular", ContentHash: "blake3:nope"},
			Stat:     stat,
		}}}
		got, err := Inspect(prior, root)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(BeEmpty(), "matching stat must short-circuit the content check")
	})

	ginkgo.It("hashes the resolved target content when re-validating a symlink install", func() {
		t := ginkgo.GinkgoTB()
		// Lay out an install symlink-policy entry: a symlink pointing to a polypkg-
		// controlled file outside the active root. The target's content is hashed
		// when stat changes.
		tmp := t.TempDir()
		target := filepath.Join(tmp, "src")
		Expect(os.WriteFile(target, []byte("targetcontent"), 0o644)).To(Succeed())
		root := setupTree(t, fsEntry{Path: "hello/bin/hi", Type: "symlink", Target: target})
		prior := &schema.Ownership{Entries: []schema.OwnershipEntry{{
			Path: "hello/bin/hi", Action: "install",
			Expected: schema.Expected{FileType: "symlink", ContentHash: blake3Hex([]byte("targetcontent"))},
			// Intentionally mismatched stat to force re-hash of target content.
			Stat: schema.StatInfo{Size: 999, MtimeNs: 1, Inode: 1},
		}}}
		got, err := Inspect(prior, root)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(BeEmpty(), "resolved-target content hash must match the recorded hash")
	})
})

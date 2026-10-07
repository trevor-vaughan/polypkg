package source

import (
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("SweepArtifactCache", func() {
	var state string

	// put creates <state>/cache/<rel> and, when old, backdates it past a
	// one-hour grace window.
	put := func(rel string, old bool) string {
		GinkgoHelper()
		p := filepath.Join(state, "cache", rel)
		Expect(os.MkdirAll(filepath.Dir(p), 0o700)).To(Succeed())
		Expect(os.WriteFile(p, []byte("x"), 0o600)).To(Succeed())
		if old {
			t := time.Now().Add(-2 * time.Hour)
			Expect(os.Chtimes(p, t, t)).To(Succeed())
		}
		return p
	}

	BeforeEach(func() {
		state = GinkgoT().TempDir()
		for _, rel := range []string{
			"native/aa11.att.json",
			"native/bb22.att.json",
			"native/bye-1.0.0.tar.zst",
			"native/hello-1.0.0.tar.zst",
			"native/index.json",
			"native/index.json.tmp",
			"native/revocations.json",
			"native/trust-bundle.json",
			"native/trust.json",
			"other/bye-1.0.0.tar.zst",
		} {
			put(rel, true)
		}
	})

	It("removes unreferenced artifacts and crash temps in every source, keeping referenced ones and signed metadata", func() {
		keep := map[string]bool{"hello-1.0.0.tar.zst": true, "aa11.att.json": true}
		removed, err := SweepArtifactCache(state, keep, time.Hour)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(Equal([]string{
			"native/bb22.att.json",
			"native/bye-1.0.0.tar.zst",
			"native/index.json.tmp",
			"other/bye-1.0.0.tar.zst",
		}))
		for _, kept := range []string{"aa11.att.json", "hello-1.0.0.tar.zst", "index.json", "revocations.json", "trust-bundle.json", "trust.json"} {
			Expect(filepath.Join(state, "cache", "native", kept)).To(BeAnExistingFile())
		}
		Expect(filepath.Join(state, "cache", "other", "bye-1.0.0.tar.zst")).NotTo(BeAnExistingFile())
	})

	It("keeps young unreferenced entries (in-flight apply grace window)", func() {
		young := put("native/young-2.0.0.tar.zst", false)
		removed, err := SweepArtifactCache(state, map[string]bool{}, time.Hour)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).NotTo(ContainElement("native/young-2.0.0.tar.zst"))
		Expect(young).To(BeAnExistingFile())
	})

	It("never removes signed metadata, even with no grace window", func() {
		removed, err := SweepArtifactCache(state, map[string]bool{}, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(HaveLen(6))
		for _, meta := range []string{"index.json", "revocations.json", "trust-bundle.json", "trust.json"} {
			Expect(filepath.Join(state, "cache", "native", meta)).To(BeAnExistingFile())
		}
	})

	It("leaves directories inside a source cache alone", func() {
		sub := filepath.Join(state, "cache", "native", "pool")
		Expect(os.MkdirAll(sub, 0o700)).To(Succeed())
		t := time.Now().Add(-2 * time.Hour)
		Expect(os.Chtimes(sub, t, t)).To(Succeed())
		removed, err := SweepArtifactCache(state, map[string]bool{}, time.Hour)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).NotTo(ContainElement("native/pool"))
		Expect(sub).To(BeADirectory())
	})

	It("neither follows nor removes a symlink inside a source cache", func() {
		target := filepath.Join(GinkgoT().TempDir(), "victim.tar.zst")
		Expect(os.WriteFile(target, []byte("x"), 0o600)).To(Succeed())
		link := filepath.Join(state, "cache", "native", "link-1.0.0.tar.zst")
		Expect(os.Symlink(target, link)).To(Succeed())

		// No grace window: only the type check may spare the link.
		removed, err := SweepArtifactCache(state, map[string]bool{}, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).NotTo(ContainElement("native/link-1.0.0.tar.zst"))
		_, lerr := os.Lstat(link)
		Expect(lerr).NotTo(HaveOccurred(), "the symlink itself is left alone")
		Expect(target).To(BeAnExistingFile(), "the symlink's target is never touched")
	})

	It("does not descend into a symlink standing in for a source dir", func() {
		outside := GinkgoT().TempDir()
		victim := filepath.Join(outside, "victim-1.0.0.tar.zst")
		Expect(os.WriteFile(victim, []byte("x"), 0o600)).To(Succeed())
		Expect(os.Symlink(outside, filepath.Join(state, "cache", "evil"))).To(Succeed())

		removed, err := SweepArtifactCache(state, map[string]bool{}, 0)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).NotTo(ContainElement(HavePrefix("evil/")))
		Expect(victim).To(BeAnExistingFile())
		Expect(filepath.Join(state, "cache", "evil")).To(BeADirectory(), "the link still resolves")
	})

	It("ignores stray files directly under the cache root", func() {
		stray := put("stray", true)
		_, err := SweepArtifactCache(state, map[string]bool{}, time.Hour)
		Expect(err).NotTo(HaveOccurred())
		Expect(stray).To(BeAnExistingFile())
	})

	It("treats a missing cache root as empty", func() {
		removed, err := SweepArtifactCache(GinkgoT().TempDir(), map[string]bool{}, time.Hour)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(BeEmpty())
		Expect(removed).NotTo(BeNil())
	})

	It("roots per-source caches under <stateHome>/cache", func() {
		Expect(CacheRoot("/state")).To(Equal(filepath.Join("/state", "cache")))
	})
})

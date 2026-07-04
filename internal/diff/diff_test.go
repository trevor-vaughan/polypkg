package diff

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func mkMan(entries ...schema.ManifestEntry) *schema.Manifest {
	return &schema.Manifest{
		Schema: "polypkg.manifest/v2", Scope: "user", Entries: entries,
	}
}

func mkOwn(entries ...schema.OwnershipEntry) *schema.Ownership {
	return &schema.Ownership{
		Schema: "polypkg.ownership/v1", Scope: "user", Entries: entries,
	}
}

var _ = Describe("Diff", func() {
	Describe("package-level", func() {
		It("treats nil prior as everything added", func() {
			next := mkMan(schema.ManifestEntry{Name: "hello", Version: "1.0.0"})
			r := Diff(nil, nil, next, mkOwn())
			Expect(r.Packages.Added).To(HaveLen(1))
			Expect(r.Packages.Added[0].Name).To(Equal("hello"))
			Expect(r.Packages.Removed).To(BeEmpty())
			Expect(r.NoChanges).To(BeFalse())
		})

		It("treats nil next as everything removed", func() {
			prior := mkMan(schema.ManifestEntry{Name: "hello", Version: "1.0.0"})
			r := Diff(prior, mkOwn(), nil, nil)
			Expect(r.Packages.Removed).To(HaveLen(1))
			Expect(r.Packages.Removed[0].Name).To(Equal("hello"))
			Expect(r.Packages.Added).To(BeEmpty())
			Expect(r.NoChanges).To(BeFalse())
		})

		It("reports no changes when prior and next are identical", func() {
			m := mkMan(schema.ManifestEntry{Name: "hello", Version: "1.0.0", ContentHash: "blake3:abc"})
			r := Diff(m, mkOwn(), m, mkOwn())
			Expect(r.Packages.Added).To(BeEmpty())
			Expect(r.Packages.Removed).To(BeEmpty())
			Expect(r.Packages.Upgraded).To(BeEmpty())
			Expect(r.Packages.Downgraded).To(BeEmpty())
			Expect(r.NoChanges).To(BeTrue())
		})

		It("detects an upgrade", func() {
			prior := mkMan(schema.ManifestEntry{Name: "hello", Version: "1.0.0", ContentHash: "blake3:aaa"})
			next := mkMan(schema.ManifestEntry{Name: "hello", Version: "2.0.0", ContentHash: "blake3:bbb"})
			r := Diff(prior, mkOwn(), next, mkOwn())
			Expect(r.Packages.Upgraded).To(HaveLen(1))
			Expect(r.Packages.Upgraded[0].Name).To(Equal("hello"))
			Expect(r.Packages.Upgraded[0].OldVersion).To(Equal("1.0.0"))
			Expect(r.Packages.Upgraded[0].NewVersion).To(Equal("2.0.0"))
		})

		It("detects a downgrade", func() {
			prior := mkMan(schema.ManifestEntry{Name: "hello", Version: "2.0.0"})
			next := mkMan(schema.ManifestEntry{Name: "hello", Version: "1.0.0"})
			r := Diff(prior, mkOwn(), next, mkOwn())
			Expect(r.Packages.Downgraded).To(HaveLen(1))
			Expect(r.Packages.Downgraded[0].Name).To(Equal("hello"))
		})

		It("detects a removed package alongside an added one", func() {
			prior := mkMan(schema.ManifestEntry{Name: "old", Version: "1.0.0"})
			next := mkMan(schema.ManifestEntry{Name: "new", Version: "1.0.0"})
			r := Diff(prior, mkOwn(), next, mkOwn())
			Expect(r.Packages.Added).To(HaveLen(1))
			Expect(r.Packages.Added[0].Name).To(Equal("new"))
			Expect(r.Packages.Removed).To(HaveLen(1))
			Expect(r.Packages.Removed[0].Name).To(Equal("old"))
		})
	})

	Describe("ownership-level", func() {
		It("detects added ownership entries", func() {
			r := Diff(mkMan(), mkOwn(), mkMan(),
				mkOwn(schema.OwnershipEntry{Path: "hello/bin/hi", Package: "hello", Action: "install"}))
			Expect(r.Ownership.Added).To(HaveLen(1))
			Expect(r.Ownership.Added[0].Path).To(Equal("hello/bin/hi"))
		})

		It("detects removed ownership entries", func() {
			r := Diff(mkMan(),
				mkOwn(schema.OwnershipEntry{Path: "hello/bin/hi", Package: "hello", Action: "install"}),
				mkMan(), mkOwn())
			Expect(r.Ownership.Removed).To(HaveLen(1))
			Expect(r.Ownership.Removed[0].Path).To(Equal("hello/bin/hi"))
		})

		It("detects content-hash change on install", func() {
			prior := mkOwn(schema.OwnershipEntry{
				Path: "hello/bin/hi", Package: "hello", Action: "install",
				Expected: schema.Expected{FileType: "symlink", ContentHash: "blake3:aaa"},
			})
			next := mkOwn(schema.OwnershipEntry{
				Path: "hello/bin/hi", Package: "hello", Action: "install",
				Expected: schema.Expected{FileType: "symlink", ContentHash: "blake3:bbb"},
			})
			r := Diff(mkMan(), prior, mkMan(), next)
			Expect(r.Ownership.Changed).To(HaveLen(1))
			Expect(r.Ownership.Changed[0].Path).To(Equal("hello/bin/hi"))
			Expect(r.Ownership.Changed[0].PriorExpected.ContentHash).To(Equal("blake3:aaa"))
			Expect(r.Ownership.Changed[0].NextExpected.ContentHash).To(Equal("blake3:bbb"))
		})

		It("detects symlink target change", func() {
			prior := mkOwn(schema.OwnershipEntry{
				Path: "hello/link", Package: "hello", Action: "symlink",
				Expected: schema.Expected{FileType: "symlink", Target: "old"},
			})
			next := mkOwn(schema.OwnershipEntry{
				Path: "hello/link", Package: "hello", Action: "symlink",
				Expected: schema.Expected{FileType: "symlink", Target: "new"},
			})
			r := Diff(mkMan(), prior, mkMan(), next)
			Expect(r.Ownership.Changed).To(HaveLen(1))
			Expect(r.Ownership.Changed[0].NextExpected.Target).To(Equal("new"))
		})

		It("detects mode change on dir/perms entries", func() {
			prior := mkOwn(schema.OwnershipEntry{
				Path: "hello/bin", Package: "hello", Action: "dir",
				Expected: schema.Expected{FileType: "dir", Mode: "0o755"},
			})
			next := mkOwn(schema.OwnershipEntry{
				Path: "hello/bin", Package: "hello", Action: "dir",
				Expected: schema.Expected{FileType: "dir", Mode: "0o700"},
			})
			r := Diff(mkMan(), prior, mkMan(), next)
			Expect(r.Ownership.Changed).To(HaveLen(1))
			Expect(r.Ownership.Changed[0].PriorExpected.Mode).To(Equal("0o755"))
			Expect(r.Ownership.Changed[0].NextExpected.Mode).To(Equal("0o700"))
		})

		It("detects an alternatives priority change", func() {
			prior := mkOwn(schema.OwnershipEntry{
				Path: "bin/editor", Package: "vim", Action: "alternatives",
				Expected: schema.Expected{FileType: "symlink", Target: "vim/bin/vim", Priority: 10},
			})
			next := mkOwn(schema.OwnershipEntry{
				Path: "bin/editor", Package: "vim", Action: "alternatives",
				Expected: schema.Expected{FileType: "symlink", Target: "vim/bin/vim", Priority: 30},
			})
			r := Diff(mkMan(), prior, mkMan(), next)
			Expect(r.Ownership.Changed).To(HaveLen(1))
			Expect(r.Ownership.Changed[0].Path).To(Equal("bin/editor"))
			Expect(r.Ownership.Changed[0].PriorExpected.Priority).To(Equal(10))
			Expect(r.Ownership.Changed[0].NextExpected.Priority).To(Equal(30))
		})

		It("reports no change when alternatives priority is identical", func() {
			o := mkOwn(schema.OwnershipEntry{
				Path: "bin/editor", Package: "vim", Action: "alternatives",
				Expected: schema.Expected{FileType: "symlink", Target: "vim/bin/vim", Priority: 30},
			})
			r := Diff(mkMan(), o, mkMan(), o)
			Expect(r.Ownership.Changed).To(BeEmpty())
			Expect(r.NoChanges).To(BeTrue())
		})

		It("returns NoChanges true when both diffs are empty", func() {
			m := mkMan(schema.ManifestEntry{Name: "hello", Version: "1.0.0"})
			o := mkOwn(schema.OwnershipEntry{Path: "hello/bin/hi", Package: "hello", Action: "install"})
			r := Diff(m, o, m, o)
			Expect(r.NoChanges).To(BeTrue())
		})

		It("produces deterministic order: Added/Removed/Changed sorted by Path", func() {
			next := mkOwn(
				schema.OwnershipEntry{Path: "zeta", Package: "x"},
				schema.OwnershipEntry{Path: "alpha", Package: "x"},
				schema.OwnershipEntry{Path: "mu", Package: "x"},
			)
			r := Diff(mkMan(), mkOwn(), mkMan(), next)
			Expect(r.Ownership.Added).To(HaveLen(3))
			Expect(r.Ownership.Added[0].Path).To(Equal("alpha"))
			Expect(r.Ownership.Added[1].Path).To(Equal("mu"))
			Expect(r.Ownership.Added[2].Path).To(Equal("zeta"))
		})
	})
})

package resolver

import (
	"github.com/trevor-vaughan/polypkg/internal/schema"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func weakCat(pkgs map[string][]schema.IndexEntry) *Catalog {
	cat, err := BuildCatalog(&schema.Index{Schema: "polypkg.index/v2", Expires: "2099-01-01T00:00:00Z", Packages: pkgs}, "native")
	Expect(err).NotTo(HaveOccurred())
	return cat
}

var _ = Describe("ResolveWithWeak", func() {
	It("pulls in a satisfiable recommend and marks it weak", func() {
		cat := weakCat(map[string][]schema.IndexEntry{
			"app":    {{Version: "1.0.0", ContentHash: "blake3:a", Artifact: "app", Recommends: []schema.Relation{{Name: "extras"}}}},
			"extras": {{Version: "1.0.0", ContentHash: "blake3:e", Artifact: "extras"}},
		})
		res, err := ResolveWithWeak([]Requirement{{Name: "app"}}, cat, WeakOn)
		Expect(err).NotTo(HaveOccurred())
		names := map[string]Resolved{}
		for _, r := range res.Installed {
			names[r.Name] = r
		}
		Expect(names).To(HaveKey("extras"))
		Expect(names["extras"].Weak).To(BeTrue())
		Expect(names["extras"].RecommendedBy).To(Equal([]string{"app"}))
		Expect(names["app"].Weak).To(BeFalse())
		Expect(res.Skipped).To(BeEmpty())
	})

	It("records all recommenders of a shared weak package, sorted", func() {
		cat := weakCat(map[string][]schema.IndexEntry{
			"aaa":    {{Version: "1.0.0", ContentHash: "blake3:1", Artifact: "aaa", Recommends: []schema.Relation{{Name: "extras"}}}},
			"zzz":    {{Version: "1.0.0", ContentHash: "blake3:2", Artifact: "zzz", Recommends: []schema.Relation{{Name: "extras"}}}},
			"extras": {{Version: "1.0.0", ContentHash: "blake3:e", Artifact: "extras"}},
		})
		res, err := ResolveWithWeak([]Requirement{{Name: "aaa"}, {Name: "zzz"}}, cat, WeakOn)
		Expect(err).NotTo(HaveOccurred())
		var extras *Resolved
		for i := range res.Installed {
			if res.Installed[i].Name == "extras" {
				extras = &res.Installed[i]
			}
		}
		Expect(extras).NotTo(BeNil())
		Expect(extras.Weak).To(BeTrue())
		Expect(extras.RecommendedBy).To(Equal([]string{"aaa", "zzz"}))
	})

	It("skips and reports a recommend with no candidate", func() {
		cat := weakCat(map[string][]schema.IndexEntry{
			"app": {{Version: "1.0.0", ContentHash: "blake3:a", Artifact: "app", Recommends: []schema.Relation{{Name: "ghost"}}}},
		})
		res, err := ResolveWithWeak([]Requirement{{Name: "app"}}, cat, WeakOn)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Installed).To(HaveLen(1))
		Expect(res.Skipped).To(HaveLen(1))
		Expect(res.Skipped[0].Name).To(Equal("ghost"))
		Expect(res.Skipped[0].RecommendedBy).To(Equal([]string{"app"}))
	})

	It("lists every recommender of a shared unsatisfiable recommend, sorted", func() {
		cat := weakCat(map[string][]schema.IndexEntry{
			"zzz": {{Version: "1.0.0", ContentHash: "blake3:z", Artifact: "zzz", Recommends: []schema.Relation{{Name: "ghost"}}}},
			"aaa": {{Version: "1.0.0", ContentHash: "blake3:a", Artifact: "aaa", Recommends: []schema.Relation{{Name: "ghost"}}}},
		})
		res, err := ResolveWithWeak([]Requirement{{Name: "aaa"}, {Name: "zzz"}}, cat, WeakOn)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Skipped).To(HaveLen(1))
		Expect(res.Skipped[0].Name).To(Equal("ghost"))
		Expect(res.Skipped[0].RecommendedBy).To(Equal([]string{"aaa", "zzz"}))
	})

	It("skips a recommend that conflicts with the hard set", func() {
		cat := weakCat(map[string][]schema.IndexEntry{
			"app": {{Version: "1.0.0", ContentHash: "blake3:a", Artifact: "app",
				Depends:    []schema.Relation{{Name: "lib", Version: "=1.0.0"}},
				Recommends: []schema.Relation{{Name: "wants-lib2"}}}},
			"lib": {
				{Version: "2.0.0", ContentHash: "blake3:l2", Artifact: "lib2"},
				{Version: "1.0.0", ContentHash: "blake3:l1", Artifact: "lib1"},
			},
			"wants-lib2": {{Version: "1.0.0", ContentHash: "blake3:w", Artifact: "w",
				Depends: []schema.Relation{{Name: "lib", Version: "=2.0.0"}}}},
		})
		res, err := ResolveWithWeak([]Requirement{{Name: "app"}}, cat, WeakOn)
		Expect(err).NotTo(HaveOccurred())
		for _, r := range res.Installed {
			Expect(r.Name).NotTo(Equal("wants-lib2"))
		}
		Expect(res.Skipped).To(HaveLen(1))
		Expect(res.Skipped[0].Name).To(Equal("wants-lib2"))
	})

	It("pulls transitive recommends", func() {
		cat := weakCat(map[string][]schema.IndexEntry{
			"app":  {{Version: "1.0.0", ContentHash: "blake3:a", Artifact: "app", Recommends: []schema.Relation{{Name: "mid"}}}},
			"mid":  {{Version: "1.0.0", ContentHash: "blake3:m", Artifact: "mid", Recommends: []schema.Relation{{Name: "leaf"}}}},
			"leaf": {{Version: "1.0.0", ContentHash: "blake3:l", Artifact: "leaf"}},
		})
		res, err := ResolveWithWeak([]Requirement{{Name: "app"}}, cat, WeakOn)
		Expect(err).NotTo(HaveOccurred())
		got := map[string]bool{}
		for _, r := range res.Installed {
			got[r.Name] = true
		}
		Expect(got).To(HaveKey("mid"))
		Expect(got).To(HaveKey("leaf"))
	})

	It("does not mark a package weak when it is also hard-required", func() {
		cat := weakCat(map[string][]schema.IndexEntry{
			"app": {{Version: "1.0.0", ContentHash: "blake3:a", Artifact: "app",
				Depends:    []schema.Relation{{Name: "shared"}},
				Recommends: []schema.Relation{{Name: "shared"}}}},
			"shared": {{Version: "1.0.0", ContentHash: "blake3:s", Artifact: "shared"}},
		})
		res, err := ResolveWithWeak([]Requirement{{Name: "app"}}, cat, WeakOn)
		Expect(err).NotTo(HaveOccurred())
		for _, r := range res.Installed {
			if r.Name == "shared" {
				Expect(r.Weak).To(BeFalse())
			}
		}
	})

	It("with policy off, installs no recommends but still surfaces suggests", func() {
		cat := weakCat(map[string][]schema.IndexEntry{
			"app": {{Version: "1.0.0", ContentHash: "blake3:a", Artifact: "app",
				Recommends: []schema.Relation{{Name: "extras"}},
				Suggests:   []schema.Relation{{Name: "docs"}}}},
			"extras": {{Version: "1.0.0", ContentHash: "blake3:e", Artifact: "extras"}},
		})
		res, err := ResolveWithWeak([]Requirement{{Name: "app"}}, cat, WeakOff)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Installed).To(HaveLen(1))
		Expect(res.Skipped).To(BeEmpty())
		Expect(res.Suggests).To(HaveLen(1))
		Expect(res.Suggests[0].Name).To(Equal("docs"))
	})
})

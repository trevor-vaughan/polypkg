package resolver

import (
	"github.com/trevor-vaughan/polypkg/internal/schema"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("recurse contract (relied on by Phase 2)", func() {
	buildContract := func() *Catalog {
		idx := &schema.Index{Schema: "polypkg.index/v3", Expires: "2099-01-01T00:00:00Z", Packages: map[string][]schema.IndexEntry{
			"lib": {
				{Version: "2.0.0", ContentHash: "blake3:b2", Artifact: "lib2"},
				{Version: "1.0.0", ContentHash: "blake3:b1", Artifact: "lib1"},
			},
			"needs-lib2": {{Version: "1.0.0", ContentHash: "blake3:n", Artifact: "n",
				Depends: []schema.Relation{{Name: "lib", Version: "=2.0.0"}}}},
		}}
		cat, err := BuildCatalog(idx, "native", testHost)
		Expect(err).NotTo(HaveOccurred())
		return cat
	}

	It("honors a pre-pinned selection (no different-version reselection)", func() {
		cat := buildContract()
		s := &solver{cat: cat, budget: defaultMaxSteps}
		chosen := map[string]*Candidate{}
		lib1, err := cat.Newest("lib", "=1.0.0")
		Expect(err).NotTo(HaveOccurred())
		chosen["lib"] = lib1
		ferr := s.recurse([]node{{req: Requirement{Name: "needs-lib2"}, name: "needs-lib2"}}, chosen)
		Expect(ferr).NotTo(BeNil())
		Expect(chosen["lib"].Version).To(Equal("1.0.0"))
		_, leaked := chosen["needs-lib2"]
		Expect(leaked).To(BeFalse())
	})

	It("restores chosen exactly on sub-solve failure (undo log)", func() {
		cat := buildContract()
		s := &solver{cat: cat, budget: defaultMaxSteps}
		chosen := map[string]*Candidate{}
		before := len(chosen)
		ferr := s.recurse([]node{{req: Requirement{Name: "needs-lib2", VersionRange: "=9.9.9"}, name: "needs-lib2"}}, chosen)
		Expect(ferr).NotTo(BeNil())
		Expect(chosen).To(HaveLen(before))
	})

	// Gap 4: Phase 2's degrade-to-skip path relies on recurse returning
	// KindTooComplex with chosen fully restored when the per-recommend budget
	// trips MID-DESCENT (after at least one selection has been committed). The
	// conflict/no-version cases above never commit a key first; this one does, so
	// it locks that a budget abort leaks no partial keys.
	It("rolls chosen back exactly when the budget trips mid-descent (KindTooComplex)", func() {
		idx := &schema.Index{Schema: "polypkg.index/v3", Expires: "2099-01-01T00:00:00Z", Packages: map[string][]schema.IndexEntry{
			"top": {{Version: "1.0.0", ContentHash: "blake3:t", Artifact: "top",
				Depends: []schema.Relation{{Name: "a"}}}},
			"a": {{Version: "1.0.0", ContentHash: "blake3:a", Artifact: "a",
				Depends: []schema.Relation{{Name: "b"}}}},
			"b": {{Version: "1.0.0", ContentHash: "blake3:b", Artifact: "b",
				Depends: []schema.Relation{{Name: "c"}}}},
			"c": {{Version: "1.0.0", ContentHash: "blake3:c", Artifact: "c"}},
		}}
		cat, err := BuildCatalog(idx, "native", testHost)
		Expect(err).NotTo(HaveOccurred())

		// Budget of 2 admits a couple of selections (top, a) before the chain
		// (b, c) exhausts it, so the abort happens after keys were committed.
		s := &solver{cat: cat, budget: 2}
		chosen := map[string]*Candidate{}
		ferr := s.recurse([]node{{req: Requirement{Name: "top"}, name: "top"}}, chosen)
		Expect(ferr).NotTo(BeNil())
		Expect(ferr.Kind).To(Equal(KindTooComplex))
		// Entry state was empty; every mid-descent selection must be undone.
		Expect(chosen).To(BeEmpty())
	})
})

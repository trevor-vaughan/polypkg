package resolver

import (
	"sort"

	"github.com/trevor-vaughan/polypkg/internal/schema"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("weak augmentation invariants", func() {
	cat := func() *Catalog {
		return weakCat(map[string][]schema.IndexEntry{
			"app": {{Version: "1.0.0", ContentHash: "blake3:a", Artifact: "app",
				Recommends: []schema.Relation{{Name: "x"}, {Name: "y"}}}},
			"x": {{Version: "1.0.0", ContentHash: "blake3:x", Artifact: "x", Recommends: []schema.Relation{{Name: "z"}}}},
			"y": {{Version: "1.0.0", ContentHash: "blake3:y", Artifact: "y"}},
			"z": {{Version: "1.0.0", ContentHash: "blake3:z", Artifact: "z"}},
		})
	}

	It("is deterministic across runs (identical Installed/Skipped/Suggests)", func() {
		var first *Result
		for i := 0; i < 25; i++ {
			res, err := ResolveWithWeak([]Requirement{{Name: "app"}}, cat(), WeakOn)
			Expect(err).NotTo(HaveOccurred())
			if first == nil {
				first = res
				continue
			}
			Expect(res.Installed).To(Equal(first.Installed))
			Expect(res.Skipped).To(Equal(first.Skipped))
			Expect(res.Suggests).To(Equal(first.Suggests))
		}
	})

	// multiAndDiamondCat exercises BOTH ordering sorts that the single-package
	// determinism case above leaves dormant:
	//
	//   - Multi-package sub-closure: `app` recommends `big`; one sub-solve for
	//     `big` adds {big, dep1, dep2, dep3} (big hard-depends on all three).
	//     Their order in addedKeys() is the chosen map's iteration order absent
	//     the sort.Strings(out) in addedKeys.
	//
	//   - Diamond / multi-round recommender: `target` is recommended by `zmid`
	//     (a hard dep of app, seeded into the frontier in round 1) AND by `ar1`
	//     (pulled in weakly, so its Recommends are queued for round 2). The two
	//     appends to weakBy["target"] land in different frontier rounds: round
	//     order is [zmid, ar1], but the final per-recommender sort.Strings must
	//     yield [ar1, zmid]. The recommender names are chosen so ROUND order
	//     (zmid first) differs from SORTED order (ar1 first), making the sort
	//     load-bearing rather than coincidentally satisfied.
	multiAndDiamondCat := func() *Catalog {
		return weakCat(map[string][]schema.IndexEntry{
			"app": {{Version: "1.0.0", ContentHash: "blake3:a", Artifact: "app",
				Depends:    []schema.Relation{{Name: "zmid"}},
				Recommends: []schema.Relation{{Name: "big"}, {Name: "ar1"}}}},
			"zmid": {{Version: "1.0.0", ContentHash: "blake3:m", Artifact: "zmid",
				Recommends: []schema.Relation{{Name: "target"}}}},
			"big": {{Version: "1.0.0", ContentHash: "blake3:b", Artifact: "big",
				Depends: []schema.Relation{{Name: "dep1"}, {Name: "dep2"}, {Name: "dep3"}}}},
			"dep1":   {{Version: "1.0.0", ContentHash: "blake3:d1", Artifact: "dep1"}},
			"dep2":   {{Version: "1.0.0", ContentHash: "blake3:d2", Artifact: "dep2"}},
			"dep3":   {{Version: "1.0.0", ContentHash: "blake3:d3", Artifact: "dep3"}},
			"ar1":    {{Version: "1.0.0", ContentHash: "blake3:r1", Artifact: "ar1", Recommends: []schema.Relation{{Name: "target"}}}},
			"target": {{Version: "1.0.0", ContentHash: "blake3:t", Artifact: "target"}},
		})
	}

	It("pins multi-package add-order and multi-round recommender order (both sorts)", func() {
		// Primary guard: explicit sorted-order assertions. These fail
		// DETERMINISTICALLY the instant either sort is removed from weak.go,
		// independent of the per-process map-iteration seed.
		//
		//   - res.Installed sorted by Name pins chosenToResolved's sort.
		//   - The set of weak packages added by the big sub-solve, read back in
		//     Installed order, must be sorted — addedKeys' sort.Strings(out).
		//   - target.RecommendedBy must be sorted across the two rounds —
		//     the per-recommender sort.Strings(weakBy[name]).
		res, err := ResolveWithWeak([]Requirement{{Name: "app"}}, multiAndDiamondCat(), WeakOn)
		Expect(err).NotTo(HaveOccurred())

		names := make([]string, len(res.Installed))
		for i, e := range res.Installed {
			names[i] = e.Name
		}
		Expect(sort.StringsAreSorted(names)).To(BeTrue(), "Installed must be name-sorted: %v", names)
		Expect(names).To(Equal([]string{"app", "ar1", "big", "dep1", "dep2", "dep3", "target", "zmid"}))

		byName := map[string]Resolved{}
		for _, e := range res.Installed {
			byName[e.Name] = e
		}
		// The multi-package sub-closure: big + its three deps are all weak.
		for _, n := range []string{"big", "dep1", "dep2", "dep3"} {
			Expect(byName).To(HaveKey(n))
			Expect(byName[n].Weak).To(BeTrue(), "%s should be weak", n)
		}
		// dep1/dep2/dep3 were each attributed to recommender "big" via the
		// addedKeys path; their RecommendedBy is a single element, so the
		// add-order sort is checked through Installed ordering above and the
		// diamond list below.

		// The diamond target, recommended across two frontier rounds, must have
		// its recommenders in sorted order regardless of round-of-discovery.
		Expect(byName).To(HaveKey("target"))
		Expect(byName["target"].Weak).To(BeTrue())
		Expect(sort.StringsAreSorted(byName["target"].RecommendedBy)).To(BeTrue(),
			"target.RecommendedBy must be sorted: %v", byName["target"].RecommendedBy)
		// Round order would be [zmid, ar1]; the sort must produce [ar1, zmid].
		Expect(byName["target"].RecommendedBy).To(Equal([]string{"ar1", "zmid"}))
	})

	It("is deterministic across runs with a multi-package sub-closure and diamond", func() {
		// Full element-wise Equal across ~25 runs, including each Resolved's
		// RecommendedBy slice (inside Installed), plus Skipped and Suggests.
		var first *Result
		for i := 0; i < 25; i++ {
			res, err := ResolveWithWeak([]Requirement{{Name: "app"}}, multiAndDiamondCat(), WeakOn)
			Expect(err).NotTo(HaveOccurred())
			if first == nil {
				first = res
				continue
			}
			Expect(res.Installed).To(Equal(first.Installed))
			Expect(res.Skipped).To(Equal(first.Skipped))
			Expect(res.Suggests).To(Equal(first.Suggests))
		}
	})

	It("never changes the hard closure (policy on vs off)", func() {
		on, err := ResolveWithWeak([]Requirement{{Name: "app"}}, cat(), WeakOn)
		Expect(err).NotTo(HaveOccurred())
		off, err := ResolveWithWeak([]Requirement{{Name: "app"}}, cat(), WeakOff)
		Expect(err).NotTo(HaveOccurred())
		hardOf := func(r *Result) map[string]string {
			m := map[string]string{}
			for _, e := range r.Installed {
				if !e.Weak {
					m[e.Name] = e.Version
				}
			}
			return m
		}
		Expect(hardOf(on)).To(Equal(hardOf(off)))
	})

	It("degrades to skip (never aborts) when the Phase-2 budget is exhausted", func() {
		c := weakCat(map[string][]schema.IndexEntry{
			"app": {{Version: "1.0.0", ContentHash: "blake3:a", Artifact: "app",
				Recommends: []schema.Relation{{Name: "big"}}}},
			"big": {{Version: "1.0.0", ContentHash: "blake3:b", Artifact: "big",
				Depends: []schema.Relation{{Name: "dep"}}}},
			"dep": {{Version: "1.0.0", ContentHash: "blake3:d", Artifact: "dep"}},
		})
		res, err := resolveWithWeakBudget([]Requirement{{Name: "app"}}, c, WeakOn, 1, maxWeakSteps)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Installed).To(HaveLen(1))
		Expect(res.Installed[0].Name).To(Equal("app"))
		Expect(res.Skipped).To(HaveLen(1))
		Expect(res.Skipped[0].Name).To(Equal("big"))
		Expect(res.Skipped[0].Reason).To(Equal("too complex"))
	})

	It("isolates the per-recommend budget so a benign recommend is not starved by a heavy one", func() {
		// `heavy` needs >1 sub-solve step (it has a dependency chain), `trivial`
		// needs exactly 1. With a per-recommend budget of 1, an early heavy
		// recommend must NOT consume the budget a later trivial recommend needs.
		c := weakCat(map[string][]schema.IndexEntry{
			"app": {{Version: "1.0.0", ContentHash: "blake3:a", Artifact: "app",
				Recommends: []schema.Relation{{Name: "heavy"}, {Name: "trivial"}}}},
			"heavy": {{Version: "1.0.0", ContentHash: "blake3:h", Artifact: "heavy",
				Depends: []schema.Relation{{Name: "dep"}}}},
			"dep":     {{Version: "1.0.0", ContentHash: "blake3:d", Artifact: "dep"}},
			"trivial": {{Version: "1.0.0", ContentHash: "blake3:t", Artifact: "trivial"}},
		})
		res, err := resolveWithWeakBudget([]Requirement{{Name: "app"}}, c, WeakOn, 1, maxWeakSteps)
		Expect(err).NotTo(HaveOccurred())
		installed := map[string]bool{}
		weak := map[string]bool{}
		for _, e := range res.Installed {
			installed[e.Name] = true
			weak[e.Name] = e.Weak
		}
		Expect(installed).To(HaveKey("trivial"))
		Expect(weak["trivial"]).To(BeTrue())
		Expect(installed).NotTo(HaveKey("heavy"))
		Expect(res.Skipped).To(HaveLen(1))
		Expect(res.Skipped[0].Name).To(Equal("heavy"))
		Expect(res.Skipped[0].Reason).To(Equal("too complex"))
	})

	It("bounds total Phase-2 work with a global cap, skipping remaining recommends as too complex", func() {
		// Each recommend is trivially satisfiable on its own, so the per-recommend
		// budget never trips. A tiny global cap must still bound total work: once
		// crossed, remaining recommends become "too complex" skips rather than
		// being silently dropped or hanging. The hard install must still succeed.
		c := weakCat(map[string][]schema.IndexEntry{
			"app": {{Version: "1.0.0", ContentHash: "blake3:a", Artifact: "app",
				Recommends: []schema.Relation{{Name: "r1"}, {Name: "r2"}, {Name: "r3"}, {Name: "r4"}}}},
			"r1": {{Version: "1.0.0", ContentHash: "blake3:1", Artifact: "r1"}},
			"r2": {{Version: "1.0.0", ContentHash: "blake3:2", Artifact: "r2"}},
			"r3": {{Version: "1.0.0", ContentHash: "blake3:3", Artifact: "r3"}},
			"r4": {{Version: "1.0.0", ContentHash: "blake3:4", Artifact: "r4"}},
		})
		// Per-recommend budget generous (each fits); global cap of 2 total steps.
		res, err := resolveWithWeakBudget([]Requirement{{Name: "app"}}, c, WeakOn, 1000, 2)
		Expect(err).NotTo(HaveOccurred())
		// Hard install succeeds.
		hard := map[string]bool{}
		for _, e := range res.Installed {
			if !e.Weak {
				hard[e.Name] = true
			}
		}
		Expect(hard).To(HaveKey("app"))
		// Every recommend is accounted for: installed-weak or skipped. None dropped.
		seen := map[string]bool{}
		for _, e := range res.Installed {
			seen[e.Name] = true
		}
		complexSkips := 0
		for _, s := range res.Skipped {
			seen[s.Name] = true
			if s.Reason == "too complex" {
				complexSkips++
			}
		}
		for _, n := range []string{"r1", "r2", "r3", "r4"} {
			Expect(seen).To(HaveKey(n))
		}
		// The global cap must have forced at least one "too complex" skip.
		Expect(complexSkips).To(BeNumerically(">", 0))
	})

	// Gap 2: the `&& !hard[c.Name]` guard in attributeRecommender must keep a
	// hard-required package out of weak attribution even when another installed
	// package Recommends it. A black-box assertion (RecommendedBy empty) is
	// masked by chosenToResolved's own !hard re-check, so the primary guard is a
	// WHITE-BOX call to augmentWeak that inspects weakBy directly: removing the
	// guard populates weakBy["shared"] and fails this test deterministically.
	// Gap 1 (white-box primary guard for addedKeys' sort.Strings(out)):
	// addedKeys must return its result SORTED. The black-box determinism specs
	// above are masked by sortWeakReqs re-sorting the frontier each round, so this
	// directly asserts the function's contract. With many added keys, Go's
	// randomized map iteration makes the pre-sort order non-sorted with
	// overwhelming probability, so removing sort.Strings(out) fails this
	// deterministically.
	It("addedKeys returns names in sorted order (add-order determinism)", func() {
		// `before` is empty; every key in `chosen` is "added". Names are chosen so
		// insertion/iteration order is unrelated to sorted order.
		chosen := map[string]*Candidate{}
		names := []string{"mike", "alpha", "tango", "bravo", "zulu", "echo", "delta", "kilo", "november", "foxtrot", "golf", "hotel"}
		for _, n := range names {
			chosen[n] = &Candidate{Name: n, Version: "1.0.0"}
		}
		got := addedKeys(map[string]bool{}, chosen)
		Expect(got).To(HaveLen(len(names)))
		Expect(sort.StringsAreSorted(got)).To(BeTrue(), "addedKeys must be sorted: %v", got)
		want := append([]string(nil), names...)
		sort.Strings(want)
		Expect(got).To(Equal(want))
	})

	It("never attributes a recommender to a hard-required package (white-box weakBy)", func() {
		c := weakCat(map[string][]schema.IndexEntry{
			"app": {{Version: "1.0.0", ContentHash: "blake3:a", Artifact: "app",
				Depends:    []schema.Relation{{Name: "shared"}},
				Recommends: []schema.Relation{{Name: "shared"}}}},
			"shared": {{Version: "1.0.0", ContentHash: "blake3:s", Artifact: "shared"}},
		})
		// Reproduce the pinned hard selection the way resolveWithWeakBudget does.
		chosen, ferr := resolveChosen([]Requirement{{Name: "app"}}, c, defaultMaxSteps)
		Expect(ferr).To(BeNil())
		Expect(chosen).To(HaveKey("app"))
		Expect(chosen).To(HaveKey("shared"))
		hard := make(map[string]bool, len(chosen))
		for name := range chosen {
			hard[name] = true
		}
		weakBy := map[string][]string{}
		skipped := augmentWeak(c, chosen, hard, weakBy, defaultWeakSteps, maxWeakSteps)

		// "shared" is hard; its recommender ("app") must NOT be attributed.
		Expect(weakBy).NotTo(HaveKey("shared"))
		Expect(weakBy["shared"]).To(BeEmpty())
		// A satisfied hard recommend is not a skip either.
		Expect(skipped).To(BeEmpty())
	})

	It("leaves RecommendedBy empty for a hard package that is also recommended", func() {
		c := weakCat(map[string][]schema.IndexEntry{
			"app": {{Version: "1.0.0", ContentHash: "blake3:a", Artifact: "app",
				Depends:    []schema.Relation{{Name: "shared"}},
				Recommends: []schema.Relation{{Name: "shared"}}}},
			"shared": {{Version: "1.0.0", ContentHash: "blake3:s", Artifact: "shared"}},
		})
		res, err := ResolveWithWeak([]Requirement{{Name: "app"}}, c, WeakOn)
		Expect(err).NotTo(HaveOccurred())
		var shared *Resolved
		for i := range res.Installed {
			if res.Installed[i].Name == "shared" {
				shared = &res.Installed[i]
			}
		}
		Expect(shared).NotTo(BeNil())
		Expect(shared.Weak).To(BeFalse())
		Expect(shared.RecommendedBy).To(BeEmpty())
	})
})

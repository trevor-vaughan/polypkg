package gc

import (
	"sort"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Decide", func() {
	now := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	mkGen := func(id int, daysAgo int) Generation {
		return Generation{
			ID:          id,
			CommittedAt: now.Add(-time.Duration(daysAgo) * 24 * time.Hour),
		}
	}
	mkCurrent := func(id int, daysAgo int) Generation {
		g := mkGen(id, daysAgo)
		g.IsCurrent = true
		return g
	}
	mkPinned := func(id int, daysAgo int) Generation {
		g := mkGen(id, daysAgo)
		g.Pinned = true
		return g
	}

	DescribeTable("retention rules",
		func(gens []Generation, policy Policy, wantKeep, wantRemove []int) {
			got := Decide(gens, policy, now)
			sort.Ints(got.Keep)
			sort.Ints(got.Remove)
			if wantKeep == nil {
				wantKeep = []int{}
			}
			if wantRemove == nil {
				wantRemove = []int{}
			}
			Expect(got.Keep).To(Equal(wantKeep))
			Expect(got.Remove).To(Equal(wantRemove))
		},
		Entry("empty input",
			nil,
			Policy{Count: 5, Age: 30 * 24 * time.Hour},
			[]int{},
			[]int{},
		),
		Entry("count keeps top N by ID",
			[]Generation{
				mkGen(1, 100), mkGen(2, 80), mkGen(3, 60), mkGen(4, 40),
				mkCurrent(5, 20), mkGen(6, 10), mkGen(7, 5),
			},
			Policy{Count: 3, Age: 0},
			[]int{5, 6, 7},
			[]int{1, 2, 3, 4},
		),
		Entry("age window keeps everyone within age",
			[]Generation{
				mkGen(1, 100), mkGen(2, 80), mkGen(3, 60),
				mkCurrent(4, 20), mkGen(5, 10),
			},
			Policy{Count: 1, Age: 30 * 24 * time.Hour},
			[]int{4, 5},
			[]int{1, 2, 3},
		),
		Entry("count and age both keep gens (union)",
			[]Generation{
				mkGen(1, 100), mkGen(2, 80), mkGen(3, 50),
				mkGen(4, 25), mkCurrent(5, 10),
			},
			Policy{Count: 2, Age: 30 * 24 * time.Hour},
			[]int{4, 5},
			[]int{1, 2, 3},
		),
		Entry("pinned always kept regardless of count or age",
			[]Generation{
				mkPinned(1, 100), mkGen(2, 80), mkGen(3, 60), mkGen(4, 40), mkCurrent(5, 0),
			},
			Policy{Count: 2, Age: 0},
			[]int{1, 4, 5},
			[]int{2, 3},
		),
		Entry("current always kept even when count=1 and it's outside top-1",
			[]Generation{
				mkCurrent(2, 60), mkGen(3, 30), mkGen(4, 10),
			},
			Policy{Count: 1, Age: 0},
			[]int{2, 4},
			[]int{3},
		),
		Entry("zero-timestamp gens never evicted by age",
			[]Generation{
				{ID: 1, CommittedAt: time.Time{}},
				mkCurrent(2, 0),
			},
			Policy{Count: 1, Age: time.Hour},
			[]int{1, 2},
			[]int{},
		),
		Entry("everything eligible, nothing kept extra",
			[]Generation{
				mkCurrent(1, 0),
			},
			Policy{Count: 5, Age: 30 * 24 * time.Hour},
			[]int{1},
			[]int{},
		),
	)

	It("is idempotent across consecutive runs", func() {
		nowLocal := time.Now().UTC()
		gens := []Generation{
			{ID: 1, CommittedAt: nowLocal.Add(-100 * 24 * time.Hour), IsCurrent: false},
			{ID: 2, CommittedAt: nowLocal.Add(-50 * 24 * time.Hour), Pinned: true},
			{ID: 3, CommittedAt: nowLocal.Add(-10 * 24 * time.Hour), IsCurrent: true},
		}
		policy := Policy{Count: 2, Age: 30 * 24 * time.Hour}

		first := Decide(gens, policy, nowLocal)
		var after []Generation
		rm := map[int]bool{}
		for _, id := range first.Remove {
			rm[id] = true
		}
		for _, g := range gens {
			if !rm[g.ID] {
				after = append(after, g)
			}
		}
		second := Decide(after, policy, nowLocal)
		Expect(second.Remove).To(BeEmpty())
	})
})

var _ = Describe("Decide KeptByAge", func() {
	now := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
	gen := func(id, daysAgo int) Generation {
		return Generation{ID: id, CommittedAt: now.Add(-time.Duration(daysAgo) * 24 * time.Hour)}
	}

	It("names the generations only the age window saved", func() {
		gens := []Generation{
			gen(1, 5), gen(2, 4), gen(3, 3), gen(4, 2), gen(5, 1),
			{ID: 6, CommittedAt: now, IsCurrent: true},
		}
		dec := Decide(gens, Policy{Count: 1, Age: 30 * 24 * time.Hour}, now)
		Expect(dec.Remove).To(BeEmpty())
		Expect(dec.KeptByAge).To(Equal([]int{1, 2, 3, 4, 5}))
	})

	It("excludes generations the count rule already retained", func() {
		gens := []Generation{gen(1, 5), gen(2, 4), {ID: 3, CommittedAt: now, IsCurrent: true}}
		dec := Decide(gens, Policy{Count: 3, Age: 30 * 24 * time.Hour}, now)
		Expect(dec.KeptByAge).To(BeEmpty())
	})

	It("excludes pinned and current generations", func() {
		gens := []Generation{
			{ID: 1, CommittedAt: now.Add(-24 * time.Hour), Pinned: true},
			{ID: 2, CommittedAt: now, IsCurrent: true},
		}
		dec := Decide(gens, Policy{Count: 1, Age: 30 * 24 * time.Hour}, now)
		Expect(dec.KeptByAge).To(BeEmpty())
	})

	It("is empty when the age rule is disabled", func() {
		gens := []Generation{gen(1, 5), {ID: 2, CommittedAt: now, IsCurrent: true}}
		dec := Decide(gens, Policy{Count: 1, Age: 0}, now)
		Expect(dec.Remove).To(Equal([]int{1}))
		Expect(dec.KeptByAge).To(BeEmpty())
	})

	// A zero CommittedAt is treated as now-equivalent by the age rule, so it is
	// genuinely age-saved: disabling the age rule would evict it. Reporting it
	// keeps the counts in the CLI note reconcilable with what gc removed.
	It("counts a zero-timestamp generation as age-saved", func() {
		gens := []Generation{
			{ID: 1, CommittedAt: time.Time{}},
			{ID: 2, CommittedAt: now, IsCurrent: true},
		}
		dec := Decide(gens, Policy{Count: 1, Age: time.Hour}, now)
		Expect(dec.Remove).To(BeEmpty())
		Expect(dec.KeptByAge).To(Equal([]int{1}))
	})
})

var _ = Describe("Decide incomplete generations", func() {
	now := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)

	It("removes an incomplete generation regardless of the age window", func() {
		gens := []Generation{
			{ID: 1, CommittedAt: now.Add(-time.Hour)},
			{ID: 2, Incomplete: true},
			{ID: 3, CommittedAt: now, IsCurrent: true},
		}
		dec := Decide(gens, Policy{Count: 5, Age: 30 * 24 * time.Hour}, now)
		Expect(dec.Remove).To(Equal([]int{2}))
		Expect(dec.Keep).To(Equal([]int{1, 3}))
		Expect(dec.KeptByAge).To(BeEmpty())
	})

	It("does not let an incomplete generation take a --count slot", func() {
		gens := []Generation{
			{ID: 1, CommittedAt: now.Add(-48 * time.Hour)},
			{ID: 2, CommittedAt: now.Add(-24 * time.Hour), IsCurrent: true},
			{ID: 3, Incomplete: true},
		}
		dec := Decide(gens, Policy{Count: 2, Age: 0}, now)
		Expect(dec.Keep).To(Equal([]int{1, 2}))
		Expect(dec.Remove).To(Equal([]int{3}))
	})

	It("never removes the current generation even when it is incomplete", func() {
		gens := []Generation{{ID: 4, Incomplete: true, IsCurrent: true}}
		dec := Decide(gens, Policy{Count: 1, Age: 0}, now)
		Expect(dec.Keep).To(Equal([]int{4}))
		Expect(dec.Remove).To(BeEmpty())
	})

	It("keeps a pinned incomplete generation (the substrate refuses to remove pins)", func() {
		gens := []Generation{
			{ID: 1, Incomplete: true, Pinned: true},
			{ID: 2, CommittedAt: now, IsCurrent: true},
		}
		dec := Decide(gens, Policy{Count: 1, Age: 0}, now)
		Expect(dec.Keep).To(Equal([]int{1, 2}))
		Expect(dec.Remove).To(BeEmpty())
	})
})

var _ = Describe("Decide damaged generations", func() {
	now := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)

	It("never removes a damaged generation, at any age or under any --count", func() {
		gens := []Generation{
			{ID: 1, Damaged: true},
			{ID: 2, Damaged: true, CommittedAt: now.Add(-365 * 24 * time.Hour)},
			{ID: 3, CommittedAt: now.Add(-48 * time.Hour)},
			{ID: 4, CommittedAt: now, IsCurrent: true},
		}
		dec := Decide(gens, Policy{Count: 1, Age: 0}, now)
		Expect(dec.Keep).To(Equal([]int{1, 2, 4}))
		Expect(dec.Remove).To(Equal([]int{3}))
		Expect(dec.KeptByAge).To(BeEmpty())
	})

	It("does not let a damaged generation take a --count slot", func() {
		gens := []Generation{
			{ID: 1, CommittedAt: now.Add(-48 * time.Hour)},
			{ID: 2, CommittedAt: now.Add(-24 * time.Hour), IsCurrent: true},
			{ID: 3, Damaged: true},
		}
		dec := Decide(gens, Policy{Count: 2, Age: 0}, now)
		Expect(dec.Keep).To(Equal([]int{1, 2, 3}))
		Expect(dec.Remove).To(BeEmpty())
	})
})

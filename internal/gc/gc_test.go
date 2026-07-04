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

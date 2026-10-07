package gc

import (
	"sort"
	"time"
)

// Generation is one item the algorithm reasons about. It is intentionally
// substrate-agnostic so the same algorithm can serve own-store and future
// substrates (sysext, OSTree). CommittedAt may be the zero value for
// pre-D generations whose manifest never recorded a timestamp; the algorithm
// treats zero-time as "now-equivalent" so age never evicts them.
type Generation struct {
	ID          int
	CommittedAt time.Time
	Pinned      bool
	IsCurrent   bool
	// Incomplete marks a generation an interrupted apply left without a
	// manifest. It can never be activated, so neither the count nor the age
	// rule retains it.
	Incomplete bool
	// Damaged marks a generation whose manifest exists but does not parse or
	// names another generation: corruption or tampering, not a crash. It is
	// evidence, so it is always kept for an operator to inspect, and it never
	// takes a count slot because it can never be activated.
	Damaged bool
}

// Decision is the algorithm's output: two disjoint, sorted lists, plus the
// subset of Keep that only the age rule saved.
type Decision struct {
	Keep   []int
	Remove []int
	// KeptByAge lists the generations that fell outside Policy.Count and were
	// neither current nor pinned, and survived solely because they sit inside
	// Policy.Age. It is exactly the set an operator who asked for a smaller
	// --count expected to see collected, so callers can explain why a run with
	// an explicit --count reclaimed nothing. Sorted; empty when the age rule is
	// disabled or saved nothing.
	KeptByAge []int
}

// Decide applies the retention policy to gens at the given now-time.
//
// A generation is kept iff ANY of:
//   - IsCurrent is true
//   - Pinned is true
//   - Damaged is true (only an operator removes it)
//   - It is complete and one of the policy.Count most-recent complete
//     generations by ID
//   - It is complete and now.Sub(CommittedAt) <= policy.Age (zero
//     CommittedAt counts as now)
//
// The function is pure: it never sorts gens in place and never inspects the
// filesystem. Callers handle removal themselves via the substrate.
func Decide(gens []Generation, policy Policy, now time.Time) Decision {
	if len(gens) == 0 {
		return Decision{Keep: []int{}, Remove: []int{}}
	}
	idsByRecency := make([]int, 0, len(gens))
	for _, g := range gens {
		if !g.Incomplete && !g.Damaged {
			idsByRecency = append(idsByRecency, g.ID)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(idsByRecency)))
	topN := map[int]bool{}
	for i := 0; i < len(idsByRecency) && i < policy.Count; i++ {
		topN[idsByRecency[i]] = true
	}

	keep := []int{}
	remove := []int{}
	keptByAge := []int{}
	for _, g := range gens {
		survives := g.IsCurrent || g.Pinned || g.Damaged || topN[g.ID]
		if !survives && !g.Incomplete && policy.Age > 0 {
			if g.CommittedAt.IsZero() || now.Sub(g.CommittedAt) <= policy.Age {
				survives = true
				keptByAge = append(keptByAge, g.ID)
			}
		}
		if survives {
			keep = append(keep, g.ID)
		} else {
			remove = append(remove, g.ID)
		}
	}
	sort.Ints(keep)
	sort.Ints(remove)
	sort.Ints(keptByAge)
	return Decision{Keep: keep, Remove: remove, KeptByAge: keptByAge}
}

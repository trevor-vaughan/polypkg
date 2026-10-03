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
//   - It is one of the policy.Count most-recent generations by ID
//   - now.Sub(CommittedAt) <= policy.Age  (zero CommittedAt counts as now)
//
// The function is pure: it never sorts gens in place and never inspects the
// filesystem. Callers handle removal themselves via the substrate.
func Decide(gens []Generation, policy Policy, now time.Time) Decision {
	if len(gens) == 0 {
		return Decision{Keep: []int{}, Remove: []int{}}
	}
	idsByRecency := make([]int, len(gens))
	for i, g := range gens {
		idsByRecency[i] = g.ID
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
		survives := g.IsCurrent || g.Pinned || topN[g.ID]
		if !survives && policy.Age > 0 {
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

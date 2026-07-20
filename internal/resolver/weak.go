package resolver

import (
	"slices"
	"sort"
)

// WeakPolicy selects whether Phase-2 weak augmentation runs.
type WeakPolicy int

// WeakPolicy values: WeakOff freezes the Phase-1 hard set; WeakOn additively
// pulls in satisfiable Recommends.
const (
	WeakOff WeakPolicy = iota
	WeakOn
)

// defaultWeakSteps is the PER-RECOMMEND Phase-2 budget: the step limit granted
// to each top-level recommend's sub-solve in isolation. It bounds augmentation
// independently of the Phase-1 budget. Exhausting it degrades that one recommend
// to a skip (Reason "too complex"); it never aborts an install whose hard solve
// already succeeded, and never starves a later, benign recommend.
const defaultWeakSteps = 100_000

// maxWeakSteps caps TOTAL Phase-2 work summed across every recommend sub-solve.
// Because each recommend now gets its own fresh budget (defaultWeakSteps),
// per-recommend isolation alone would let aggregate work grow with catalog size;
// this global cap bounds it for anti-DoS. When total steps reach the cap, the
// remaining (and any in-flight unsatisfied) recommends are recorded as "too
// complex" skips rather than silently dropped — augmentation never hangs and
// never aborts a successful hard install.
const maxWeakSteps = 5_000_000

// Result is the outcome of a two-phase resolve: the hard closure plus any weak
// additions (Installed), the recommends that could not be satisfied (Skipped),
// and the surfaced-but-not-installed Suggests.
type Result struct {
	Installed []Resolved
	Skipped   []SkippedRecommend
	Suggests  []Suggestion
}

// SkippedRecommend is a recommend that was dropped during Phase-2 augmentation,
// with a human-readable reason and the package that recommended it.
type SkippedRecommend struct {
	Name          string
	VersionRange  string
	Reason        string
	RecommendedBy []string
}

// Suggestion is a Suggests relation surfaced to the user. Suggests are never
// installed automatically regardless of policy.
type Suggestion struct {
	Name         string
	VersionRange string
	SuggestedBy  string
}

// ResolveWithWeak runs Phase 1 (the hard solve via resolveChosen) and, when
// policy is WeakOn, Phase 2 weak augmentation: each installed package's
// Recommends is sub-solved against the frozen hard selection by reusing the
// internal recurse. Augmentation is purely additive — it never alters the hard
// set and never aborts the solve; an unsatisfiable or conflicting recommend is
// dropped and reported in Skipped. Suggests are always surfaced, never installed.
func ResolveWithWeak(roots []Requirement, cat *Catalog, policy WeakPolicy) (*Result, error) {
	return resolveWithWeakBudget(roots, cat, policy, defaultWeakSteps, maxWeakSteps)
}

// resolveWithWeakBudget is the budget-parameterized core of ResolveWithWeak,
// retained for package-internal tests that exercise the Phase-2 step limits.
// perBudget is the per-recommend step budget; globalCap bounds total Phase-2
// steps across all sub-solves.
func resolveWithWeakBudget(roots []Requirement, cat *Catalog, policy WeakPolicy, perBudget, globalCap int) (*Result, error) {
	chosen, ferr := resolveChosen(roots, cat, defaultMaxSteps)
	if ferr != nil {
		return nil, ferr
	}
	hard := make(map[string]bool, len(chosen))
	for name := range chosen {
		hard[name] = true
	}
	res := &Result{}
	weakBy := map[string][]string{}
	if policy == WeakOn {
		res.Skipped = augmentWeak(cat, chosen, hard, weakBy, perBudget, globalCap)
	}
	res.Suggests = collectSuggests(chosen)
	res.Installed = chosenToResolved(chosen, hard, weakBy)
	return res, nil
}

// weakReq is a recommend requirement paired with the package that recommended
// it, so a successful pull can be attributed and a skip explained.
type weakReq struct {
	req         Requirement
	recommender string
}

// augmentWeak performs Phase-2 weak augmentation over a breadth-first frontier
// of recommends. Each recommend is sub-solved against the shared, pinned chosen
// map via recurse, which honors the pins and restores chosen exactly on failure
// (see the recurse CONTRACT).
//
// Budgeting is two-tiered. Each top-level recommend sub-solve gets its own fresh
// perBudget step allowance (s.steps is reset to 0 before each recurse), so a
// heavy recommend never starves a later benign one. A running totalSteps is
// summed across sub-solves and bounded by globalCap for anti-DoS: once the cap
// is reached, every remaining unsatisfied recommend (drained from the frontier
// in deterministic sorted order) is recorded as a "too complex" skip rather than
// silently dropped — augmentation never hangs and never aborts a successful hard
// install.
//
// A failed sub-solve is recorded as a skip; a successful one attributes every
// newly-added non-hard package to its recommender and queues that package's own
// recommends. When several recommenders target the SAME failing recommend, the
// sub-solve is run once (the `seen` dedup) but every recommender is appended to
// that target's skip entry, mirroring the install path's []string provenance.
// The returned skips are sorted by (Name, VersionRange) and each RecommendedBy
// list is sorted, for deterministic reporting.
func augmentWeak(cat *Catalog, chosen map[string]*Candidate, hard map[string]bool, weakBy map[string][]string, perBudget, globalCap int) []SkippedRecommend {
	s := &solver{cat: cat, budget: perBudget}
	var skipped []SkippedRecommend
	// skipIdx maps a failing target key -> its index in `skipped`, so a later
	// recommender of the same failing target appends rather than re-running the
	// sub-solve or dropping its attribution.
	skipIdx := map[string]int{}
	seen := map[string]bool{}
	totalSteps := 0
	frontier := seedRecommends(chosen)
	for len(frontier) > 0 {
		sortWeakReqs(frontier)
		var next []weakReq
		for i, wr := range frontier {
			// Target already present (hard or weak): attribute (if weak) and stop —
			// do this BEFORE the `seen` guard so a second recommender of the same
			// target is still recorded.
			if ok, _ := s.satisfied(wr.req, chosen); ok {
				attributeRecommender(wr, chosen, hard, weakBy)
				continue
			}
			key := wr.req.Name + "\x00" + wr.req.VersionRange
			if seen[key] {
				// The sub-solve already ran. If it FAILED, this later recommender of
				// the same target appends to the existing skip entry; if it SUCCEEDED,
				// the satisfied check above already attributed it.
				if idx, ok := skipIdx[key]; ok {
					skipped[idx].RecommendedBy = appendUnique(skipped[idx].RecommendedBy, wr.recommender)
				}
				continue
			}
			// Global cap reached: do not start more sub-solves. Convert this and
			// every remaining unsatisfied recommend (this frontier pass plus the
			// queued next pass) into "too complex" skips, drained deterministically.
			if totalSteps >= globalCap {
				next = append(next, frontier[i:]...)
				sortWeakReqs(next)
				for _, rem := range next {
					if ok, _ := s.satisfied(rem.req, chosen); ok {
						continue
					}
					rkey := rem.req.Name + "\x00" + rem.req.VersionRange
					if idx, ok := skipIdx[rkey]; ok {
						skipped[idx].RecommendedBy = appendUnique(skipped[idx].RecommendedBy, rem.recommender)
						continue
					}
					if seen[rkey] {
						continue
					}
					seen[rkey] = true
					skipIdx[rkey] = len(skipped)
					skipped = append(skipped, SkippedRecommend{
						Name: rem.req.Name, VersionRange: rem.req.VersionRange,
						Reason: "too complex", RecommendedBy: []string{rem.recommender},
					})
				}
				next = nil
				break
			}
			seen[key] = true
			// Each top-level recommend sub-solve gets its own fresh budget so an
			// earlier heavy recommend cannot starve this one.
			s.steps = 0
			before := snapshotKeys(chosen)
			ferr := s.recurse([]node{{req: wr.req, name: wr.req.Name}}, chosen)
			totalSteps += s.steps
			if ferr != nil {
				skipIdx[key] = len(skipped)
				skipped = append(skipped, SkippedRecommend{
					Name: wr.req.Name, VersionRange: wr.req.VersionRange,
					Reason: weakSkipReason(ferr), RecommendedBy: []string{wr.recommender},
				})
				continue
			}
			for _, name := range addedKeys(before, chosen) {
				if !hard[name] {
					weakBy[name] = appendUnique(weakBy[name], wr.recommender)
				}
				for _, rel := range chosen[name].Recommends {
					next = append(next, weakReq{req: Requirement{Name: rel.Name, VersionRange: rel.Version}, recommender: name})
				}
			}
		}
		frontier = next
	}
	// Stabilize each recommender list regardless of the round/order in which
	// recommenders were appended across frontier passes.
	for name := range weakBy {
		sort.Strings(weakBy[name])
	}
	for i := range skipped {
		sort.Strings(skipped[i].RecommendedBy)
	}
	sort.SliceStable(skipped, func(i, j int) bool {
		if skipped[i].Name != skipped[j].Name {
			return skipped[i].Name < skipped[j].Name
		}
		return skipped[i].VersionRange < skipped[j].VersionRange
	})
	return skipped
}

// attributeRecommender records `recommender` as a recommender of the real
// package that currently satisfies wr.req, when that package is weak (not in
// the hard closure). It matches on the real package name only. The documented
// limit applies to THIS already-present-target branch: a recommend already
// satisfied by an existing selection's virtual Provides (rather than a real-name
// match) is not attributed here. A recommend freshly satisfied by pulling in a
// new provider IS attributed via the addedKeys path in augmentWeak.
func attributeRecommender(wr weakReq, chosen map[string]*Candidate, hard map[string]bool, weakBy map[string][]string) {
	if c, ok := chosen[wr.req.Name]; ok && !hard[c.Name] {
		weakBy[c.Name] = appendUnique(weakBy[c.Name], wr.recommender)
	}
}

// seedRecommends builds the initial Phase-2 frontier from the Recommends of
// every hard-selected package.
func seedRecommends(chosen map[string]*Candidate) []weakReq {
	var out []weakReq
	for name, c := range chosen {
		for _, rel := range c.Recommends {
			out = append(out, weakReq{req: Requirement{Name: rel.Name, VersionRange: rel.Version}, recommender: name})
		}
	}
	return out
}

// collectSuggests gathers every Suggests relation across the selection,
// deduplicated by (name, version, suggester) and sorted by (Name, SuggestedBy).
func collectSuggests(chosen map[string]*Candidate) []Suggestion {
	seen := map[string]bool{}
	var out []Suggestion
	for name, c := range chosen {
		for _, rel := range c.Suggests {
			key := rel.Name + "\x00" + rel.Version + "\x00" + name
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Suggestion{Name: rel.Name, VersionRange: rel.Version, SuggestedBy: name})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].SuggestedBy < out[j].SuggestedBy
	})
	return out
}

// sortWeakReqs orders a frontier by (Name, VersionRange, recommender) so Phase-2
// augmentation is deterministic regardless of the chosen map's iteration order.
func sortWeakReqs(ws []weakReq) {
	sort.SliceStable(ws, func(i, j int) bool {
		if ws[i].req.Name != ws[j].req.Name {
			return ws[i].req.Name < ws[j].req.Name
		}
		if ws[i].req.VersionRange != ws[j].req.VersionRange {
			return ws[i].req.VersionRange < ws[j].req.VersionRange
		}
		return ws[i].recommender < ws[j].recommender
	})
}

// snapshotKeys captures the set of selected names before a sub-solve so the
// packages it adds can be identified afterward.
func snapshotKeys(chosen map[string]*Candidate) map[string]bool {
	out := make(map[string]bool, len(chosen))
	for k := range chosen {
		out[k] = true
	}
	return out
}

// addedKeys returns the names present in chosen but absent from before, sorted.
func addedKeys(before map[string]bool, chosen map[string]*Candidate) []string {
	var out []string
	for k := range chosen {
		if !before[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// appendUnique appends x to xs only if it is not already present, preserving order.
func appendUnique(xs []string, x string) []string {
	if slices.Contains(xs, x) {
		return xs
	}
	return append(xs, x)
}

// weakSkipReason renders a *ResolveError from a failed Phase-2 sub-solve into a
// concise, user-facing skip reason.
func weakSkipReason(ferr *ResolveError) string {
	switch ferr.Kind {
	case KindUnknownName:
		return "no candidate (unknown package)"
	case KindNoVersion:
		return "no version satisfies the constraint"
	case KindConflict:
		if ferr.Detail != "" {
			return "conflict: " + ferr.Detail
		}
		return "conflicts with the selected set"
	case KindTooComplex:
		return "too complex"
	default:
		// KindNoCandidate (and any unclassified kind) may carry the underlying
		// error text in Detail (e.g. a constraint/version parse failure surfaced
		// via satisfied); preserve it so the skip reason stays actionable.
		if ferr.Detail != "" {
			return "no compatible candidate: " + ferr.Detail
		}
		return "no compatible candidate"
	}
}

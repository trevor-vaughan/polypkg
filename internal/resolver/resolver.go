// Package resolver implements polypkg's pure-Go dependency resolver: a
// deterministic backtracking solver over a signed source catalog supporting
// transitive depends, Provides/virtual packages, Conflicts, and Obsoletes.
package resolver

import (
	"sort"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// Requirement is a constraint on one (possibly virtual) package name.
type Requirement struct {
	Name         string
	VersionRange string
}

// Resolved is one chosen real package version.
type Resolved struct {
	Name          string
	Version       string
	ContentHash   string
	Artifact      string
	Attestations  []schema.AttestationRef // signed attestation refs from the index entry
	Source        string                  // source the chosen candidate came from
	Weak          bool                    // present via Recommends, not the hard closure
	RecommendedBy []string                // installed packages that recommended it (weak only)
}

// defaultMaxSteps bounds the search so a crafted catalog yields an explained
// failure rather than a hang. Generous for realistic profiles.
const defaultMaxSteps = 100_000

// Resolve selects, for the given roots, a consistent set of package versions
// from the catalog, preferring the highest satisfying version.
func Resolve(roots []Requirement, cat *Catalog) ([]Resolved, error) {
	chosen, ferr := resolveChosen(roots, cat, defaultMaxSteps)
	if ferr != nil {
		return nil, ferr
	}
	return chosenToResolved(chosen, nil, nil), nil
}

// resolveWithBudget is a thin shim retained for package-internal tests that
// exercise the budget limit directly. External code should use Resolve or
// resolveChosen.
func resolveWithBudget(roots []Requirement, cat *Catalog, budget int) ([]Resolved, error) {
	chosen, ferr := resolveChosen(roots, cat, budget)
	if ferr != nil {
		return nil, ferr
	}
	return chosenToResolved(chosen, nil, nil), nil
}

// resolveChosen runs Phase 1 and returns the raw selection map (real name ->
// chosen candidate). It is the shared core of Resolve and ResolveWithWeak.
func resolveChosen(roots []Requirement, cat *Catalog, budget int) (map[string]*Candidate, *ResolveError) {
	s := &solver{cat: cat, budget: budget}
	queue := make([]node, 0, len(roots))
	sorted := append([]Requirement(nil), roots...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, r := range sorted {
		queue = append(queue, node{req: r, name: r.Name})
	}
	chosen := map[string]*Candidate{}
	if ferr := s.recurse(queue, chosen); ferr != nil {
		return nil, ferr
	}
	return chosen, nil
}

// chosenToResolved converts a selection map into a sorted []Resolved, marking
// entries whose name is NOT in hardNames as Weak and attaching recommenders
// from weakBy. hardNames/weakBy may be nil (pure Phase-1 result: all hard).
func chosenToResolved(chosen map[string]*Candidate, hardNames map[string]bool, weakBy map[string][]string) []Resolved {
	out := make([]Resolved, 0, len(chosen))
	for _, c := range chosen {
		r := Resolved{Name: c.Name, Version: c.Version, ContentHash: c.ContentHash, Artifact: c.Artifact, Attestations: c.Attestations, Source: c.Source}
		if hardNames != nil && !hardNames[c.Name] {
			r.Weak = true
			r.RecommendedBy = weakBy[c.Name]
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// node is a requirement plus a parent-linked path that introduced it. The path
// is stored as a name plus a pointer to the parent node so that descending one
// level is O(1); the full []string chain is materialized only when an error is
// built (see node.chain). This avoids O(depth) path copies per decision, which
// would make a deep chain O(N^2).
type node struct {
	req    Requirement
	name   string
	parent *node
}

// chain flattens the parent-linked path from the root down to n, for use in a
// ResolveError. It is called only on the rare error path.
func (n *node) chain() []string {
	depth := 0
	for p := n; p != nil; p = p.parent {
		depth++
	}
	out := make([]string, depth)
	for p, i := n, depth-1; p != nil; p, i = p.parent, i-1 {
		out[i] = p.name
	}
	return out
}

type solver struct {
	cat    *Catalog
	budget int
	steps  int
}

// recurse satisfies the first unsatisfied requirement in queue, backtracking
// across candidate choices. chosen maps real package names to selections and is
// mutated in place: each selection is recorded and undone on backtrack via an
// undo log, so the map is exactly restored on every failure path. This keeps
// per-decision work bounded instead of cloning the whole selection per step.
//
// CONTRACT (relied on by Phase 2 weak augmentation, see weak.go):
//  1. A pre-populated `chosen` is honored as pins: a candidate whose name is
//     already chosen at a different version is rejected (conflictReason), never
//     reselected.
//  2. On any failure path the undo log restores `chosen` to exactly its entry
//     state — callers may sub-solve against a shared map and rely on rollback.
//  3. Conflicts (Conflicts/Obsoletes/version clashes) reject cleanly, so a
//     sub-solve that would disturb the pinned set fails rather than mutating it.
//
// recurse_contract_test.go locks these; do not weaken them.
func (s *solver) recurse(queue []node, chosen map[string]*Candidate) *ResolveError {
	idx := -1
	for i := range queue {
		ok, err := s.satisfied(queue[i].req, chosen)
		if err != nil {
			return &ResolveError{Kind: KindNoCandidate, Requirement: queue[i].req, Path: queue[i].chain(), Detail: err.Error()}
		}
		if !ok {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil
	}

	cur := &queue[idx]
	s.steps++
	if s.budget == 0 || s.steps > s.budget {
		return &ResolveError{Kind: KindTooComplex, Requirement: cur.req, Path: cur.chain()}
	}

	rest := make([]node, 0, len(queue)-1)
	rest = append(rest, queue[:idx]...)
	rest = append(rest, queue[idx+1:]...)

	cands := s.cat.candidatesFor(cur.req)
	if len(cands) == 0 {
		return s.noCandidateError(cur.req, cur.chain())
	}

	var last *ResolveError
	for _, cand := range cands {
		conflict := s.conflictReason(cand, chosen)
		if conflict != "" {
			last = &ResolveError{Kind: KindConflict, Requirement: cur.req, Path: cur.chain(), Detail: conflict}
			continue
		}

		// Forward-checking: before committing to cand, ensure every one of its
		// own dependencies still has a non-empty, selection-compatible domain.
		// Pruning here collapses pigeonhole-style search to linear instead of
		// descending into branches that are already doomed.
		pruned := false
		for _, d := range cand.Depends {
			dep := Requirement{Name: d.Name, VersionRange: d.Version}
			if !s.dependViable(dep, chosen) {
				prunePath := append(cur.chain(), d.Name)
				last = s.noCandidateError(dep, prunePath)
				pruned = true
				break
			}
		}
		if pruned {
			continue
		}

		// Select cand on the shared map; record whether we added the key so we
		// restore the map exactly on backtrack. conflictReason already rejects
		// selecting a different version over an existing pin, so an existing key
		// here means cand equals the current selection and we add nothing.
		_, already := chosen[cand.Name]
		if !already {
			chosen[cand.Name] = cand
		}

		nq := make([]node, len(rest), len(rest)+len(cand.Depends))
		copy(nq, rest)
		for _, d := range cand.Depends {
			nq = append(nq, node{
				req:    Requirement{Name: d.Name, VersionRange: d.Version},
				name:   d.Name,
				parent: cur,
			})
		}
		ferr := s.recurse(nq, chosen)
		if ferr == nil {
			return nil
		}
		if !already {
			delete(chosen, cand.Name)
		}
		last = ferr
	}
	// last is always set: cands is non-empty and every iteration assigns last
	// (a conflict, a forward-check prune, or the descent's error).
	return last
}

// noCandidateError builds the failure for a requirement that no catalog
// candidate can satisfy, classifying it so the CLI can speak to the user's two
// real questions — is the NAME wrong, or the VERSION? When the catalog holds no
// entry for the name at all it is KindUnknownName; when the name is present but
// no version matches the constraint it is KindNoVersion carrying the known
// versions (newest first). The residual case — versions exist in range but are
// all excluded by the current selection (a pin clash surfaced via forward
// checking) — stays KindNoCandidate, the pre-existing generic shape.
func (s *solver) noCandidateError(req Requirement, path []string) *ResolveError {
	if !s.cat.knownName(req.Name) {
		return &ResolveError{Kind: KindUnknownName, Requirement: req, Path: path}
	}
	// KindNoVersion applies only when the constraint itself excludes every
	// version (candidatesFor returns nothing) yet the name is real. If
	// candidatesFor is non-empty here, the requirement was reachable but every
	// candidate was excluded by the current selection (a pin clash caught by
	// forward checking); that is a generic no-candidate, not a version mismatch.
	if len(s.cat.candidatesFor(req)) == 0 {
		if avail := s.cat.availableVersions(req.Name); len(avail) > 0 {
			return &ResolveError{Kind: KindNoVersion, Requirement: req, Path: path, Available: avail}
		}
	}
	return &ResolveError{Kind: KindNoCandidate, Requirement: req, Path: path}
}

// dependViable reports whether requirement d can still be satisfied given the
// current selection: some already-chosen package provides it, OR the catalog
// has at least one candidate for d that is selection-compatible (its real name
// is not already pinned to a different version).
func (s *solver) dependViable(d Requirement, chosen map[string]*Candidate) bool {
	if ok, _ := s.satisfied(d, chosen); ok {
		return true
	}
	for _, c := range s.cat.candidatesFor(d) {
		if existing, pinned := chosen[c.Name]; !pinned || existing.Version == c.Version {
			return true
		}
	}
	return false
}

// satisfied reports whether any current selection provides req. The common case
// is a real-name requirement, resolved by a direct map lookup. The O(N) provider
// scan runs only when req.Name is a name some candidate supplies virtually;
// otherwise a direct miss is conclusive, keeping the per-decision cost O(1).
func (s *solver) satisfied(req Requirement, chosen map[string]*Candidate) (bool, error) {
	if c, ok := chosen[req.Name]; ok {
		provides, err := candidateProvides(c, req.Name, req.VersionRange)
		if err != nil {
			return false, err
		}
		if provides {
			return true, nil
		}
	}
	if !s.cat.virtualNames[req.Name] {
		return false, nil
	}
	for name, c := range chosen {
		if name == req.Name {
			continue // already checked above
		}
		ok, err := candidateProvides(c, req.Name, req.VersionRange)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// conflictReason returns a non-empty description if cand cannot join chosen:
// a different version of the same name, or a Conflicts/Obsoletes clash either
// direction. Empty string means cand is selectable. The full selection cross-
// scan only runs when a clash is actually possible (cand declares relations, or
// some selected candidate could target cand); otherwise it is skipped, keeping
// conflict-free chains O(1) per decision. When several selected packages clash,
// the smallest by (Name, Version) is reported so the explanation is stable.
func (s *solver) conflictReason(cand *Candidate, chosen map[string]*Candidate) string {
	if existing, ok := chosen[cand.Name]; ok && existing.Version != cand.Version {
		return cand.Name + " already selected at " + existing.Version
	}
	if !s.canClash(cand) {
		return ""
	}
	var best *Candidate
	for _, other := range chosen {
		if clashes(cand, other) || clashes(other, cand) {
			if best == nil || candLess(other, best) {
				best = other
			}
		}
	}
	if best != nil {
		return "conflicts with selected " + best.Name + " " + best.Version
	}
	return ""
}

// canClash reports whether cand could possibly conflict with some selection:
// either cand declares its own Conflicts/Obsoletes, or cand (by real name or a
// name it provides) is a recorded target of some other candidate's relation.
func (s *solver) canClash(cand *Candidate) bool {
	if len(cand.Conflicts) > 0 || len(cand.Obsoletes) > 0 {
		return true
	}
	if s.cat.conflictTargets[cand.Name] {
		return true
	}
	for _, p := range cand.Provides {
		if s.cat.conflictTargets[p.Name] {
			return true
		}
	}
	return false
}

// candLess orders candidates by (Name, Version) for deterministic selection of
// a representative conflicting package.
func candLess(a, b *Candidate) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return a.Version < b.Version
}

// clashes reports whether a's Conflicts or Obsoletes exclude b.
func clashes(a, b *Candidate) bool {
	for _, rel := range a.Conflicts {
		if ok, _ := candidateMatchesRelation(b, rel); ok {
			return true
		}
	}
	for _, rel := range a.Obsoletes {
		if ok, _ := candidateMatchesRelation(b, rel); ok {
			return true
		}
	}
	return false
}

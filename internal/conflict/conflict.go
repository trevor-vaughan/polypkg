// Package conflict detects cross-package collisions in a generation's ownership
// set: a shared path claimed by more than one package. It is pure (no I/O, no
// filesystem, no policy beyond identifying the collision). The runner consumes
// it pre-commit to refuse an apply; the plan command consumes it to report.
//
// Namespaced ownership paths embed the owning package name (<pkg>/...), so two
// different packages can never produce the same path string and are inherently
// conflict-free. Only shared paths placed outside the package namespace — today
// the path action's bin/<name> symlinks — can be claimed by two packages.
//
// Action-awareness: an ownership group where every claimant carries the
// "alternatives" action is arbitrated by internal/alternatives — but only when
// all claimants share a single arbitration key. A primary's key is "" (the
// empty master field); a follower's key is its master name. An all-alternatives
// group is safe (not a conflict) only when its members have exactly one distinct
// key: all primaries of the same consumer name, or all followers of a single
// master. Mixed keys — a primary alongside a follower, or followers of
// different masters — are ambiguous and declared a conflict. Any group with at
// least one non-alternatives claimant is a conflict regardless.
package conflict

import (
	"fmt"
	"sort"
	"strings"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// Conflict is one ownership path claimed by more than one distinct package.
type Conflict struct {
	Path     string   // the contested ownership path, e.g. "bin/foo"
	Packages []string // the distinct claiming packages, sorted
}

// Detect returns every ownership path that constitutes a conflict: claimed by
// more than one distinct package AND either at least one claimant is not an
// "alternatives" action, or the alternatives claimants do not share a single
// arbitration key. All-alternatives groups with one key arbitrate via
// internal/alternatives and are not conflicts. Results are sorted by Path, and
// each Conflict.Packages slice is sorted, for deterministic output. Multiple
// entries from the same package on one path are not a conflict.
func Detect(entries []schema.OwnershipEntry) []Conflict {
	type group struct {
		pkgs   map[string]struct{}
		allAlt bool            // every claimant so far carries the alternatives action
		keys   map[string]bool // distinct arbitration keys among alternatives claimants
	}
	byPath := make(map[string]*group, len(entries))
	for i := range entries {
		e := &entries[i]
		g := byPath[e.Path]
		if g == nil {
			g = &group{pkgs: map[string]struct{}{}, allAlt: true, keys: map[string]bool{}}
			byPath[e.Path] = g
		}
		g.pkgs[e.Package] = struct{}{}
		if e.Action != "alternatives" {
			g.allAlt = false
		} else {
			// A primary's key is "" (same path => same name); a follower's key is
			// its master. A safely-arbitrated group has exactly one key: all
			// primaries, or all followers of one master. Mixed keys are ambiguous.
			g.keys[e.Expected.Master] = true
		}
	}
	var out []Conflict
	for path, g := range byPath {
		if len(g.pkgs) < 2 {
			continue // single owner
		}
		if g.allAlt && len(g.keys) == 1 {
			continue // an arbitrated all-alternatives group sharing one key
		}
		pkgs := make([]string, 0, len(g.pkgs))
		for p := range g.pkgs {
			pkgs = append(pkgs, p)
		}
		sort.Strings(pkgs)
		out = append(out, Conflict{Path: path, Packages: pkgs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Summary renders conflicts as a single-line message for error text and audit.
func Summary(conflicts []Conflict) string {
	parts := make([]string, len(conflicts))
	for i, c := range conflicts {
		parts[i] = fmt.Sprintf("%s (claimed by %s)", c.Path, strings.Join(c.Packages, ", "))
	}
	return strings.Join(parts, "; ")
}

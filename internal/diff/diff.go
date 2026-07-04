// Package diff computes the differences between two (manifest, ownership)
// pairs. It is pure: no I/O, no logging. Consumers feed it the current
// generation's persisted state (prior) and the planner's projected state
// (next), and receive a Result that describes what changed.
package diff

import (
	"sort"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// PackageDiff describes package-level changes between two manifests.
type PackageDiff struct {
	Added      []schema.ManifestEntry `json:"added,omitempty"`
	Removed    []schema.ManifestEntry `json:"removed,omitempty"`
	Upgraded   []VersionChange        `json:"upgraded,omitempty"`
	Downgraded []VersionChange        `json:"downgraded,omitempty"`
}

// VersionChange is a same-name package whose version moved.
type VersionChange struct {
	Name       string `json:"name"`
	OldVersion string `json:"old_version"`
	NewVersion string `json:"new_version"`
	OldHash    string `json:"old_hash,omitempty"`
	NewHash    string `json:"new_hash,omitempty"`
}

// OwnershipDiff describes per-path ownership-entry changes between two
// ownership indexes.
type OwnershipDiff struct {
	Added   []schema.OwnershipEntry `json:"added,omitempty"`
	Removed []schema.OwnershipEntry `json:"removed,omitempty"`
	Changed []OwnershipChange       `json:"changed,omitempty"`
}

// OwnershipChange is a same-path entry whose Expected fields differ.
type OwnershipChange struct {
	Path          string          `json:"path"`
	Package       string          `json:"package"`
	Action        string          `json:"action"`
	PriorExpected schema.Expected `json:"prior_expected"`
	NextExpected  schema.Expected `json:"next_expected"`
}

// Result is the full diff output.
type Result struct {
	Packages  PackageDiff   `json:"packages"`
	Ownership OwnershipDiff `json:"ownership"`
	NoChanges bool          `json:"no_changes"`
}

// Diff computes the change between two (manifest, ownership) pairs. Either
// side may be nil: a nil prior means "first apply, everything is added"; a
// nil next means "uninstall everything". Output is deterministic: all lists
// are sorted by name/path.
func Diff(priorMan *schema.Manifest, priorOwn *schema.Ownership,
	nextMan *schema.Manifest, nextOwn *schema.Ownership,
) Result {
	r := Result{}

	priorPkgs := indexManifest(priorMan)
	nextPkgs := indexManifest(nextMan)
	for name, n := range nextPkgs {
		p, ok := priorPkgs[name]
		if !ok {
			r.Packages.Added = append(r.Packages.Added, *n)
			continue
		}
		if p.Version == n.Version {
			continue
		}
		vc := VersionChange{
			Name: name, OldVersion: p.Version, NewVersion: n.Version,
			OldHash: p.ContentHash, NewHash: n.ContentHash,
		}
		if p.Version < n.Version {
			r.Packages.Upgraded = append(r.Packages.Upgraded, vc)
		} else {
			r.Packages.Downgraded = append(r.Packages.Downgraded, vc)
		}
	}
	for name, p := range priorPkgs {
		if _, ok := nextPkgs[name]; !ok {
			r.Packages.Removed = append(r.Packages.Removed, *p)
		}
	}

	priorOE := indexOwnership(priorOwn)
	nextOE := indexOwnership(nextOwn)
	for path, n := range nextOE {
		p, ok := priorOE[path]
		if !ok {
			r.Ownership.Added = append(r.Ownership.Added, *n)
			continue
		}
		if !expectedEqual(p.Expected, n.Expected) {
			r.Ownership.Changed = append(r.Ownership.Changed, OwnershipChange{
				Path: path, Package: n.Package, Action: n.Action,
				PriorExpected: p.Expected, NextExpected: n.Expected,
			})
		}
	}
	for path, p := range priorOE {
		if _, ok := nextOE[path]; !ok {
			r.Ownership.Removed = append(r.Ownership.Removed, *p)
		}
	}

	sortManifestEntries(r.Packages.Added)
	sortManifestEntries(r.Packages.Removed)
	sortVersionChanges(r.Packages.Upgraded)
	sortVersionChanges(r.Packages.Downgraded)
	sortOwnershipEntries(r.Ownership.Added)
	sortOwnershipEntries(r.Ownership.Removed)
	sortOwnershipChanges(r.Ownership.Changed)

	r.NoChanges = len(r.Packages.Added) == 0 &&
		len(r.Packages.Removed) == 0 &&
		len(r.Packages.Upgraded) == 0 &&
		len(r.Packages.Downgraded) == 0 &&
		len(r.Ownership.Added) == 0 &&
		len(r.Ownership.Removed) == 0 &&
		len(r.Ownership.Changed) == 0
	return r
}

func indexManifest(m *schema.Manifest) map[string]*schema.ManifestEntry {
	out := map[string]*schema.ManifestEntry{}
	if m == nil {
		return out
	}
	for i := range m.Entries {
		out[m.Entries[i].Name] = &m.Entries[i]
	}
	return out
}

func indexOwnership(o *schema.Ownership) map[string]*schema.OwnershipEntry {
	out := map[string]*schema.OwnershipEntry{}
	if o == nil {
		return out
	}
	for i := range o.Entries {
		out[o.Entries[i].Path] = &o.Entries[i]
	}
	return out
}

func expectedEqual(a, b schema.Expected) bool {
	return a.FileType == b.FileType &&
		a.ContentHash == b.ContentHash &&
		a.Target == b.Target &&
		a.Mode == b.Mode &&
		a.Priority == b.Priority
}

func sortManifestEntries(s []schema.ManifestEntry) {
	sort.Slice(s, func(i, j int) bool { return s[i].Name < s[j].Name })
}

func sortVersionChanges(s []VersionChange) {
	sort.Slice(s, func(i, j int) bool { return s[i].Name < s[j].Name })
}

func sortOwnershipEntries(s []schema.OwnershipEntry) {
	sort.Slice(s, func(i, j int) bool { return s[i].Path < s[j].Path })
}

func sortOwnershipChanges(s []OwnershipChange) {
	sort.Slice(s, func(i, j int) bool { return s[i].Path < s[j].Path })
}

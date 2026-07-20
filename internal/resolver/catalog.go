package resolver

import (
	"fmt"
	"sort"

	"github.com/Masterminds/semver/v3"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// Candidate is one concrete package version available for selection.
type Candidate struct {
	Name         string
	Version      string
	ContentHash  string
	Artifact     string
	Attestations []schema.AttestationRef // signed attestation refs from the index entry
	Depends      []schema.Relation
	Recommends   []schema.Relation
	Suggests     []schema.Relation
	Provides     []schema.Relation
	Conflicts    []schema.Relation
	Obsoletes    []schema.Relation
	Source       string // name of the source this candidate came from
	sv           *semver.Version
}

// Catalog indexes candidates by real name and by the virtual names they provide.
type Catalog struct {
	byName    map[string][]*Candidate
	providers map[string][]*Candidate
	// conflictTargets holds every name that appears as the target of some
	// Conflicts or Obsoletes relation across all candidates. It lets
	// conflictReason skip the O(N) cross-scan of the selection when no
	// candidate could possibly clash with cand.
	conflictTargets map[string]bool
	// virtualNames holds every name some candidate declares in Provides. It
	// lets satisfied skip the O(N) provider scan of the selection for real
	// names that nothing supplies virtually (the common case).
	virtualNames map[string]bool
}

// BuildCatalog converts a verified index into a resolver Catalog whose
// candidates are all tagged with sourceName.
func BuildCatalog(idx *schema.Index, sourceName string) (*Catalog, error) {
	c := &Catalog{byName: map[string][]*Candidate{}}
	for name, entries := range idx.Packages {
		for i := range entries {
			e := &entries[i]
			v, err := semver.NewVersion(e.Version)
			if err != nil {
				return nil, fmt.Errorf("catalog: %s %q: %w", name, e.Version, err)
			}
			c.byName[name] = append(c.byName[name], &Candidate{
				Name: name, Version: e.Version, ContentHash: e.ContentHash, Artifact: e.Artifact,
				Attestations: e.Attestations,
				Depends:      e.Depends, Recommends: e.Recommends, Suggests: e.Suggests,
				Provides: e.Provides, Conflicts: e.Conflicts, Obsoletes: e.Obsoletes,
				Source: sourceName,
				sv:     v,
			})
		}
	}
	c.reindex()
	return c, nil
}

// reindex rebuilds the derived lookup maps (providers, conflictTargets,
// virtualNames) from c.byName and (re-)sorts every candidate slice. Both
// BuildCatalog and MergeCatalogs call it so the two paths produce identical
// index structures.
func (c *Catalog) reindex() {
	c.providers = map[string][]*Candidate{}
	c.conflictTargets = map[string]bool{}
	c.virtualNames = map[string]bool{}
	for name := range c.byName {
		sortCandidates(c.byName[name])
		for _, cand := range c.byName[name] {
			for _, p := range cand.Provides {
				c.providers[p.Name] = append(c.providers[p.Name], cand)
				c.virtualNames[p.Name] = true
			}
			for _, rel := range cand.Conflicts {
				c.conflictTargets[rel.Name] = true
			}
			for _, rel := range cand.Obsoletes {
				c.conflictTargets[rel.Name] = true
			}
		}
	}
	for name := range c.providers {
		sortProviders(c.providers[name])
	}
}

func sortCandidates(cs []*Candidate) {
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].sv.GreaterThan(cs[j].sv) })
}

// sortProviders gives a deterministic order: by provider name, then version desc.
func sortProviders(cs []*Candidate) {
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].Name != cs[j].Name {
			return cs[i].Name < cs[j].Name
		}
		return cs[i].sv.GreaterThan(cs[j].sv)
	})
}

// knownName reports whether the catalog has any entry for name, either as a
// real package or as a virtual name some candidate provides. It lets a failed
// resolution distinguish "name absent from every source" (an unknown package)
// from "name present, but no version satisfies the constraint".
func (c *Catalog) knownName(name string) bool {
	return len(c.byName[name]) > 0 || len(c.providers[name]) > 0
}

// availableVersions returns every concrete version the catalog holds for a real
// package name, newest first. Used to enumerate the choices in a no-matching-
// version failure. Virtual-only names (no real entries) yield an empty slice;
// such names are reported as unknown rather than version-mismatched.
func (c *Catalog) availableVersions(name string) []string {
	return c.Versions(name)
}

// Versions returns every known version for a real package name, newest first.
// Returns an empty (non-nil) slice for unknown names. Virtual-only names (names
// declared only via Provides, with no real entry in byName) yield an empty
// slice as well — the catalog treats them as unknown for version-listing
// purposes.
func (c *Catalog) Versions(name string) []string {
	cands := c.byName[name]
	if len(cands) == 0 {
		return []string{}
	}
	// byName entries are already sorted newest-first by BuildCatalog.
	out := make([]string, len(cands))
	for i, cand := range cands {
		out[i] = cand.Version
	}
	return out
}

// Newest returns the newest Candidate for name that satisfies constraint. An
// empty constraint matches any version. Errors use the existing *ResolveError
// type: KindUnknownName when the name is absent from every source, and
// KindNoVersion (with Available set) when the name is present but no version
// satisfies the constraint.
func (c *Catalog) Newest(name, constraint string) (*Candidate, error) {
	req := Requirement{Name: name, VersionRange: constraint}
	if !c.knownName(name) {
		return nil, &ResolveError{Kind: KindUnknownName, Requirement: req, Path: []string{name}}
	}
	// candidatesFor returns real candidates first, sorted newest-first, which
	// gives us the newest satisfying candidate at index 0.
	cands := c.candidatesFor(req)
	if len(cands) == 0 {
		return nil, &ResolveError{
			Kind:        KindNoVersion,
			Requirement: req,
			Path:        []string{name},
			Available:   c.availableVersions(name),
		}
	}
	return cands[0], nil
}

// Names returns the sorted list of real package names in the catalog. Virtual
// names — names that appear only in Provides entries of real packages and have
// no independent entry in byName — are excluded. The rationale: byName holds
// packages that a user can explicitly request or list; virtualNames holds names
// that exist solely as aliases for other real packages, and enumerating them
// alongside real names would be confusing (e.g. "python3" listed next to "py").
func (c *Catalog) Names() []string {
	out := make([]string, 0, len(c.byName))
	for name := range c.byName {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// candidatesFor returns candidates that can satisfy req: real candidates named
// req.Name in range first (version desc), then virtual providers.
func (c *Catalog) candidatesFor(req Requirement) []*Candidate {
	seen := map[*Candidate]bool{}
	var out []*Candidate
	for _, cand := range c.byName[req.Name] {
		ok, err := constraintAllows(req.VersionRange, cand.Version)
		if err == nil && ok && !seen[cand] {
			out = append(out, cand)
			seen[cand] = true
		}
	}
	for _, cand := range c.providers[req.Name] {
		ok, err := candidateProvides(cand, req.Name, req.VersionRange)
		if err == nil && ok && !seen[cand] {
			out = append(out, cand)
			seen[cand] = true
		}
	}
	return out
}

// constraintAllows reports whether version satisfies con ("" = any).
func constraintAllows(con, version string) (bool, error) {
	if con == "" {
		return true, nil
	}
	cc, err := semver.NewConstraint(con)
	if err != nil {
		return false, fmt.Errorf("invalid constraint %q: %w", con, err)
	}
	v, err := semver.NewVersion(version)
	if err != nil {
		return false, fmt.Errorf("invalid version %q: %w", version, err)
	}
	return cc.Check(v), nil
}

// candidateProvides reports whether cand satisfies a requirement on name+con,
// either by being that package or by declaring a matching Provides entry.
func candidateProvides(cand *Candidate, name, con string) (bool, error) {
	if cand.Name == name {
		ok, err := constraintAllows(con, cand.Version)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	for _, p := range cand.Provides {
		if p.Name != name {
			continue
		}
		pv := p.Version
		if pv == "" {
			pv = cand.Version
		}
		ok, err := constraintAllows(con, pv)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// candidateMatchesRelation reports whether cand falls under rel (name + range).
func candidateMatchesRelation(cand *Candidate, rel schema.Relation) (bool, error) {
	return candidateProvides(cand, rel.Name, rel.Version)
}

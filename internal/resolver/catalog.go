package resolver

import (
	"fmt"
	"maps"
	"slices"
	"sort"

	"github.com/Masterminds/semver/v3"
	"github.com/trevor-vaughan/polypkg/internal/platform"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// Candidate is one concrete package version available for selection.
type Candidate struct {
	Name         string
	Version      string
	ContentHash  string
	Artifact     string
	Platform     string                  // index entry platform; "" = platform-agnostic
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
	// host is the platform this catalog was filtered for (platform.Host() in
	// production). It names the host in a wrong-platform resolution failure.
	host string
	// dropped records, per package name and version, the entries left out
	// because they were published only for platforms other than host.
	dropped map[string]map[string]*unavailable
}

// unavailable is the set of platforms one (name, version) is published for
// that are not the catalog's host.
type unavailable struct {
	sv        *semver.Version
	platforms []string // sorted once BuildCatalog finishes; distinct by admitBuild
}

// BuildCatalog converts a verified index into a resolver Catalog for host (a
// platform.Host() value) whose candidates are all tagged with sourceName.
//
// Every package key and every relation name must be a package-name slug
// (schema.ValidatePackageName), and every entry platform must satisfy the
// consumer grammar (platform.ValidateConsumer). Every (version, platform)
// pair is listed once, and no version has both a platform-agnostic entry and
// platform entries (repo build's publishing rules). Index names flow into
// on-disk paths downstream (the planner's extract directory), and the index
// signature proves only who published a name, not that it is safe. A
// violation fails the whole load: a malformed signed index is a publisher
// fault, not an entry to skip.
//
// Only entries whose platform is empty (platform-agnostic) or equal to host
// become candidates; everything downstream of the catalog sees only what this
// host can install. The other entries are recorded per (name, version) so
// callers can name the platforms a package IS published for (OtherPlatforms,
// NewestUnavailable). Entries are validated before they are filtered, so a
// malformed entry for another platform still fails the load.
func BuildCatalog(idx *schema.Index, sourceName, host string) (*Catalog, error) {
	c := &Catalog{
		byName:  map[string][]*Candidate{},
		dropped: map[string]map[string]*unavailable{},
		host:    host,
	}
	for name, entries := range idx.Packages {
		if err := schema.ValidatePackageName(name); err != nil {
			return nil, fmt.Errorf("catalog: %w", err)
		}
		// builds maps version -> platform ("" for platform-agnostic) for the
		// entries seen so far, to enforce repo build's publishing rules.
		builds := map[string]map[string]bool{}
		for i := range entries {
			e := &entries[i]
			if err := validateRelationNames(name, e); err != nil {
				return nil, err
			}
			if e.Platform != "" {
				if err := platform.ValidateConsumer(e.Platform); err != nil {
					return nil, fmt.Errorf("catalog: %s %s: %w", name, e.Version, err)
				}
			}
			v, err := semver.NewVersion(e.Version)
			if err != nil {
				return nil, fmt.Errorf("catalog: %s %q: %w", name, e.Version, err)
			}
			if err := admitBuild(builds, name, e.Version, e.Platform); err != nil {
				return nil, err
			}
			if e.Platform != "" && e.Platform != host {
				byVersion := c.dropped[name]
				if byVersion == nil {
					byVersion = map[string]*unavailable{}
					c.dropped[name] = byVersion
				}
				u := byVersion[e.Version]
				if u == nil {
					u = &unavailable{sv: v}
					byVersion[e.Version] = u
				}
				u.platforms = append(u.platforms, e.Platform)
				continue
			}
			c.byName[name] = append(c.byName[name], &Candidate{
				Name: name, Version: e.Version, ContentHash: e.ContentHash, Artifact: e.Artifact,
				Platform:     e.Platform,
				Attestations: e.Attestations,
				Depends:      e.Depends, Recommends: e.Recommends, Suggests: e.Suggests,
				Provides: e.Provides, Conflicts: e.Conflicts, Obsoletes: e.Obsoletes,
				Source: sourceName,
				sv:     v,
			})
		}
	}
	for _, byVersion := range c.dropped {
		for _, u := range byVersion {
			slices.Sort(u.platforms)
		}
	}
	c.reindex()
	return c, nil
}

// admitBuild records that an index entry publishes version of name for plat
// ("" for platform-agnostic) in builds, or returns the error for an entry that
// breaks repo build's publishing rules: a (version, platform) pair is listed
// once, and a version is either one platform-agnostic artifact or one artifact
// per platform, never both. Either violation would hand a host two candidates
// for one version, so it fails the load like any other malformed entry.
func admitBuild(builds map[string]map[string]bool, name, version, plat string) error {
	byPlat := builds[version]
	if byPlat[plat] {
		return fmt.Errorf("catalog: %s %q for platform %q is listed more than once",
			name, version, platform.Display(plat))
	}
	other := ""
	switch {
	case plat != "" && byPlat[""]:
		other = plat
	case plat == "" && len(byPlat) > 0:
		other = slices.Sorted(maps.Keys(byPlat))[0]
	}
	if other != "" {
		return fmt.Errorf("catalog: %s %q has both a platform-agnostic entry and a %q entry",
			name, version, other)
	}
	if byPlat == nil {
		byPlat = map[string]bool{}
		builds[version] = byPlat
	}
	byPlat[plat] = true
	return nil
}

// validateRelationNames checks every relation target an index entry names, in
// all six relation fields, against the package-name slug rule.
func validateRelationNames(name string, e *schema.IndexEntry) error {
	for _, rels := range []struct {
		field string
		list  []schema.Relation
	}{
		{"depends", e.Depends},
		{"recommends", e.Recommends},
		{"suggests", e.Suggests},
		{"provides", e.Provides},
		{"conflicts", e.Conflicts},
		{"obsoletes", e.Obsoletes},
	} {
		for _, rel := range rels.list {
			if err := schema.ValidatePackageName(rel.Name); err != nil {
				return fmt.Errorf("catalog: %s %s: %s: %w", name, e.Version, rels.field, err)
			}
		}
	}
	return nil
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
		// A name published as a real package only for other platforms is
		// owned by that publisher. A provider must not stand in for it on this
		// host, or a lower-priority source could satisfy it by declaring
		// provides; dropping the virtual entry lets lookup fall through to
		// the wrong-platform failure instead.
		if len(c.byName[name]) == 0 && len(c.dropped[name]) > 0 {
			delete(c.providers, name)
			delete(c.virtualNames, name)
			continue
		}
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
// type: KindWrongPlatform when the name is published only for other platforms,
// or no host version satisfies constraint but another platform's does; KindUnknownName when the
// name is absent from every source; and KindNoVersion (with Available set)
// when the name is present but no version on any platform satisfies the
// constraint.
func (c *Catalog) Newest(name, constraint string) (*Candidate, error) {
	req := Requirement{Name: name, VersionRange: constraint}
	if !c.knownName(name) {
		if we := c.wrongPlatformError(req, []string{name}); we != nil {
			return nil, we
		}
		return nil, &ResolveError{Kind: KindUnknownName, Requirement: req, Path: []string{name}}
	}
	// candidatesFor returns real candidates first, sorted newest-first, which
	// gives us the newest satisfying candidate at index 0.
	cands := c.candidatesFor(req)
	if len(cands) == 0 {
		if we := c.wrongPlatformVersionError(req, []string{name}); we != nil {
			return nil, we
		}
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

// PublishedNames returns the sorted real package names published for any
// platform: every name with an artifact for this host (Names) plus every name
// whose entries were all dropped for other platforms. search lists these so a
// package that exists only for other platforms is still found.
func (c *Catalog) PublishedNames() []string {
	set := make(map[string]struct{}, len(c.byName)+len(c.dropped))
	for name := range c.byName {
		set[name] = struct{}{}
	}
	for name := range c.dropped {
		set[name] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// UnavailableVersions returns, newest first, the versions of name published
// only for other platforms. A version with an artifact for this host, under
// that spelling or a semver-equal one ("1.0" and "1.0.0"), is available even
// if other platforms also publish it, and is not listed. Semver-equal
// spellings are ordered by spelling so the result is stable. Returns an empty
// (non-nil) slice when there are none, like Versions.
func (c *Catalog) UnavailableVersions(name string) []string {
	var vs []*unavailable
	for _, u := range c.dropped[name] {
		onHost := slices.ContainsFunc(c.byName[name], func(cand *Candidate) bool { return cand.sv.Equal(u.sv) })
		if !onHost {
			vs = append(vs, u)
		}
	}
	sort.Slice(vs, func(i, j int) bool {
		if !vs[i].sv.Equal(vs[j].sv) {
			return vs[i].sv.GreaterThan(vs[j].sv)
		}
		return vs[i].sv.Original() < vs[j].sv.Original()
	})
	out := make([]string, 0, len(vs))
	for _, u := range vs {
		out = append(out, u.sv.Original())
	}
	return out
}

// OtherPlatforms returns the sorted platforms (name, version) is published for
// that were dropped because they are not this catalog's host. Semver-equal
// spellings of version ("1.0" and "1.0.0") are one version, so their
// platforms are unioned, as in NewestUnavailable. nil when none were. The
// slice is a copy.
func (c *Catalog) OtherPlatforms(name, version string) []string {
	sv, err := semver.NewVersion(version)
	var out []string
	for v, u := range c.dropped[name] {
		if v == version || (err == nil && u.sv.Equal(sv)) {
			out = append(out, u.platforms...)
		}
	}
	if out == nil {
		return nil
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// NewestUnavailable reports, for a name the index publishes but never for this
// host, the newest version (by semver) published for any platform and the
// sorted platforms it is published for. Distinct version strings that parse to
// that one semver ("1.0" and "1.0.0") are one version: their platforms are
// unioned, and the lexically smallest string names them (as mirror pull's
// pick does) so the answer is independent of map order. ok is false when the
// name has a host-applicable candidate, or no entry at all (an unknown name).
func (c *Catalog) NewestUnavailable(name string) (version string, platforms []string, ok bool) {
	if len(c.byName[name]) > 0 {
		return "", nil, false
	}
	return c.newestDropped(name, "")
}

// newestDropped reports the newest version of name (by semver) that satisfies
// constraint ("" = any) among the entries dropped for other platforms, and the
// sorted union of the platforms of every spelling semver-equal to it; the
// lexically smallest such spelling names the version. ok is false when no
// dropped version satisfies constraint.
func (c *Catalog) newestDropped(name, constraint string) (version string, platforms []string, ok bool) {
	var best *unavailable
	for v, u := range c.dropped[name] {
		if allowed, err := constraintAllows(constraint, v); err != nil || !allowed {
			continue
		}
		if best == nil || u.sv.GreaterThan(best.sv) || (u.sv.Equal(best.sv) && v < version) {
			best, version = u, v
		}
	}
	if best == nil {
		return "", nil, false
	}
	for _, u := range c.dropped[name] {
		if u.sv.Equal(best.sv) {
			platforms = append(platforms, u.platforms...)
		}
	}
	slices.Sort(platforms)
	return version, slices.Compact(platforms), true
}

// wrongPlatformError returns the KindWrongPlatform failure for req when every
// entry the catalog holds for req.Name was dropped as another platform's, or
// nil when that is not the case (the name has a host candidate, or no entry at
// all).
func (c *Catalog) wrongPlatformError(req Requirement, path []string) *ResolveError {
	version, platforms, ok := c.NewestUnavailable(req.Name)
	if !ok {
		return nil
	}
	return &ResolveError{Kind: KindWrongPlatform, Requirement: req, Path: path,
		Version: version, Platforms: platforms, Host: c.host}
}

// wrongPlatformVersionError returns the KindWrongPlatform failure for req when
// no host candidate satisfies req's constraint but a version published only
// for other platforms does, naming the newest such version; nil otherwise. It
// tells "this host cannot install that version" apart from "no such version".
func (c *Catalog) wrongPlatformVersionError(req Requirement, path []string) *ResolveError {
	version, platforms, ok := c.newestDropped(req.Name, req.VersionRange)
	if !ok {
		return nil
	}
	return &ResolveError{Kind: KindWrongPlatform, Requirement: req, Path: path,
		Version: version, Platforms: platforms, Host: c.host}
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

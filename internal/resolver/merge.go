package resolver

import (
	"fmt"
	"maps"
	"slices"
)

// MergeCatalogs collapses per-source catalogs into one, applying priority
// overlay: for each package name, the first source in order that publishes the
// name for any platform owns it, unless a per-package pin forces a specific
// source. catalogs holds every fetched source's catalog keyed by source name;
// order is the precedence list (a subset of catalogs' keys); pins maps a
// package name to a source name that must provide it.
//
// Ownership does not depend on the host. When the owning source publishes the
// name only for other platforms, the merged catalog has no candidate for it and
// carries the owner's record of those platforms, so resolution fails naming
// them; a lower-priority source's host build is NOT substituted. Otherwise a
// public lower-priority source could stand in for a private package on every
// host the private source does not build for (dependency confusion). A user
// who wants the lower source's build pins the name to it. The owner's dropped
// record travels with the name in either case.
//
// A pinned source may live outside order. A name absent from every order
// catalog and unpinned is simply omitted (downstream resolution then reports it
// as unknown).
func MergeCatalogs(catalogs map[string]*Catalog, order []string, pins map[string]string) (*Catalog, error) {
	merged := &Catalog{byName: map[string][]*Candidate{}, dropped: map[string]map[string]*unavailable{}}
	// FetchCatalog builds every per-source catalog for the same host
	// (platform.Host()), so any one of them names it.
	for _, cat := range catalogs {
		if cat != nil {
			merged.host = cat.host
			break
		}
	}

	names := map[string]bool{}
	for _, s := range order {
		if cat := catalogs[s]; cat != nil {
			for name := range cat.byName {
				names[name] = true
			}
			for name := range cat.dropped {
				names[name] = true
			}
		}
	}
	for name := range pins {
		names[name] = true
	}

	// Sorted, so that when several pinned names fail, the error returned is
	// the same on every run.
	for _, name := range slices.Sorted(maps.Keys(names)) {
		var winner string
		if src, pinned := pins[name]; pinned {
			cat, ok := catalogs[src]
			if !ok {
				return nil, fmt.Errorf("package %q pins source %q, which is not configured", name, src)
			}
			if len(cat.byName[name]) == 0 {
				if we := cat.wrongPlatformError(Requirement{Name: name}, []string{name}); we != nil {
					return nil, we
				}
				return nil, fmt.Errorf("package %q pinned to source %q, but %q has no package %q", name, src, src, name)
			}
			winner = src
		} else {
			for _, s := range order {
				if cat := catalogs[s]; cat != nil && (len(cat.byName[name]) > 0 || len(cat.dropped[name]) > 0) {
					winner = s
					break
				}
			}
			if winner == "" {
				continue
			}
		}
		// Copy the slice so reindex()'s in-place sort never mutates the winning
		// source's own catalog (shared via the catalogs map). An owner with no
		// host build contributes no candidate, so the name stays out of byName.
		if cands := catalogs[winner].byName[name]; len(cands) > 0 {
			merged.byName[name] = append([]*Candidate(nil), cands...)
		}
		if d := catalogs[winner].dropped[name]; d != nil {
			merged.dropped[name] = d
		}
	}

	merged.reindex()
	return merged, nil
}

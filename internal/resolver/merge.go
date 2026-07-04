package resolver

import "fmt"

// MergeCatalogs collapses per-source catalogs into one, applying priority
// overlay: for each real package name, the first source in order whose catalog
// has a real entry owns the name, unless a per-package pin forces a specific
// source. catalogs holds every fetched source's catalog keyed by source name;
// order is the precedence list (a subset of catalogs' keys); pins maps a
// package name to a source name that must provide it.
//
// A pinned source may live outside order. A name absent from every order
// catalog and unpinned is simply omitted (downstream resolution then reports it
// as unknown).
func MergeCatalogs(catalogs map[string]*Catalog, order []string, pins map[string]string) (*Catalog, error) {
	merged := &Catalog{byName: map[string][]*Candidate{}}

	names := map[string]bool{}
	for _, s := range order {
		if cat := catalogs[s]; cat != nil {
			for name := range cat.byName {
				names[name] = true
			}
		}
	}
	for name := range pins {
		names[name] = true
	}

	for name := range names {
		var winner string
		if src, pinned := pins[name]; pinned {
			cat, ok := catalogs[src]
			if !ok {
				return nil, fmt.Errorf("package %q pins source %q, which is not configured", name, src)
			}
			if len(cat.byName[name]) == 0 {
				return nil, fmt.Errorf("package %q pinned to source %q, but %q has no package %q", name, src, src, name)
			}
			winner = src
		} else {
			for _, s := range order {
				if cat := catalogs[s]; cat != nil && len(cat.byName[name]) > 0 {
					winner = s
					break
				}
			}
			if winner == "" {
				continue
			}
		}
		// Copy the slice so reindex()'s in-place sort never mutates the winning
		// source's own catalog (shared via the catalogs map).
		merged.byName[name] = append([]*Candidate(nil), catalogs[winner].byName[name]...)
	}

	merged.reindex()
	return merged, nil
}

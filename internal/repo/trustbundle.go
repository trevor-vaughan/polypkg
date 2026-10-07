package repo

import (
	"maps"
	"slices"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// trustBundleSet is what a build publishes in trust-bundle.json: builder keys
// (deduplicated by key_id, in first-seen order) and sigstore roots
// (deduplicated by structural equality). An empty set publishes no bundle.
type trustBundleSet struct {
	keys  map[string]schema.BuilderKey
	order []string
	roots []schema.SigstoreRoot
}

// collectTrustBundle gathers the trust-bundle material for a build of lay:
// first the roots converted from each sigstore_roots entry (manifest order),
// then every prebuilt entry's carried trust_bundle, visited in the order Build
// visits packages (sorted names, manifest order within a name). A root already
// collected is not added again, so a sigstore root that an upstream bundle also
// carries is published once.
//
// Build and Inspector.Pending both call it, so `repo status` reports a pending
// trust-bundle change exactly when a build would publish one.
func collectTrustBundle(lay repoLayout) (trustBundleSet, error) {
	s := trustBundleSet{keys: map[string]schema.BuilderKey{}}
	for _, entry := range lay.manifest.SigstoreRoots {
		roots, err := sigstoreRootsFromFile(entry, resolveRel(lay.manifestDir, entry))
		if err != nil {
			return trustBundleSet{}, err
		}
		for i := range roots {
			if !containsRoot(s.roots, roots[i]) {
				s.roots = append(s.roots, roots[i])
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(lay.manifest.Packages)) {
		for _, pkg := range lay.manifest.Packages[name] {
			if pkg.Prebuilt == nil || pkg.Prebuilt.TrustBundle == "" {
				continue
			}
			if err := mergeCarriedBundle(resolveRel(lay.manifestDir, pkg.Prebuilt.TrustBundle), s.keys, &s.order, &s.roots); err != nil {
				return trustBundleSet{}, err
			}
		}
	}
	return s, nil
}

// publishedChange compares s with the trust-bundle.json published in
// outputDir. changed is true when s has material and the published bundle does
// not already carry exactly it (serial and expiry excluded, as for the index).
// orphaned is true when s is empty but an earlier build's bundle is still
// published: it would keep vouching for keys and roots the manifest no longer
// names, so it must be withdrawn at a new serial.
func (s trustBundleSet) publishedChange(outputDir string) (changed, orphaned bool) {
	if len(s.order) == 0 && len(s.roots) == 0 {
		return false, publishedTrustBundleExists(outputDir)
	}
	return !publishedBundleMatches(outputDir, s.keys, s.roots), false
}

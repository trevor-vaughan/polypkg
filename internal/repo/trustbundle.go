package repo

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"

	"github.com/trevor-vaughan/polypkg/internal/attest"
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

// TrustBundleChange summarizes a change to the published trust-bundle.json
// for whoever reviews it. The bundle widens what consumers trust (its
// sigstore roots verify carried provenance, its builder keys verify carried
// signatures), so a sigstore_roots or trust_bundle edit is reviewed by what
// the new bundle vouches for, not by the path that changed.
type TrustBundleChange struct {
	// Withdrawn is true when the manifest no longer backs a published
	// bundle and the build removes it; Roots and BuilderKeys are then empty.
	Withdrawn   bool                  `json:"withdrawn"`
	Roots       []SigstoreRootSummary `json:"sigstore_roots,omitempty"`
	BuilderKeys []BuilderKeySummary   `json:"builder_keys,omitempty"`
}

// SigstoreRootSummary identifies one sigstore root of a trust bundle.
type SigstoreRootSummary struct {
	// FulcioRootSHA256 is the hex SHA-256 of the DER of the root's Fulcio
	// root certificate: the self-signed certificate of its fulcio_ca chain.
	FulcioRootSHA256 string `json:"fulcio_root_sha256"`
	ValidFrom        string `json:"valid_from"`
	ValidUntil       string `json:"valid_until,omitempty"` // empty: open-ended
}

// BuilderKeySummary identifies one builder key of a trust bundle.
type BuilderKeySummary struct {
	KeyID      string `json:"key_id"`
	ValidFrom  string `json:"valid_from"`
	ValidUntil string `json:"valid_until,omitempty"` // empty: open-ended
}

// summary describes what a build of s does to the published bundle, given
// publishedChange's verdict: nil when it leaves the bundle as it is. Roots
// and keys are listed in the order the bundle publishes them.
func (s trustBundleSet) summary(changed, orphaned bool) (*TrustBundleChange, error) {
	if orphaned {
		return &TrustBundleChange{Withdrawn: true}, nil
	}
	if !changed {
		return nil, nil
	}
	c := &TrustBundleChange{}
	for i := range s.roots {
		r := &s.roots[i]
		rootCert, _, err := attest.FulcioRoot(r.FulcioCA)
		if err != nil {
			return nil, &PublishError{
				Msg:  fmt.Sprintf("a carried sigstore root (valid from %s) has no usable Fulcio root certificate", r.ValidFrom),
				Hint: "re-pull the carried trust_bundle from its upstream; it is damaged",
				Err:  err,
			}
		}
		sum := sha256.Sum256(rootCert.Raw)
		c.Roots = append(c.Roots, SigstoreRootSummary{
			FulcioRootSHA256: hex.EncodeToString(sum[:]),
			ValidFrom:        r.ValidFrom,
			ValidUntil:       r.ValidUntil,
		})
	}
	for _, id := range s.order {
		k := s.keys[id]
		c.BuilderKeys = append(c.BuilderKeys, BuilderKeySummary{KeyID: k.KeyID, ValidFrom: k.ValidFrom, ValidUntil: k.ValidUntil})
	}
	return c, nil
}

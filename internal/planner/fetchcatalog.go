package planner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Masterminds/semver/v3"

	"github.com/trevor-vaughan/polypkg/internal/resolver"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/source"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

// FetchResult is returned by FetchCatalog. It carries everything the artifact-
// fetch loop (Plan's second stage) needs to continue without re-deriving any of
// the network or trust work. Catalog is nil when the scope's package set is
// empty — callers must short-circuit in that case (Plan does so via the
// len(reqs) > 0 guard).
type FetchResult struct {
	// Catalog is the merged, resolved package index. Nil when no packages are
	// requested.
	Catalog *resolver.Catalog
	// Backends maps source name -> backend used to fetch that source's index and
	// artifacts.
	Backends map[string]source.Backend
	// Keyrings maps source name -> verified signing keys for that source; the
	// caller verifies each artifact against ITS OWN source's keyring.
	Keyrings map[string]trust.Keyring
	// SourceURLs maps source name -> that source's base URL (for ManifestEntry).
	SourceURLs map[string]string
	// HighWater maps source name -> package name -> the highest version that
	// source's verified index has EVER offered (D15), after folding in this
	// fetch. Plan's downgrade guard refuses resolving below it without an
	// exact profile pin.
	HighWater map[string]map[string]string
}

// FetchCatalog fetches and verifies the trust document and signed index for
// every source in the profile's fetch set — the configured sources.order plus
// any per-package source pin referenced by an in-scope package — advances each
// source's trust serial high-water mark on success, and merges their catalogs
// by priority overlay into a single resolved catalog. It returns that catalog
// together with the per-source backends and verified keyrings the caller needs
// to fetch and verify each artifact against its own source.
//
// FetchCatalog fails fast: if any source in the fetch set is unreachable or
// fails verification, the whole call returns an error (no partial catalog).
//
// Callers MUST hold the per-scope apply lock before calling FetchCatalog to
// avoid serial-advancement races with concurrent applies. Plan already acquires
// this lock (via the CLI layer); any other in-process caller must do the same.
//
// FetchCatalog returns a FetchResult with a nil Catalog when the profile scope
// requests no packages — callers must skip the artifact-fetch stage in that
// case.
func FetchCatalog(ctx context.Context, p *schema.Profile, opts Options) (*FetchResult, error) {
	// Select only this scope's packages to determine whether a fetch is needed.
	scopePkgs := p.Packages[opts.Scope]
	reqs := make([]resolver.Requirement, 0, len(scopePkgs))
	for name, ref := range scopePkgs {
		reqs = append(reqs, resolver.Requirement{Name: name, VersionRange: ref.Version})
	}

	if len(reqs) == 0 && !opts.ForceCatalogFetch {
		// No packages requested: skip the network entirely. The install action
		// sets ForceCatalogFetch to fetch the catalog anyway so it can resolve a
		// package that is not yet in the profile.
		return &FetchResult{}, nil
	}

	// Build the fetch set: sources in order (validated), then any per-package
	// source pin referenced by an in-scope package. Deduplicated; pins recorded.
	pins := map[string]string{}
	fetchSet := make([]string, 0, len(p.Sources.Order))
	seen := map[string]bool{}
	for _, s := range p.Sources.Order {
		if _, ok := p.Sources.Sources[s]; !ok {
			return nil, fmt.Errorf("sources.order references undefined source %q", s)
		}
		if !seen[s] {
			fetchSet = append(fetchSet, s)
			seen[s] = true
		}
	}
	// Map iteration order here is intentionally irrelevant: merge precedence
	// derives from p.Sources.Order, not the order pins are appended to fetchSet.
	for name, ref := range scopePkgs {
		if ref.Source == "" {
			continue
		}
		if _, ok := p.Sources.Sources[ref.Source]; !ok {
			return nil, fmt.Errorf("package %q pins undefined source %q", name, ref.Source)
		}
		pins[name] = ref.Source
		if !seen[ref.Source] {
			fetchSet = append(fetchSet, ref.Source)
			seen[ref.Source] = true
		}
	}
	if len(fetchSet) == 0 {
		return nil, fmt.Errorf("no sources configured: sources.order is empty")
	}

	catalogs := make(map[string]*resolver.Catalog, len(fetchSet))
	backends := make(map[string]source.Backend, len(fetchSet))
	keyrings := make(map[string]trust.Keyring, len(fetchSet))
	urls := make(map[string]string, len(fetchSet))
	high := make(map[string]map[string]string, len(fetchSet))
	for _, s := range fetchSet {
		cat, backend, keyring, hwm, err := fetchOneSource(ctx, s, p.Sources.Sources[s], opts)
		if err != nil {
			return nil, fmt.Errorf("source %q: %w", s, err) // fail-fast
		}
		catalogs[s] = cat
		backends[s] = backend
		keyrings[s] = keyring
		urls[s] = p.Sources.Sources[s].URL
		high[s] = hwm
	}

	merged, err := resolver.MergeCatalogs(catalogs, p.Sources.Order, pins)
	if err != nil {
		return nil, err
	}

	return &FetchResult{Catalog: merged, Backends: backends, Keyrings: keyrings, SourceURLs: urls, HighWater: high}, nil
}

// fetchOneSource fetches and verifies one source's trust document and signed
// index, advances that source's serial high-water mark, and returns its tagged
// catalog plus the backend, keyring, and per-package version high-water map
// needed to fetch/verify artifacts and guard against downgrades.
func fetchOneSource(ctx context.Context, sourceName string, src schema.SourceBackend, opts Options) (*resolver.Catalog, source.Backend, trust.Keyring, map[string]string, error) {
	if src.TrustRoot == "" {
		return nil, nil, nil, nil, fmt.Errorf("source has no trust_root; refusing to use an unverifiable index")
	}
	opts.progress("fetching trust", src.URL)
	anchor, err := os.ReadFile(filepath.Clean(src.TrustRoot))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("read trust root %q: %w", src.TrustRoot, err)
	}
	verifier, err := trust.NewVerifier(src.Type, string(anchor), sourceName)
	if err != nil {
		var ae *trust.AnchorError
		if errors.As(err, &ae) {
			// The anchor file exists but is not a minisign public key. The
			// planner knows the trust_root path; carry it in a typed error
			// the CLI frames for the user (the library detail stays in the
			// chain for logs).
			return nil, nil, nil, nil, &TrustRootError{Path: src.TrustRoot, Err: err}
		}
		return nil, nil, nil, nil, fmt.Errorf("trust verifier: %w", err)
	}
	seen, err := trust.LoadSeen(opts.StateHome, sourceName)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("load trust state: %w", err)
	}
	backend := source.NewNativeBackend(source.NativeBackendOpts{
		URL:      src.URL,
		CacheDir: filepath.Join(opts.StateHome, "cache", sourceName),
	})

	var docBytes []byte
	var docSig string
	if src.TrustDoc != "" {
		docPath := filepath.Clean(src.TrustDoc)
		docBytes, err = os.ReadFile(docPath)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("read trust document %q: %w", docPath, err)
		}
		sigBytes, err := os.ReadFile(filepath.Clean(docPath + ".minisig"))
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("read trust document signature %q: %w", docPath+".minisig", err)
		}
		docSig = string(sigBytes)
	} else {
		docBytes, docSig, err = backend.FetchTrustDoc(ctx)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("fetch trust document: %w", err)
		}
	}
	state, trustSerial, err := verifier.LoadTrust(docBytes, docSig, seen.TrustSerial)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("verify trust document: %w", err)
	}

	opts.progress("fetching index", src.URL)
	rawIndex, idxSig, err := backend.FetchIndex(ctx)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("fetch index: %w", err)
	}
	// Order matters (D13/D15): signature first, then the serial rollback
	// check, then parse + freshness + catalog construction — and only THEN
	// persist the advanced serials and per-package high-water marks. A stale,
	// unparseable, or catalog-refused index must never advance any stored
	// state: persisting its serial would wedge the consumer against every
	// still-good index below it until the publisher reaches a higher serial.
	idxClaims, err := state.Verify(trust.RoleIndex, rawIndex, idxSig)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("index signature verification failed: %w", err)
	}
	indexSerial, err := idxClaims.IndexSerial()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("index: %w", err)
	}
	if indexSerial < seen.IndexSerial {
		return nil, nil, nil, nil, fmt.Errorf("index rollback: serial %d is below last-seen %d", indexSerial, seen.IndexSerial)
	}
	index, err := schema.ParseIndex(bytes.NewReader(rawIndex))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parse index: %w", err)
	}
	if err := trust.CheckExpiry("index", index.Expires); err != nil {
		return nil, nil, nil, nil, err
	}

	// Fold this verified index into the per-package version high-water map:
	// semver-max per package, preserving entries for packages the index no
	// longer offers (vanish-then-reappear-older must still refuse, D15).
	hwm := seen.Packages
	if hwm == nil {
		hwm = map[string]string{}
	}
	for name, entries := range index.Packages {
		for i := range entries {
			e := &entries[i]
			nv, err := semver.NewVersion(e.Version)
			if err != nil {
				continue // BuildCatalog rejects non-semver below; don't double-report here
			}
			if cur, ok := hwm[name]; ok {
				if cv, cerr := semver.NewVersion(cur); cerr == nil && !nv.GreaterThan(cv) {
					continue
				}
			}
			hwm[name] = e.Version
		}
	}
	catalog, err := resolver.BuildCatalog(index, sourceName)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("build catalog: %w", err)
	}
	if err := trust.StoreSeen(opts.StateHome, sourceName, trust.Seen{TrustSerial: trustSerial, IndexSerial: indexSerial, Packages: hwm}); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("persist trust state: %w", err)
	}
	return catalog, backend, state, hwm, nil
}

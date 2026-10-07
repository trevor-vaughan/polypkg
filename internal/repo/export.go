package repo

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// ExportResult summarizes a completed export.
type ExportResult struct {
	BundlePath string
	Entries    int
	Serial     uint64
	Expires    string
	Source     string
}

// ExportBundle writes a single, self-contained, signed tarball mirror of the
// already-built repository. selectors chooses what to export: empty = the whole
// repository; "name" = every version of that package; "name@version" = one
// version (repeatable). The carried index/trust documents are copied verbatim
// (their existing signatures still validate); a new completeness manifest
// listing every bundled file is signed with the same key that signs the index.
func (b *Builder) ExportBundle(selectors []string, bundlePath string) (ExportResult, error) {
	outDir := b.insp.layout.outputDir
	source := b.insp.layout.manifest.Source

	idxRaw, err := os.ReadFile(filepath.Join(outDir, "index.json")) //nolint:gosec // G304: output dir from validated manifest; our own published docs
	if err != nil {
		return ExportResult{}, &PublishError{Msg: "read published index (is the repository built?)", Err: err}
	}
	idx, err := schema.ParseIndex(bytes.NewReader(idxRaw))
	if err != nil {
		return ExportResult{}, fmt.Errorf("parse published index: %w", err)
	}
	trustRaw, err := os.ReadFile(filepath.Join(outDir, "trust.json")) //nolint:gosec // G304: output dir from validated manifest; our own published docs
	if err != nil {
		return ExportResult{}, &PublishError{Msg: "read published trust document", Err: err}
	}
	td, err := schema.ParseTrustDoc(bytes.NewReader(trustRaw))
	if err != nil {
		return ExportResult{}, fmt.Errorf("parse published trust document: %w", err)
	}

	entries, err := resolveSelectors(idx, selectors)
	if err != nil {
		return ExportResult{}, err
	}

	// Reachable relative-path set (deduplicated). Always-present metadata first.
	rel := map[string]struct{}{
		"index.json":         {},
		"index.json.minisig": {},
		"trust.json":         {},
		"trust.json.minisig": {},
		"trust_root.pub":     {},
	}
	// Optional signed docs: include both doc and sig only when the doc exists.
	for _, opt := range []string{"trust-bundle.json", "revocations.json"} {
		if _, statErr := os.Stat(filepath.Join(outDir, opt)); statErr == nil {
			rel[opt] = struct{}{}
			rel[opt+".minisig"] = struct{}{}
		}
	}
	for i := range entries {
		e := &entries[i]
		rel[e.Artifact] = struct{}{}
		rel[e.Artifact+".minisig"] = struct{}{}
		for _, a := range e.Attestations {
			rel[a.Artifact] = struct{}{}
			rel[a.Artifact+".minisig"] = struct{}{}
		}
	}

	// Read every reachable file, hash it, classify it. Sorted for determinism.
	names := make([]string, 0, len(rel))
	for n := range rel {
		names = append(names, n)
	}
	sort.Strings(names)

	bundleFiles := make([]bundleFile, 0, len(names)+2)
	manifestEntries := make([]schema.PoolEntry, 0, len(names))
	for _, n := range names {
		body, rerr := os.ReadFile(filepath.Join(outDir, n)) //nolint:gosec // G304: output dir from validated manifest; our own published docs
		if rerr != nil {
			return ExportResult{}, fmt.Errorf("read reachable file %q: %w", n, rerr)
		}
		kind, kerr := classifyKind(n)
		if kerr != nil {
			return ExportResult{}, kerr
		}
		manifestEntries = append(manifestEntries, schema.PoolEntry{Path: n, ContentHash: ContentHash(body), Kind: kind})
		bundleFiles = append(bundleFiles, bundleFile{name: n, body: body})
	}

	manifest := schema.PoolManifest{
		Schema:   "polypkg.pool-manifest/v1",
		Source:   source,
		Serial:   td.Serial,
		IssuedAt: td.IssuedAt,
		Expires:  idx.Expires,
		Entries:  manifestEntries,
	}
	manifestJSON, err := json.Marshal(&manifest)
	if err != nil {
		return ExportResult{}, fmt.Errorf("marshal pool manifest: %w", err)
	}
	manifestSig := b.key.SignPoolManifest(td.Serial, manifestJSON)

	bundleFiles = append(bundleFiles,
		bundleFile{name: "pool-manifest.json", body: manifestJSON},
		bundleFile{name: "pool-manifest.json.minisig", body: []byte(manifestSig)},
	)

	var buf bytes.Buffer
	if err := writeBundleTar(&buf, bundleFiles); err != nil {
		return ExportResult{}, fmt.Errorf("write bundle tar: %w", err)
	}
	if err := os.WriteFile(bundlePath, buf.Bytes(), 0o644); err != nil { //nolint:gosec // G306: a mirror tarball is public, redistributable data
		return ExportResult{}, &PublishError{
			Msg:  "cannot write bundle " + bundlePath,
			Hint: "pass -o with a path in a directory you can write to",
			Err:  err,
		}
	}
	return ExportResult{BundlePath: bundlePath, Entries: len(manifestEntries), Serial: td.Serial, Expires: idx.Expires, Source: source}, nil
}

// resolveSelectors maps a selection to the set of index entries it names. Empty
// selectors means every entry in the repository (deterministic package order).
func resolveSelectors(idx *schema.Index, selectors []string) ([]schema.IndexEntry, error) {
	if len(selectors) == 0 {
		names := make([]string, 0, len(idx.Packages))
		for n := range idx.Packages {
			names = append(names, n)
		}
		sort.Strings(names)
		var all []schema.IndexEntry
		for _, n := range names {
			all = append(all, idx.Packages[n]...)
		}
		return all, nil
	}
	var out []schema.IndexEntry
	for _, sel := range selectors {
		name, ver, hasVer := strings.Cut(sel, "@")
		pkgEntries, ok := idx.Packages[name]
		if !ok {
			return nil, fmt.Errorf("package %q is not in the repository index", name)
		}
		if !hasVer {
			out = append(out, pkgEntries...)
			continue
		}
		found := false
		for i := range pkgEntries {
			if pkgEntries[i].Version == ver {
				out = append(out, pkgEntries[i])
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("package %q has no version %q in the repository index", name, ver)
		}
	}
	return out, nil
}

// classifyKind maps a bundle-relative path to its manifest kind.
func classifyKind(rel string) (string, error) {
	switch rel {
	case "index.json":
		return schema.PoolKindIndex, nil
	case "index.json.minisig":
		return schema.PoolKindIndexSig, nil
	case "trust.json":
		return schema.PoolKindTrust, nil
	case "trust.json.minisig":
		return schema.PoolKindTrustSig, nil
	case "trust-bundle.json":
		return schema.PoolKindTrustBundle, nil
	case "trust-bundle.json.minisig":
		return schema.PoolKindTrustBundleSig, nil
	case "revocations.json":
		return schema.PoolKindRevocationList, nil
	case "revocations.json.minisig":
		return schema.PoolKindRevocationListSig, nil
	case "trust_root.pub":
		return schema.PoolKindTrustRoot, nil
	}
	if strings.HasPrefix(rel, "pool/") {
		switch {
		case strings.HasSuffix(rel, ".tar.zst.minisig"):
			return schema.PoolKindArtifactSig, nil
		case strings.HasSuffix(rel, ".tar.zst"):
			return schema.PoolKindArtifact, nil
		case strings.HasSuffix(rel, ".att.json.minisig"):
			return schema.PoolKindAttestationSig, nil
		case strings.HasSuffix(rel, ".att.json"):
			return schema.PoolKindAttestation, nil
		}
	}
	return "", fmt.Errorf("cannot classify bundle file %q", rel)
}

type bundleFile struct {
	name string
	body []byte
}

// writeBundleTar writes files as a deterministic tar: sorted by name, PAX
// format, zeroed timestamps, fixed mode (mirrors internal/repo/pack.go).
func writeBundleTar(w *bytes.Buffer, files []bundleFile) error {
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	tw := tar.NewWriter(w)
	var zero time.Time
	for _, f := range files {
		hdr := &tar.Header{
			Name:       f.name,
			Mode:       0o644,
			Size:       int64(len(f.body)),
			Format:     tar.FormatPAX,
			ModTime:    zero,
			AccessTime: zero,
			ChangeTime: zero,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(f.body); err != nil {
			return err
		}
	}
	return tw.Close()
}

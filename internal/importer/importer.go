package importer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/root"

	"github.com/trevor-vaughan/polypkg/internal/ghrelease"
	"github.com/trevor-vaughan/polypkg/internal/platform"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

const (
	// maxAssetBytes caps an asset download at polypkg's package fetch limit.
	maxAssetBytes = 2 << 30
)

// Options configures one import. Owner, Repo, OutDir, Client, TrustedRoot and
// Lint are required; the rest have defaults.
type Options struct {
	// Owner and Repo name the GitHub repository whose release is imported.
	Owner, Repo string
	// Tag names the release; "" imports the latest non-prerelease release.
	Tag string
	// OutDir receives the package sources; it is created when missing, but
	// its parent must exist.
	OutDir string
	// Name is the package name; "" means the repository name, lower-cased.
	Name string
	// Version is the package version; "" derives it from the release tag.
	Version string
	// Bins are the executables to put on PATH; empty means just Name.
	Bins []string
	// Overrides force the asset for a platform ("os/arch" → asset-name glob).
	Overrides map[string]string
	// RequireAttestation drops a platform whose asset has no kept attestation.
	RequireAttestation bool
	// InsecureSkipDigest accepts an asset with neither a GitHub digest nor a
	// checksums-file entry, recording its integrity as UNVERIFIED.
	InsecureSkipDigest bool
	// Client talks to the GitHub REST API.
	Client *ghrelease.Client
	// TrustedRoot returns the Sigstore trusted_root.json the import verifies
	// attestations against and writes to OutDir (see DefaultTrustedRoot).
	TrustedRoot func(ctx context.Context) ([]byte, error)
	// Lint returns the findings for one generated package source (see
	// PkgLint). Any finding refuses the import.
	Lint func(dir string) ([]string, error)
}

// Result describes a completed import.
type Result struct {
	Name, Version string
	// TrustedRootPath is OutDir's sigstore-trusted-root.json.
	TrustedRootPath string
	// Platforms lists the imported platforms, ordered by platform.
	Platforms []PlatformResult
	// Skipped lists the release assets not imported and why: those the
	// matcher skipped and those whose platform the import dropped. Name and
	// Reason hold strings from the release (asset names, archive member
	// paths), which its author controls: a renderer must quote or escape
	// them rather than print them raw.
	Skipped []ghrelease.Skip
}

// PlatformResult describes one imported platform.
type PlatformResult struct {
	Platform string // "os/arch"
	Asset    string // the release asset's file name
	// Integrity is how the asset's bytes were checked: "github-digest",
	// "checksums-file" or "UNVERIFIED".
	Integrity    string
	Dir          string   // the package source directory written
	Attestations int      // provenance attestations carried in Dir/attestations
	Warnings     []string // provenance attestations dropped, and why
	Notes        []string // attestations skipped as not SLSA provenance (informational)
}

// refusal drops one platform from an import; any other error refuses the
// whole import. err, when set, is the cause reason describes.
type refusal struct {
	reason string
	err    error
}

func (r *refusal) Error() string { return r.reason }
func (r *refusal) Unwrap() error { return r.err }

// importRun carries one import's resolved settings through its platforms.
type importRun struct {
	opts      Options
	meta      recipeMeta
	origin    string // names the release in each recipe's comment
	bins      []string
	assets    []ghrelease.Asset // the whole release, for finding checksums files
	tm        root.TrustedMaterial
	out       *output
	checksums map[string][]byte // each downloaded checksums file by asset name, fetched once
}

// Run imports one GitHub release into opts.OutDir, writing one package source
// per platform at <OutDir>/<name>/<version>/<os>-<arch>/ (polypkg.yaml,
// content/<asset>, attestations/<n>.json) and the Sigstore trusted root at
// <OutDir>/sigstore-trusted-root.json.
//
// It refuses before downloading anything when a target directory already
// exists. Each asset's integrity is checked (its GitHub digest, else the
// release's checksums file), its attestations verified offline, and its
// generated source linted, all in a staging directory inside OutDir that is
// moved into place only when every platform has succeeded, so a failed
// import leaves OutDir as it was.
//
// A platform that cannot be imported safely (an unpublishable platform, an
// unsafe asset name, no integrity source, an unsupported asset kind, an
// executable built for another architecture, a missing executable, no
// attestation under RequireAttestation) is dropped and reported in
// Result.Skipped; the import fails when none remains. A digest
// mismatch, a download that is not the size the release lists, an
// attestation that fails verification, a lint finding or a GitHub API error
// refuses the whole import.
func Run(ctx context.Context, opts Options) (res *Result, err error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	if opts.Version != "" {
		if err := CheckVersion(opts.Version); err != nil {
			return nil, err
		}
	}
	name, err := resolveName(opts.Name, opts.Repo)
	if err != nil {
		return nil, err
	}
	bins := opts.Bins
	if len(bins) == 0 {
		bins = []string{name}
	}
	if err := CheckBins(bins); err != nil {
		return nil, err
	}

	rel, err := opts.Client.Release(ctx, opts.Owner, opts.Repo, opts.Tag)
	if err != nil {
		return nil, &LookupError{Lookup: "release", Err: err}
	}
	version, err := resolveVersion(opts.Version, rel.Tag)
	if err != nil {
		return nil, err
	}
	repo, err := opts.Client.Repo(ctx, opts.Owner, opts.Repo)
	if err != nil {
		return nil, &LookupError{Lookup: "repository", Err: err}
	}
	match, err := ghrelease.Match(rel.Assets, opts.Overrides)
	if err != nil {
		return nil, err
	}
	if len(match.Chosen) == 0 {
		return nil, fmt.Errorf("release %q of %s/%s has no asset polypkg can install (%d assets skipped)",
			rel.Tag, opts.Owner, opts.Repo, len(match.Skipped))
	}

	res = &Result{
		Name:            name,
		Version:         version,
		TrustedRootPath: filepath.Join(opts.OutDir, trustedRootFile),
		Skipped:         slices.Clone(match.Skipped),
	}
	var refusals []string
	var causes []error
	drop := func(plat string, a ghrelease.Asset, why error) {
		res.Skipped = append(res.Skipped, ghrelease.Skip{Name: a.Name, Reason: plat + ": " + why.Error()})
		refusals = append(refusals, plat+": "+why.Error())
		causes = append(causes, why)
	}
	noneLeft := func() error {
		return &NoPlatformError{Owner: opts.Owner, Repo: opts.Repo, Version: version, Reasons: refusals, causes: causes}
	}

	// Every target is checked before anything is downloaded or written.
	plats := make([]string, 0, len(match.Chosen))
	targets := make(map[string]string, len(match.Chosen))
	for _, p := range slices.Sorted(maps.Keys(match.Chosen)) {
		t, terr := targetDir(name, version, p)
		if terr != nil {
			drop(p, match.Chosen[p], terr)
			continue
		}
		dir := filepath.Join(opts.OutDir, filepath.FromSlash(t))
		switch _, serr := os.Lstat(dir); {
		case serr == nil:
			return nil, &TargetExistsError{Dir: dir}
		case !errors.Is(serr, fs.ErrNotExist):
			return nil, fmt.Errorf("check %s: %w", dir, serr)
		}
		plats = append(plats, p)
		targets[p] = t
	}
	if len(plats) == 0 {
		return nil, noneLeft()
	}

	rootJSON, err := opts.TrustedRoot(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetchTrustedRoot, err)
	}
	tm, err := root.NewTrustedRootFromJSON(rootJSON)
	if err != nil {
		return nil, fmt.Errorf("parse the Sigstore trusted root: %w", err)
	}

	out, err := openOutput(opts.OutDir)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			err = errors.Join(err, out.discard())
		}
	}()

	r := &importRun{
		opts: opts,
		meta: recipeMeta{
			name:        name,
			version:     version,
			title:       opts.Repo,
			description: cleanDescription(repo.Description),
		},
		origin:    fmt.Sprintf("github:%s/%s, version %s", opts.Owner, opts.Repo, version),
		bins:      bins,
		assets:    rel.Assets,
		tm:        tm,
		out:       out,
		checksums: map[string][]byte{},
	}
	done := make([]string, 0, len(plats))
	for _, p := range plats {
		a := match.Chosen[p]
		pr, perr := r.importPlatform(ctx, p, a, targets[p])
		var rf *refusal
		if errors.As(perr, &rf) {
			drop(p, a, rf)
			continue
		}
		if perr != nil {
			return nil, perr
		}
		res.Platforms = append(res.Platforms, *pr)
		done = append(done, targets[p])
	}
	if len(done) == 0 {
		return nil, noneLeft()
	}
	if err := out.commit(done, rootJSON); err != nil {
		return nil, err
	}
	committed = true
	if err := out.close(); err != nil {
		return nil, fmt.Errorf("imported into %s, but removing its staging directory failed: %w", opts.OutDir, err)
	}
	return res, nil
}

// validate refuses Options that Run cannot act on, before any network use.
func (o *Options) validate() error {
	if err := ghrelease.ValidateRepository(o.Owner, o.Repo); err != nil {
		return err
	}
	switch {
	case o.OutDir == "":
		return errors.New("an out-dir is required")
	case o.Client == nil:
		return errors.New("importer: Options.Client is required")
	case o.TrustedRoot == nil:
		return errors.New("importer: Options.TrustedRoot is required")
	case o.Lint == nil:
		return errors.New("importer: Options.Lint is required")
	}
	return nil
}

// targetDir returns the slash path below out-dir that holds plat's package
// source, <name>/<version>/<os>-<arch>. It refuses a platform repo build
// could not publish, which also keeps the path to safe segments.
func targetDir(name, version, plat string) (string, error) {
	if err := platform.ValidateProducer(plat); err != nil {
		return "", err
	}
	return path.Join(name, version, strings.ReplaceAll(plat, "/", "-")), nil
}

// importPlatform downloads, checks and stages the asset chosen for plat at
// target, then lints the staged source. A *refusal drops just this platform;
// any other error refuses the import.
func (r *importRun) importPlatform(ctx context.Context, plat string, a ghrelease.Asset, target string) (*PlatformResult, error) {
	// The name becomes content/<name> on disk and $PKG/content/<name> in the
	// recipe, where the runner would expand a '$'.
	if err := ghrelease.ValidateAssetName(a.Name); err != nil {
		return nil, &refusal{reason: err.Error()}
	}
	if a.Size > maxAssetBytes {
		return nil, &refusal{reason: fmt.Sprintf("asset %s is listed as %d bytes, larger than the %d-byte limit on a package's content", a.Name, a.Size, maxAssetBytes)}
	}
	// The release lists the asset's size, so a body of any other length is
	// truncated or padded; refusing it here names the cause, where the
	// integrity check would report only a digest mismatch.
	data, err := r.opts.Client.Download(ctx, a.URL, a.Size)
	if err != nil {
		return nil, fmt.Errorf("download %s (listed as %d bytes): %w", a.Name, a.Size, err)
	}
	if int64(len(data)) != a.Size {
		return nil, fmt.Errorf("asset %s: downloaded %d bytes, but the release lists it as %d bytes", a.Name, len(data), a.Size)
	}
	sums, err := r.checksumsFor(ctx, a)
	if err != nil {
		return nil, err
	}
	integrity, err := ghrelease.CheckIntegrity(a, data, sums, r.opts.InsecureSkipDigest)
	if err != nil {
		var mismatch *ghrelease.IntegrityError
		if errors.As(err, &mismatch) {
			return nil, fmt.Errorf("asset %s: %w", a.Name, err)
		}
		return nil, &refusal{reason: fmt.Sprintf("asset %s: %v", a.Name, err), err: err}
	}
	recipe, mode, err := r.recipeFor(plat, a.Name, data)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	kept, warnings, notes, err := r.carryAttestations(ctx, a.Name, hex.EncodeToString(sum[:]))
	if err != nil {
		return nil, err
	}
	if r.opts.RequireAttestation && len(kept) == 0 {
		return nil, &refusal{reason: fmt.Sprintf("asset %s has no verified SLSA provenance from github.com/%s/%s, and attestations are required",
			a.Name, r.opts.Owner, r.opts.Repo)}
	}
	yml, err := marshalRecipe(recipe, r.origin)
	if err != nil {
		return nil, err
	}
	staged, err := r.out.stage(target, yml, a.Name, data, mode, kept)
	if err != nil {
		return nil, err
	}
	findings, err := r.opts.Lint(staged)
	if err != nil {
		return nil, fmt.Errorf("lint the generated source for %s: %w", plat, err)
	}
	if len(findings) > 0 {
		return nil, fmt.Errorf("the generated source for %s fails pkg lint:\n  %s", plat, strings.Join(findings, "\n  "))
	}
	return &PlatformResult{
		Platform:     plat,
		Asset:        a.Name,
		Integrity:    integrity,
		Dir:          filepath.Join(r.opts.OutDir, filepath.FromSlash(target)),
		Attestations: len(kept),
		Warnings:     warnings,
		Notes:        notes,
	}, nil
}

// checksumsFor returns the checksums covering a, parsed from the release's
// checksums file for it (a shared list or a per-asset .sha256), downloading
// each checksums file at most once. It returns nil when a has a GitHub digest
// (which takes precedence) or the release has no checksums file for it.
func (r *importRun) checksumsFor(ctx context.Context, a ghrelease.Asset) (map[string]string, error) {
	if a.Digest != "" {
		return nil, nil
	}
	cs, ok := ghrelease.FindChecksums(r.assets, a.Name)
	if !ok {
		return nil, nil
	}
	b, seen := r.checksums[cs.Name]
	if !seen {
		var err error
		b, err = r.opts.Client.Download(ctx, cs.URL, ghrelease.MaxChecksumsSize)
		if err != nil {
			return nil, fmt.Errorf("download checksums file %s: %w", cs.Name, err)
		}
		r.checksums[cs.Name] = b
	}
	sums, err := ghrelease.ChecksumsFor(cs, a.Name, b)
	if err != nil {
		return nil, fmt.Errorf("parse checksums file %s: %w", cs.Name, err)
	}
	return sums, nil
}

// recipeFor classifies the asset and builds its recipe, returning the mode
// its content file is written with: 0o755 for a bare executable, which the
// install action's copy keeps, else 0o644.
func (r *importRun) recipeFor(plat, asset string, data []byte) (recipe *schema.Package, mode fs.FileMode, err error) {
	goos, goarch, _ := strings.Cut(plat, "/")
	format, bare, err := detectKind(data, goos, goarch)
	if err != nil {
		return nil, 0, &refusal{reason: fmt.Sprintf("asset %s %v", asset, err)}
	}
	if bare {
		if len(r.bins) != 1 {
			return nil, 0, &refusal{reason: fmt.Sprintf("asset %s is a single executable, which provides one command, but %d were requested with --bin",
				asset, len(r.bins))}
		}
		return bareRecipe(r.meta, plat, asset, r.bins[0]), 0o755, nil
	}
	strip, members, err := chooseStrip(data, format)
	if err != nil {
		return nil, 0, &refusal{reason: fmt.Sprintf("asset %s: %v", asset, err)}
	}
	locs := make([]binLocation, 0, len(r.bins))
	for _, b := range r.bins {
		p, lerr := locateBin(members, b)
		if lerr != nil {
			return nil, 0, &refusal{reason: fmt.Sprintf("asset %s: %v", asset, lerr)}
		}
		locs = append(locs, binLocation{name: b, path: p})
	}
	return archiveRecipe(r.meta, plat, asset, strip, locs), 0o644, nil
}

// carryAttestations fetches every attestation GitHub holds for the digest of
// the asset named asset and sorts them with checkBundle: the provenance
// bundles to carry, a warning for each provenance bundle dropped, and a note
// for each attestation skipped as not provenance. A bundle checkBundle
// refuses refuses the import. kept is ordered by the sha256 of each bundle's
// bytes, so attestations/<n>.json does not depend on the API's order.
func (r *importRun) carryAttestations(ctx context.Context, asset, assetSHA256 string) (kept [][]byte, warnings, notes []string, err error) {
	bundles, err := r.opts.Client.Attestations(ctx, r.opts.Owner, r.opts.Repo, assetSHA256)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("fetch attestations for asset %s (sha256:%s): %w", asset, assetSHA256, err)
	}
	repoURI := "https://github.com/" + r.opts.Owner + "/" + r.opts.Repo
	for i, b := range bundles {
		outcome, why, cerr := checkBundle(b, r.tm, assetSHA256, repoURI)
		var vf *verifyFailure
		switch {
		case errors.As(cerr, &vf):
			return nil, nil, nil, &ProvenanceError{Asset: asset, Index: i + 1, Total: len(bundles), Reason: vf.reason}
		case cerr != nil:
			return nil, nil, nil, fmt.Errorf("attestation %d of %d for %s (sha256:%s): %w; refusing the import, because an attestation GitHub returned for this asset that cannot be read or does not attest it is a sign of tampering",
				i+1, len(bundles), asset, assetSHA256, cerr)
		}
		switch outcome {
		case bundleKept:
			kept = append(kept, b)
		case bundleDropped:
			warnings = append(warnings, why)
		case bundleSkipped:
			notes = append(notes, why)
		}
	}
	slices.SortFunc(kept, func(a, b []byte) int {
		sa, sb := sha256.Sum256(a), sha256.Sum256(b)
		return bytes.Compare(sa[:], sb[:])
	})
	return kept, warnings, notes, nil
}

package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/mirror"
	"github.com/trevor-vaughan/polypkg/internal/repo"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func newMirrorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mirror",
		Short: "Verify and manage offline repository mirror bundles",
		Long: `Work with the self-contained tarball mirrors produced by
'polypkg repo export-bundle': verify their signature, freshness, and
completeness before serving them at an air-gapped site.`,
		Args: cobra.ArbitraryArgs,
		RunE: requireSubcommand(""),
	}
	cmd.AddCommand(newMirrorVerifyCmd())
	cmd.AddCommand(newMirrorPullCmd())
	return cmd
}

func newMirrorVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify <bundle.tar>",
		Short: "Verify a mirror bundle: manifest signature, freshness, and completeness",
		Long: `Verifies that a mirror bundle is intact and complete: the signed
completeness manifest checks out against the trust root, the manifest is fresh
(or within --accept-expiry-until grace), and every listed blob is present and
byte-identical with no un-listed file smuggled in. Any failure names the
offending file and exits non-zero.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "mirror verify", runMirrorVerify(cmd, args[0], format))
		},
	}
	cmd.Flags().String("trust-root", "", "Pinned trust_root.pub to verify the bundle's signed manifest against (default: the trust root carried in the bundle)")
	cmd.Flags().String("accept-expiry-until", "", "RFC3339 deadline: accept an expired bundle manifest up to this time (freshness grace for a frozen mirror)")
	return cmd
}

func runMirrorVerify(cmd *cobra.Command, bundlePath string, format Format) error {
	trustRoot, _ := cmd.Flags().GetString("trust-root")
	acceptUntil, _ := cmd.Flags().GetString("accept-expiry-until")
	res, err := mirror.VerifyBundle(bundlePath, mirror.VerifyOptions{TrustRootPath: trustRoot, AcceptExpiryUntil: acceptUntil})
	if err != nil {
		return err
	}
	if res.Graced {
		fmt.Fprintf(cmd.ErrOrStderr(), "SECURITY: bundle manifest expired — accepted under grace until %s (freshness relaxed; completeness still enforced)\n", acceptUntil)
	}
	EmitResult(cmd, format, "mirror verify",
		map[string]any{"source": res.Source, "serial": res.Serial, "expires": res.Expires, "entries": res.EntriesChecked, "graced": res.Graced},
		func(w *bytes.Buffer, d map[string]any) {
			fmt.Fprintf(w, "OK: %v (serial %v), %v files verified\n", d["source"], d["serial"], d["entries"])
		})
	return nil
}

func newMirrorPullCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pull",
		Short: "Fetch upstream packages, re-publish them locally, and export a mirror bundle",
		Long: `Fetches selected packages from one or more upstream polypkg sources,
verifies them inbound against the pinned trust root(s), re-publishes them
verbatim into a local repository signed by your key (carried provenance is
preserved and still checks against the original builder keys), and optionally
exports a signed, self-contained mirror bundle for an air-gapped site.

Single source: pass --source-url and --trust-root. Multiple sources: pass
--sources-file (a YAML list of {url, trust_root, ...}); the two are mutually
exclusive.

Selection (single-source): with no --package/--from-file the latest version of
every upstream package is pulled. A 'name' selector pulls the latest of that
package; 'name@version' pulls one version. --package is repeatable and unions
with --from-file. (Multi-source selection is per-entry in the sources file.)

--fresh produces a clone with NO upstream provenance: upstream attestations and
upstream builder keys/roots are dropped and the repo re-anchors on your key
alone. A downstream 'require' policy then correctly fails closed on the missing
provenance.

Every pull writes a polypkg-repo.yaml into --output-dir. That is the manifest
'polypkg repo revoke', 'repo status', 'repo build', 'repo key show', and
'repo export-bundle' read, so you can manage the mirror in place — for example
'polypkg repo revoke --remove-builder-key <id>' to prune the mirror's revocation
list. It points at the mirror's own published pool, so a 'repo build' against it
is a no-op; refresh content by re-running 'mirror pull'.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "mirror pull", runMirrorPull(cmd, format))
		},
	}
	// Upstream (single source)
	cmd.Flags().String("source-url", "", "Upstream source URL or local path (single-source mode)")
	cmd.Flags().String("trust-root", "", "Path to the upstream source's trust_root.pub anchor (required with --source-url)")
	cmd.Flags().String("source-type", "", "Upstream trust type (default: polypkg-native)")
	cmd.Flags().String("source-name", "", "Logical name for the upstream source (verifier context)")
	cmd.Flags().String("accept-expiry-until", "", "RFC3339 deadline: accept expired upstream metadata up to this time (freshness grace)")
	cmd.Flags().StringArray("package", nil, "Select a package to pull: name or name@version (repeatable, single-source mode)")
	cmd.Flags().String("from-file", "", "Read additional selectors, one per line (single-source mode)")
	// Upstream (multi source)
	cmd.Flags().String("sources-file", "", "YAML file listing multiple upstream sources (mutually exclusive with --source-url)")
	// Local re-publish
	cmd.Flags().String("repo-source", "", "Source identity stamped into the local signed index/trust docs (required)")
	cmd.Flags().String("output-dir", "", "Directory to publish the local repository into, including the polypkg-repo.yaml the repo subcommands manage it through (required)")
	cmd.Flags().String("key", "", "Path to the local signing key file (required)")
	cmd.Flags().String("key-kdf", "scrypt", "KDF recorded in the generated manifest's key block (scrypt or pbkdf2)")
	cmd.Flags().String("key-dir", "", "Directory holding the build cache; must be outside --output-dir (default: the directory containing --key)")
	cmd.Flags().String("key-password-file", "", "File containing the signing-key password")
	cmd.Flags().Duration("valid-for", repo.DefaultValidFor, "Validity window stamped into the local signed index and trust document")
	cmd.Flags().String("stage-dir", "", "Directory for staging fetched artifacts (default: a temp dir removed on success)")
	// Export
	cmd.Flags().StringP("bundle", "o", "", "Also export a signed mirror bundle tarball to this path")
	// Strip
	cmd.Flags().Bool("fresh", false, "Drop upstream attestations and builder keys/roots; re-anchor on the local key alone")

	_ = cmd.MarkFlagRequired("repo-source")
	_ = cmd.MarkFlagRequired("output-dir")
	_ = cmd.MarkFlagRequired("key")
	return cmd
}

// pullInputs holds the validated CLI inputs shared by the single- and
// multi-source pull paths.
type pullInputs struct {
	sources   []mirror.SourceSpec // one per upstream
	repoSrc   string
	outputDir string
	keyPath   string
	keyKDF    string
	keyDir    string
	password  string
	validFor  time.Duration
	stageDir  string // resolved staging root
	bundle    string // "" ⇒ no export
	fresh     bool
}

// resolveMirrorPullInputs validates the flag combination and resolves the upstream
// source list (single --source-url or a --sources-file).
func resolveMirrorPullInputs(cmd *cobra.Command) (pullInputs, error) {
	sourceURL, _ := cmd.Flags().GetString("source-url")
	sourcesFile, _ := cmd.Flags().GetString("sources-file")
	switch {
	case sourceURL == "" && sourcesFile == "":
		return pullInputs{}, &CLIError{Msg: "no upstream source: pass --source-url or --sources-file", Hint: "single source uses flags; many sources use a --sources-file"}
	case sourceURL != "" && sourcesFile != "":
		return pullInputs{}, &CLIError{Msg: "--source-url and --sources-file are mutually exclusive", Hint: "use flags for one source, a sources file for many"}
	}

	if sourcesFile != "" {
		for _, f := range []string{"trust-root", "source-type", "source-name", "accept-expiry-until", "package", "from-file"} {
			if cmd.Flags().Changed(f) {
				return pullInputs{}, &CLIError{
					Msg:  "--" + f + " cannot be combined with --sources-file",
					Hint: "with --sources-file, set trust_root/source_type/source_name/accept_expiry_until/packages per entry inside the file",
				}
			}
		}
	}

	var sources []mirror.SourceSpec
	if sourcesFile != "" {
		specs, err := mirror.ParseSourcesFile(sourcesFile)
		if err != nil {
			return pullInputs{}, &CLIError{Msg: err.Error(), Hint: "each entry needs url and trust_root; see `polypkg mirror pull --help`"}
		}
		sources = specs
	} else {
		trustRoot, _ := cmd.Flags().GetString("trust-root")
		if trustRoot == "" {
			return pullInputs{}, &CLIError{Msg: "--trust-root is required with --source-url", Hint: "pin the upstream source's trust_root.pub"}
		}
		sType, _ := cmd.Flags().GetString("source-type")
		sName, _ := cmd.Flags().GetString("source-name")
		acceptUntil, _ := cmd.Flags().GetString("accept-expiry-until")
		selectors, _ := cmd.Flags().GetStringArray("package")
		if ff, _ := cmd.Flags().GetString("from-file"); ff != "" {
			more, ferr := readSelectorFile(ff)
			if ferr != nil {
				return pullInputs{}, ferr
			}
			selectors = append(selectors, more...)
		}
		sources = []mirror.SourceSpec{{
			URL: sourceURL, TrustRoot: trustRoot, SourceType: sType,
			SourceName: sName, AcceptExpiryUntil: acceptUntil, Packages: selectors,
		}}
	}

	in := pullInputs{sources: sources}
	in.repoSrc, _ = cmd.Flags().GetString("repo-source")
	// --repo-source is stamped into the generated manifest and interpolated into
	// the build-cache path under --key-dir. Reject a path- or URL-shaped value
	// here, before any upstream is fetched, so the failure names the flag
	// instead of surfacing as a mangled open() error deep in the build.
	if err := schema.ValidateSourceName(in.repoSrc); err != nil {
		return pullInputs{}, &CLIError{
			Msg:  fmt.Sprintf("--repo-source %q is not a valid slug", in.repoSrc),
			Hint: "--repo-source is the local source NAME stamped into your signed index (e.g. mymirror), not a URL; it must match " + schema.SourceNamePattern,
			Err:  err,
		}
	}
	// Absolutize --output-dir and --key against the CALLER's cwd. They are
	// interpolated into a manifest that lives in the staging root, and `repo
	// build` resolves a relative manifest path against the manifest's own
	// directory — so `--output-dir ./mirror-repo` (the shape docs/publishing.md
	// shows) used to publish into the temp staging dir and be deleted with it,
	// and `--key ./local-repo.key` was looked for there too.
	outputDir, _ := cmd.Flags().GetString("output-dir")
	keyPath, _ := cmd.Flags().GetString("key")
	absOut, err := filepath.Abs(outputDir)
	if err != nil {
		return pullInputs{}, fmt.Errorf("resolve --output-dir: %w", err)
	}
	absKey, err := filepath.Abs(keyPath)
	if err != nil {
		return pullInputs{}, fmt.Errorf("resolve --key: %w", err)
	}
	in.outputDir = absOut
	in.keyPath = absKey
	in.keyKDF, _ = cmd.Flags().GetString("key-kdf")
	in.keyDir, _ = cmd.Flags().GetString("key-dir")
	if in.keyDir == "" {
		in.keyDir = filepath.Dir(in.keyPath)
	} else if abs, aerr := filepath.Abs(in.keyDir); aerr == nil {
		in.keyDir = abs
	}
	validFor, err := resolveValidFor(cmd)
	if err != nil {
		return pullInputs{}, err
	}
	in.validFor = validFor
	in.stageDir, _ = cmd.Flags().GetString("stage-dir")
	in.bundle, _ = cmd.Flags().GetString("bundle")
	in.fresh, _ = cmd.Flags().GetBool("fresh")

	pw, err := repoKeyPassword(cmd)
	if err != nil {
		return pullInputs{}, err
	}
	in.password = pw
	return in, nil
}

func runMirrorPull(cmd *cobra.Command, format Format) error {
	in, err := resolveMirrorPullInputs(cmd)
	if err != nil {
		return err
	}

	// Resolve the staging root: an explicit --stage-dir persists (for debugging);
	// otherwise a temp dir removed on every return path (success or error).
	stageRoot := in.stageDir
	if stageRoot == "" {
		stageRoot, err = os.MkdirTemp("", "polypkg-mirror-pull-*")
		if err != nil {
			return fmt.Errorf("create staging dir: %w", err)
		}
		defer func() { _ = os.RemoveAll(stageRoot) }()
	}

	// A --fresh re-anchor must land in a clean target. This is defense in depth,
	// not a patch over one specific leak: "carries no upstream provenance" is
	// today the joint product of four mechanisms — stripFresh clearing
	// TrustBundlePath and AttDir, build.go's bundleOrphaned path pruning a prior
	// trust-bundle.json, the throwaway build cache set up below, and Build
	// flooring the serial at publishedSerial(outputDir). Each has changed on its
	// own schedule, so pinning the guarantee to any one of them ages badly.
	// Demanding an empty directory makes it a property you can observe instead
	// of one you have to re-derive.
	//
	// It also covers the gap none of those four close: Build republishes the
	// pool but never prunes it, so a dirty target keeps serving the attestation
	// blobs a previous non-fresh run wrote (under this repo's own key) even
	// though the re-anchored index references none of them.
	//
	// Checked before any fetch so a doomed run wastes no network work.
	if in.fresh {
		if err := ensureCleanOutputDir(in.outputDir); err != nil {
			return err
		}
	}

	// Fetch + verify + stage each upstream source into its own StageDir subdir so
	// per-source trust bundles do not clobber one another.
	results := make([]*mirror.PullResult, 0, len(in.sources))
	for i := range in.sources {
		s := &in.sources[i]
		res, perr := mirror.Pull(context.Background(), mirror.PullOptions{
			URL: s.URL, TrustRoot: s.TrustRoot, SourceType: s.SourceType,
			SourceName: s.SourceName, AcceptExpiryUntil: s.AcceptExpiryUntil,
			Selectors: s.Packages, StageDir: filepath.Join(stageRoot, fmt.Sprintf("src-%d", i)),
		})
		if perr != nil {
			return perr
		}
		for _, note := range res.Graced {
			fmt.Fprintf(cmd.ErrOrStderr(), "SECURITY: upstream %s accepted under freshness grace: %s\n", s.URL, note)
		}
		results = append(results, res)
	}

	if in.fresh {
		if err := stripFresh(stageRoot, results); err != nil {
			return err
		}
	}

	// Generate the prebuilt manifest and ingest it under the local key.
	manifestPath := filepath.Join(stageRoot, "polypkg-repo.yaml")
	if err := mirror.WritePrebuiltManifestMulti(manifestPath, mirror.PrebuiltManifestParams{
		Source: in.repoSrc, Output: in.outputDir, KeyPath: in.keyPath, KeyKDF: in.keyKDF,
	}, results); err != nil {
		return err
	}
	// Under --fresh, ingest against a clean build cache so no content-hash cache
	// hit re-surfaces stored upstream attestation refs. The signing key loads from
	// the manifest's absolute key.path, not this dir, so a distinct cache dir does
	// not affect key loading (and stays outside --output-dir for guardKeyNotInOutput).
	buildCacheDir := in.keyDir
	if in.fresh {
		buildCacheDir = filepath.Join(stageRoot, "fresh-cache")
	}
	if err := os.MkdirAll(buildCacheDir, 0o755); err != nil { //nolint:gosec // G301: operator-local build cache
		return fmt.Errorf("create build cache: %w", err)
	}
	b, err := repo.NewBuilder(manifestPath, buildCacheDir, in.password)
	if err != nil {
		return mapPublishError(err)
	}
	if _, err := b.Build(repo.BuildOptions{ValidFor: in.validFor}); err != nil {
		return mapPublishError(err)
	}

	// Re-emit the union of every upstream's (and any local) revocations as a
	// mirror-signed revocations.json BEFORE exporting a bundle, so downstream
	// clients of this re-publishing mirror enforce them (retroactive coverage).
	var revAtts, revKeys []string
	for _, r := range results {
		revAtts = append(revAtts, r.RevokedAttestations...)
		revKeys = append(revKeys, r.RevokedBuilderKeys...)
	}
	if _, _, err := b.PropagateRevocations(revAtts, revKeys, in.validFor); err != nil {
		return mapPublishError(err)
	}

	// Leave a manifest the operator can manage the mirror with. Without it the
	// documented revocation-prune procedure (docs/publishing.md) is unreachable:
	// the build manifest lives in the staging root, which is a temp dir this
	// function deletes. Written after PropagateRevocations so the trust bundle
	// and revocation list it references are already published.
	if err := mirror.WriteManagementManifest(mirror.PrebuiltManifestParams{
		Source: in.repoSrc, Output: in.outputDir, KeyPath: in.keyPath, KeyKDF: in.keyKDF,
	}); err != nil {
		return err
	}

	// Optionally export a signed bundle of everything just re-published.
	var bundlePath string
	if in.bundle != "" {
		exp, eerr := b.ExportBundle(nil, in.bundle)
		if eerr != nil {
			return mapPublishError(eerr)
		}
		bundlePath = exp.BundlePath
	}

	pkgCount := 0
	for _, r := range results {
		pkgCount += len(r.Packages)
	}
	mirrorManifest := filepath.Join(in.outputDir, mirror.ManagementManifestName)
	EmitResult(cmd, format, "mirror pull",
		map[string]any{"packages": pkgCount, "output": in.outputDir, "manifest": mirrorManifest, "bundle": bundlePath, "fresh": in.fresh},
		func(w *bytes.Buffer, d map[string]any) {
			fmt.Fprintf(w, "Pulled %v package(s) into %s\n", d["packages"], in.outputDir)
			fmt.Fprintf(w, "Manage it with: polypkg repo <command> --manifest %s\n", d["manifest"])
			if bundlePath != "" {
				fmt.Fprintf(w, "Exported mirror bundle to %s\n", bundlePath)
				fmt.Fprintf(w, "Verify with: polypkg mirror verify %s\n", bundlePath)
			}
		})
	return nil
}

// ensureCleanOutputDir enforces that a --fresh re-publish targets an empty (or
// absent) output directory. A fresh clone must carry NO upstream provenance,
// and that is a joint property of several independently-evolving mechanisms
// rather than a guarantee any one of them makes (see the rationale at the call
// site in runMirrorPull). This guard asserts the property on the directory
// directly instead of trusting those mechanisms to keep agreeing.
//
// The concrete gap it closes: `repo build` republishes the pool but never
// prunes it, so attestation blobs a previous non-fresh run wrote stay on disk
// — and stay served — even after the re-anchored index stops referencing them.
func ensureCleanOutputDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect --output-dir: %w", err)
	}
	if len(entries) > 0 {
		return &CLIError{
			Msg:  "--fresh requires an empty --output-dir",
			Hint: "point --output-dir at a new/empty directory so no prior upstream provenance (e.g. a published trust-bundle.json) survives the re-anchor",
		}
	}
	return nil
}

// stripFresh implements --fresh: drop all upstream provenance so the re-publish
// re-anchors on the local key alone. It repoints every pulled package's
// attestations at one shared EMPTY dir (the repo-v1 schema requires a non-empty
// attestations path, and discoverCarriedDir tolerates an empty dir → zero
// carried attestations) and drops every source's trust-bundle reference (so
// ingest carries no upstream builder keys or sigstore roots). Artifact bytes are
// untouched — a fresh clone still ships the verbatim upstream artifacts, vouched
// for by the local index signature alone.
func stripFresh(stageRoot string, results []*mirror.PullResult) error {
	emptyAtts := filepath.Join(stageRoot, "fresh-empty-atts")
	if err := os.MkdirAll(emptyAtts, 0o755); err != nil { //nolint:gosec // G301: operator-local staging dir
		return fmt.Errorf("create fresh empty attestations dir: %w", err)
	}
	for _, res := range results {
		res.TrustBundlePath = ""
		for i := range res.Packages {
			res.Packages[i].AttDir = emptyAtts
		}
	}
	return nil
}

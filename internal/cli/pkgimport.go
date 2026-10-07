package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/spf13/cobra"

	"github.com/trevor-vaughan/polypkg/internal/ghrelease"
	"github.com/trevor-vaughan/polypkg/internal/importer"
	"github.com/trevor-vaughan/polypkg/internal/platform"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/source"
)

// defaultGitHubAPIURL is GitHub.com's REST API root.
const defaultGitHubAPIURL = "https://api.github.com"

// maxTrustedRootBytes caps a --trusted-root file. The Sigstore public-good
// trusted_root.json is under 10 KiB.
const maxTrustedRootBytes = 1 << 20

type pkgImportFlags struct {
	name, version, apiURL, trustedRoot     string
	bins, platforms                        []string
	requireAttestation, insecureSkipDigest bool
}

// importedPlatform and skippedAsset are the JSON shapes of one imported
// platform and one skipped asset.
type importedPlatform struct {
	Platform     string   `json:"platform"`
	Asset        string   `json:"asset"`
	Integrity    string   `json:"integrity"`
	Attestations int      `json:"attestations"`
	Dir          string   `json:"dir"`
	Warnings     []string `json:"warnings"`
	Notes        []string `json:"notes"`
}

type skippedAsset struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

func newPkgImportCmd() *cobra.Command {
	var f pkgImportFlags
	cmd := &cobra.Command{
		Use:   "import github:OWNER/REPO[@TAG] <out-dir>",
		Short: "Generate per-platform package sources from a GitHub release",
		Long: `Downloads a GitHub release's per-platform assets and writes one package
source per platform to <out-dir>/<name>/<version>/<os>-<arch>/, each shipping
the upstream asset byte for byte. Without @TAG the latest release that is not
a prerelease is used.

Each asset's sha256 must match the digest GitHub reports for it, or else its
entry in the release's checksums file; --insecure-skip-digest imports an asset
that has neither, marked UNVERIFIED. GitHub artifact attestations for an asset
are verified offline against the Sigstore public-good trusted root (or
--trusted-root) and carried in the source's attestations/. The root is written
to <out-dir>/sigstore-trusted-root.json for the repository's sigstore_roots.
A failed import leaves <out-dir> as it was.

GITHUB_TOKEN, else GH_TOKEN, raises GitHub's rate limit. It is sent to the
--api-url host only, never to asset or attestation downloads.`,
		Args: needsArgs(2, 2, "github:OWNER/REPO[@TAG] <out-dir>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "pkg import", runPkgImport(cmd, args[0], args[1], &f, format))
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.name, "name", "", "Package name (default: the repository name, lower-cased)")
	fl.StringVar(&f.version, "version", "", "Package version (default: derived from the release tag)")
	fl.StringArrayVar(&f.bins, "bin", nil, "Executable to expose on PATH (repeatable; default: the package name)")
	fl.StringArrayVar(&f.platforms, "platform", nil, "Force a platform's asset: OS/ARCH=GLOB, GLOB matched against asset file names (repeatable)")
	fl.BoolVar(&f.requireAttestation, "require-attestation", false, "Refuse any platform whose asset has no verified attestation")
	fl.BoolVar(&f.insecureSkipDigest, "insecure-skip-digest", false, "Import an asset with neither a GitHub digest nor a checksums entry, marked UNVERIFIED")
	fl.StringVar(&f.apiURL, "api-url", defaultGitHubAPIURL, "GitHub REST API root (GitHub Enterprise Server: https://HOST/api/v3)")
	fl.StringVar(&f.trustedRoot, "trusted-root", "", "Verify attestations against this sigstore trusted_root.json instead of fetching the public-good root")
	return cmd
}

func runPkgImport(cmd *cobra.Command, ref, outDir string, f *pkgImportFlags, format Format) error {
	owner, repoName, tag, err := parseGitHubRef(ref)
	var rn *ghrelease.RepositoryNameError
	if errors.As(err, &rn) {
		return importError(err, ref, false, f.apiURL)
	}
	if err != nil {
		return &CLIError{
			Msg:  err.Error(),
			Hint: "name the release as github:OWNER/REPO or github:OWNER/REPO@TAG, e.g. github:cli/cli@v2.62.0",
			Err:  err,
		}
	}
	if f.name != "" {
		if err := schema.ValidatePackageName(f.name); err != nil {
			return &CLIError{
				Msg:  fmt.Sprintf("--name %q is not a valid package name", f.name),
				Hint: "a package name must match " + schema.PackageNamePattern,
				Err:  err,
			}
		}
	}
	if err := importer.CheckBins(f.bins); err != nil {
		return importError(err, ref, false, f.apiURL)
	}
	if f.version != "" {
		if err := importer.CheckVersion(f.version); err != nil {
			return importError(err, ref, false, f.apiURL)
		}
	}
	overrides, err := parsePlatformOverrides(f.platforms)
	if err != nil {
		return &CLIError{
			Msg:  err.Error(),
			Hint: "use --platform OS/ARCH=GLOB, e.g. --platform linux/amd64='*x86_64*linux-musl.tar.gz'",
			Err:  err,
		}
	}
	token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("GH_TOKEN"))
	}
	if err := ghrelease.CheckAPIURL(f.apiURL, token != ""); err != nil {
		return importError(err, ref, token != "", f.apiURL)
	}
	var trustedRoot func(context.Context) ([]byte, error)
	if f.trustedRoot != "" {
		b, err := readTrustedRoot(f.trustedRoot)
		if err != nil {
			return err
		}
		trustedRoot = func(context.Context) ([]byte, error) { return b, nil }
	} else {
		tr, err := importer.DefaultTrustedRoot()
		if err != nil {
			return &CLIError{
				Msg:  "could not locate the cache directory for the Sigstore trusted root",
				Hint: "set XDG_CACHE_HOME or HOME, or pass --trusted-root FILE",
				Err:  err,
			}
		}
		trustedRoot = tr
	}

	res, err := importer.Run(cmd.Context(), importer.Options{
		Owner:              owner,
		Repo:               repoName,
		Tag:                tag,
		OutDir:             outDir,
		Name:               f.name,
		Version:            f.version,
		Bins:               f.bins,
		Overrides:          overrides,
		RequireAttestation: f.requireAttestation,
		InsecureSkipDigest: f.insecureSkipDigest,
		Client:             ghrelease.New(f.apiURL, token, source.NewHTTPClient()),
		TrustedRoot:        trustedRoot,
		Lint:               importer.PkgLint,
	})
	if err != nil {
		return importError(err, ref, token != "", f.apiURL)
	}
	emitImportResult(cmd, format, ref, res)
	return nil
}

// parseGitHubRef splits github:OWNER/REPO[@TAG]. OWNER and REPO must follow
// GitHub's naming rules and TAG may hold no whitespace, control character, or
// character git forbids in a ref name, so none of them can carry a meaning of
// its own into a request path.
func parseGitHubRef(ref string) (owner, repo, tag string, err error) {
	rest, ok := strings.CutPrefix(ref, "github:")
	if !ok {
		return "", "", "", fmt.Errorf("%q is not a GitHub release reference: it must start with github: as in github:OWNER/REPO", ref)
	}
	slug, tag, hasTag := strings.Cut(rest, "@")
	if hasTag && !validGitTag(tag) {
		return "", "", "", fmt.Errorf("%q names an invalid release tag %q", ref, tag)
	}
	owner, repo, ok = strings.Cut(slug, "/")
	if !ok {
		return "", "", "", fmt.Errorf("%q does not name a GitHub repository as OWNER/REPO", ref)
	}
	if err := ghrelease.ValidateRepository(owner, repo); err != nil {
		return "", "", "", fmt.Errorf("%q does not name a GitHub repository as OWNER/REPO: %w", ref, err)
	}
	return owner, repo, tag, nil
}

// validGitTag reports whether tag is usable as a release tag: non-empty, at
// most 255 bytes, free of whitespace, control characters, and the characters
// git forbids in a ref name, with no "..", and neither starting with "-" or
// "/" nor ending with "/".
func validGitTag(tag string) bool {
	if tag == "" || len(tag) > 255 || strings.Contains(tag, "..") ||
		strings.HasPrefix(tag, "-") || strings.HasPrefix(tag, "/") || strings.HasSuffix(tag, "/") {
		return false
	}
	for _, r := range tag {
		if r <= ' ' || r == 0x7f || strings.ContainsRune(`~^:?*[\`, r) {
			return false
		}
	}
	return true
}

// parsePlatformOverrides turns repeated OS/ARCH=GLOB values into the
// importer's override map. The platform must be one polypkg can publish and
// the glob must compile.
func parsePlatformOverrides(specs []string) (map[string]string, error) {
	out := make(map[string]string, len(specs))
	for _, s := range specs {
		plat, glob, ok := strings.Cut(s, "=")
		if !ok || glob == "" {
			return nil, fmt.Errorf("--platform %q is not OS/ARCH=GLOB", s)
		}
		if err := platform.ValidateProducer(plat); err != nil {
			return nil, fmt.Errorf("--platform %q: %w", s, err)
		}
		if _, err := path.Match(glob, ""); err != nil {
			return nil, fmt.Errorf("--platform %q: %q is not a valid glob", s, glob)
		}
		if _, dup := out[plat]; dup {
			return nil, fmt.Errorf("--platform names %s more than once", plat)
		}
		out[plat] = glob
	}
	return out, nil
}

// readTrustedRoot reads and parses a --trusted-root file, so a wrong file
// fails before any request is made.
func readTrustedRoot(p string) ([]byte, error) {
	fh, err := os.Open(p) //nolint:gosec // G304: the operator names their own trust material
	if err != nil {
		return nil, &CLIError{Msg: fmt.Sprintf("cannot read --trusted-root %q", p), Err: err}
	}
	defer func() { _ = fh.Close() }()
	b, err := io.ReadAll(io.LimitReader(fh, maxTrustedRootBytes+1))
	if err != nil {
		return nil, &CLIError{Msg: fmt.Sprintf("cannot read --trusted-root %q", p), Err: err}
	}
	if len(b) > maxTrustedRootBytes {
		return nil, &CLIError{Msg: fmt.Sprintf("--trusted-root %q is larger than %d bytes", p, maxTrustedRootBytes)}
	}
	if _, err := root.NewTrustedRootFromJSON(b); err != nil {
		return nil, &CLIError{
			Msg:  fmt.Sprintf("--trusted-root %q is not a sigstore trusted_root.json", p),
			Hint: "pass a trusted_root.json as sigstore's TUF repository distributes it",
			Err:  err,
		}
	}
	return b, nil
}

// emitImportResult renders the import: a per-platform table, warnings, the
// skipped assets, and the commands that publish the result.
func emitImportResult(cmd *cobra.Command, format Format, ref string, res *importer.Result) {
	platforms := make([]importedPlatform, 0, len(res.Platforms))
	dirs := make([]string, 0, len(res.Platforms))
	for _, p := range res.Platforms {
		platforms = append(platforms, importedPlatform{
			Platform: p.Platform, Asset: p.Asset, Integrity: p.Integrity,
			Attestations: p.Attestations, Dir: p.Dir,
			Warnings: nonNil(p.Warnings), Notes: nonNil(p.Notes),
		})
		dirs = append(dirs, shellArg(p.Dir))
	}
	skipped := make([]skippedAsset, 0, len(res.Skipped))
	for _, s := range res.Skipped {
		skipped = append(skipped, skippedAsset{Name: s.Name, Reason: s.Reason})
	}
	rootPath := res.TrustedRootPath
	if abs, err := filepath.Abs(rootPath); err == nil {
		rootPath = abs
	}
	next := []string{"polypkg repo add " + strings.Join(dirs, " "), "polypkg repo build"}
	data := map[string]any{
		"release":      ref,
		"name":         res.Name,
		"version":      res.Version,
		"trusted_root": rootPath,
		"platforms":    platforms,
		"skipped":      skipped,
		"next":         next,
	}
	EmitResult(cmd, format, "pkg import", data, func(w *bytes.Buffer, _ map[string]any) {
		fmt.Fprintf(w, "Imported %s %s from %s\n\n", res.Name, res.Version, ref)
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "PLATFORM\tASSET\tINTEGRITY\tATTESTATIONS\tDIRECTORY")
		for _, p := range platforms {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", p.Platform, p.Asset, p.Integrity, p.Attestations, p.Dir)
		}
		_ = tw.Flush()

		warnings := make([]string, 0, len(platforms))
		for _, p := range platforms {
			if p.Integrity == ghrelease.IntegrityUnverified {
				warnings = append(warnings, fmt.Sprintf(
					"%s: %s has no published digest; imported unverified because of --insecure-skip-digest", p.Platform, p.Asset))
			}
			for _, msg := range p.Warnings {
				warnings = append(warnings, p.Platform+": "+msg)
			}
		}
		if len(warnings) > 0 {
			fmt.Fprintln(w)
			for _, msg := range warnings {
				fmt.Fprintln(w, "warning: "+msg)
			}
		}
		var notes []string
		for _, p := range platforms {
			for _, msg := range p.Notes {
				notes = append(notes, p.Platform+": "+msg)
			}
		}
		if len(notes) > 0 {
			fmt.Fprintln(w)
			for _, msg := range notes {
				fmt.Fprintln(w, "note: "+msg)
			}
		}
		if len(skipped) > 0 {
			// Both strings come from the release, which its author controls.
			fmt.Fprintf(w, "\nSkipped %d release asset(s):\n", len(skipped))
			for _, s := range skipped {
				fmt.Fprintf(w, "  %q: %q\n", s.Name, s.Reason)
			}
		}
		fmt.Fprintf(w, "\nNext:\n  %s\n  # add once to ./polypkg-repo.yaml (relative to that file):  sigstore_roots: [%q]\n  %s\n",
			next[0], manifestRelative(rootPath), next[1])
	})
}

// manifestRelative returns abs relative to the current directory, where the
// printed next commands find polypkg-repo.yaml and against which that
// manifest's sigstore_roots resolve; abs itself when no relative path exists.
func manifestRelative(abs string) string {
	cwd, err := os.Getwd()
	if err != nil {
		return abs
	}
	rel, err := filepath.Rel(cwd, abs)
	if err != nil {
		return abs
	}
	return rel
}

// nonNil returns s, or an empty slice for nil, so JSON renders [] not null.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// shellArg quotes s for a POSIX shell when it holds anything beyond the
// characters that never need quoting, so a printed command can be pasted
// as-is.
func shellArg(s string) string {
	const safe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@%+=:,./_-"
	if s != "" && strings.Trim(s, safe) == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// importError turns the importer's typed failures into user-facing errors
// that name the next step. Anything else is returned as is. apiURL is the
// --api-url the import used.
func importError(err error, ref string, haveToken bool, apiURL string) error {
	var rl *ghrelease.RateLimitError
	var amb *ghrelease.AmbiguityError
	var ie *ghrelease.IntegrityError
	var pe *importer.ProvenanceError
	var te *importer.TargetExistsError
	var be *importer.BinError
	var ae *ghrelease.APIURLError
	var ne *importer.NameError
	var ve *importer.VersionError
	var np *importer.NoPlatformError
	var rn *ghrelease.RepositoryNameError
	lookup, missing := missingLookup(err, apiURL)
	switch {
	case errors.As(err, &rl):
		hint := "set GITHUB_TOKEN (or GH_TOKEN) to a GitHub token to raise the limit, then re-run"
		if haveToken {
			hint = "the token's rate limit is used up; wait for it to reset, then re-run"
		}
		return &CLIError{Msg: "GitHub refused the request: API rate limit exceeded", Hint: hint, Err: err}
	case missing:
		return &CLIError{
			Msg:  "GitHub has no " + lookup + " for " + ref,
			Hint: "check OWNER/REPO and the tag; without @TAG the latest release that is not a prerelease is used, so name a prerelease with @TAG",
			Err:  err,
		}
	case errors.As(err, &amb):
		return &CLIError{
			Msg: fmt.Sprintf("more than one release asset matches %s: %s", amb.Platform, strings.Join(amb.Candidates, ", ")),
			Hint: fmt.Sprintf("choose one with --platform %s=GLOB, a glob matched against the asset file name, e.g. --platform %s=%s",
				amb.Platform, amb.Platform, shellArg(amb.Candidates[0])),
			Err: err,
		}
	case errors.As(err, &ie):
		return &CLIError{
			Msg:  "import refused: " + ie.Error() + "; nothing was written",
			Hint: "the downloaded bytes differ from the digest the release publishes, which means corruption or tampering in transit, or a replaced asset; re-run, and report it to the project if it persists",
			Err:  err,
		}
	case errors.As(err, &pe):
		return &CLIError{
			Msg: fmt.Sprintf("import refused: provenance attestation %d of %d for %s does not verify against the Sigstore trusted root",
				pe.Index, pe.Total, pe.Asset),
			Hint: "this can be tampering, or a Sigstore key rotation the trusted root has not caught up with: re-run later, and report it to the project if it persists. " +
				"A bundle from GitHub Enterprise Server or a private repository is signed outside Sigstore's public-good instance, and polypkg cannot import it",
			Err: err,
		}
	case errors.As(err, &ae) && ae.Plaintext:
		return &CLIError{
			Msg:  "refusing to send GITHUB_TOKEN/GH_TOKEN over plain http to " + ae.Host,
			Hint: "use an https --api-url, or unset GITHUB_TOKEN and GH_TOKEN",
			Err:  err,
		}
	case errors.As(err, &ae):
		return &CLIError{
			Msg:  fmt.Sprintf("--api-url %q is not an http(s) API root URL", ae.URL),
			Hint: "pass the REST API root, e.g. https://api.github.com or https://ghes.example.com/api/v3",
			Err:  err,
		}
	case errors.As(err, &rn):
		return &CLIError{
			Msg: rn.Error(),
			Hint: "name the release as github:OWNER/REPO[@TAG]: an owner is letters, digits, '-' and '_', not starting with '-'; " +
				"a repository name is letters, digits, '.', '-' and '_', e.g. github:cli/cli",
			Err: err,
		}
	case errors.As(err, &ne):
		return &CLIError{
			Msg:  ne.Error(),
			Hint: "choose the package name with --name; a package name is letters, digits, '_' and '-'",
			Err:  err,
		}
	case errors.As(err, &ve) && ve.FromTag:
		return &CLIError{
			Msg:  ve.Error(),
			Hint: "pass the version the release stands for with --version, e.g. --version 1.2.0",
			Err:  err,
		}
	case errors.As(err, &ve):
		return &CLIError{
			Msg:  ve.Error(),
			Hint: "pass a semantic version to --version, e.g. --version 1.2.0",
			Err:  err,
		}
	case errors.As(err, &be):
		return &CLIError{
			Msg:  be.Error(),
			Hint: "name an executable inside the release asset by its file name, e.g. --bin rg; a command name is letters, digits, '_' and '-', each given once",
			Err:  err,
		}
	case errors.As(err, &te):
		return &CLIError{
			Msg:  te.Dir + " already exists; refusing to overwrite it",
			Hint: "choose another <out-dir>, or remove or rename the existing <os>-<arch> directory, then re-run",
			Err:  err,
		}
	case errors.Is(err, importer.ErrFetchTrustedRoot):
		return &CLIError{
			Msg:  "could not fetch the Sigstore trusted root",
			Hint: "check this host can reach Sigstore's TUF repository, or pass --trusted-root FILE with a trusted_root.json obtained another way (for example on an air-gapped host)",
			Err:  err,
		}
	case errors.Is(err, ghrelease.ErrUnverifiable):
		return &CLIError{
			Msg: err.Error(),
			Hint: "nothing the release publishes vouches for these bytes beyond the download itself; if you accept that, re-run with --insecure-skip-digest, " +
				"which imports such an asset marked UNVERIFIED",
			Err: err,
		}
	case errors.As(err, &np):
		return &CLIError{
			Msg:  np.Error(),
			Hint: "each platform's reason is listed; choose another asset with --platform OS/ARCH=GLOB, or another executable with --bin",
			Err:  err,
		}
	}
	return err
}

// missingLookup reports whether err is a 404 from one of the importer's
// release or repository lookups on the --api-url origin, and which lookup.
// A 404 anywhere else (a later attestations page, a download) is not a
// missing release.
func missingLookup(err error, apiURL string) (lookup string, ok bool) {
	var le *importer.LookupError
	var nf *ghrelease.NotFoundError
	if !errors.As(err, &le) || !errors.As(le.Err, &nf) {
		return "", false
	}
	got, gerr := url.Parse(nf.URL)
	want, werr := url.Parse(apiURL)
	if gerr != nil || werr != nil || !strings.EqualFold(got.Scheme, want.Scheme) || !strings.EqualFold(got.Host, want.Host) {
		return "", false
	}
	return le.Lookup, true
}

package cli

import (
	"bytes"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/repo"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

// addRepoCommonFlags adds --manifest and --key-dir, which every repo
// subcommand needs (including read-only ones like status that never decrypt
// the signing key). Password-needing commands additionally call
// addRepoKeyPasswordFlag.
func addRepoCommonFlags(cmd *cobra.Command) {
	cmd.Flags().String("manifest", "polypkg-repo.yaml", "Path to the repo manifest")
	cmd.Flags().String("key-dir", "", "Directory holding the signing key and build cache (default: XDG data repo-keys)")
}

// addRepoKeyPasswordFlag adds --key-password-file to commands that decrypt the
// signing key (build, add, remove, key show). It is intentionally omitted from
// status, which is a read-only probe and never requires the password.
func addRepoKeyPasswordFlag(cmd *cobra.Command) {
	cmd.Flags().String("key-password-file", "", "File containing the signing-key password")
}

// addRepoBuildFlags adds the publish-tuning flags shared by every command that
// reconciles the repository through buildRepo (build, add, remove). They are
// intentionally omitted from status and key show, which never publish.
func addRepoBuildFlags(cmd *cobra.Command) {
	cmd.Flags().Duration("valid-for", repo.DefaultValidFor, "Validity window stamped into the signed index and trust document (freshness bound)")
	cmd.Flags().Bool("skip-attestations", false, "Publish without lint attestations (e.g. the signing key deliberately lacks the attestation role). Cached packages keep their previous attestation decision until their source changes.")
}

// resolveKeyDir returns the --key-dir flag value, or the XDG default when the
// flag is empty or absent.
func resolveKeyDir(cmd *cobra.Command) (string, error) {
	if kd, _ := cmd.Flags().GetString("key-dir"); kd != "" {
		return kd, nil
	}
	return defaultKeyDir()
}

// shortValidForFloor is the window below which --valid-for draws a warning.
// Anything shorter publishes metadata that consumers treat as expired within
// minutes (trust.ExpirySkew alone is 5m), which is legal but almost never what
// the operator meant.
const shortValidForFloor = time.Hour

// resolveValidFor reads --valid-for, refusing a non-positive window and warning
// about an implausibly short one. A non-positive duration used to be swallowed:
// repo.Build and repo.Revoke both substitute their 720h default for it, so
// `--valid-for -48h` silently published a 30-day window. Refusing here keeps the
// library default for programmatic callers while making the CLI say no to a
// value it cannot honor.
func resolveValidFor(cmd *cobra.Command) (time.Duration, error) {
	validFor, _ := cmd.Flags().GetDuration("valid-for")
	if validFor <= 0 {
		return 0, &CLIError{
			Msg:  fmt.Sprintf("--valid-for must be a positive duration (got %s)", validFor),
			Hint: "pass a window such as 720h (30 days, the default) or 24h; the published metadata is refused by clients once it expires",
		}
	}
	if validFor < shortValidForFloor {
		fmt.Fprintf(cmd.ErrOrStderr(),
			"warning: --valid-for %s is shorter than %s; clients refuse the published metadata once the window and the %s clock-skew allowance have passed\n",
			validFor, shortValidForFloor, trust.ExpirySkew)
	}
	return validFor, nil
}

// buildPreflight holds everything a reconcile needs, resolved and validated
// without writing anything: the flag values plus a Builder whose signing key is
// already decrypted. Splitting this out of the reconcile itself is what lets
// `repo add` and `repo remove` settle every question that could reject the
// command before they edit the manifest (see the invariant note at the top of
// repoaddremove.go).
type buildPreflight struct {
	manifest string
	keyDir   string
	validFor time.Duration
	skipAtt  bool
	builder  *repo.Builder
}

// newBuildPreflight resolves --manifest, --key-dir, --valid-for,
// --skip-attestations and the signing-key password, then loads the manifest and
// unlocks the key. Every failure it can report is decided before any file is
// written.
func newBuildPreflight(cmd *cobra.Command) (*buildPreflight, error) {
	manifest, _ := cmd.Flags().GetString("manifest")
	keyDir, err := resolveKeyDir(cmd)
	if err != nil {
		return nil, err
	}
	validFor, err := resolveValidFor(cmd)
	if err != nil {
		return nil, err
	}
	pw, err := repoKeyPassword(cmd)
	if err != nil {
		return nil, err
	}
	b, err := repo.NewBuilder(manifest, keyDir, pw)
	if err != nil {
		return nil, mapPublishError(err)
	}
	skipAtt, _ := cmd.Flags().GetBool("skip-attestations")
	return &buildPreflight{
		manifest: manifest,
		keyDir:   keyDir,
		validFor: validFor,
		skipAtt:  skipAtt,
		builder:  b,
	}, nil
}

// build performs the reconcile and returns the Result. Apart from the
// --valid-for diagnostics (which are about the flag it consumes, not about the
// result), it emits no output, so build, add, and remove can each frame the
// Result their own way.
func (p *buildPreflight) build(cmd *cobra.Command) (repo.Result, error) {
	res, err := p.builder.Build(repo.BuildOptions{ValidFor: p.validFor, SkipAttestations: p.skipAtt})
	if err != nil {
		return repo.Result{}, mapPublishError(err)
	}
	noteValidForNotApplied(cmd, res)
	return res, nil
}

// buildEdit reconciles the repository against a manifest edit that is not on
// disk yet, and persists the edit only once that reconcile has succeeded.
//
// The ordering is the whole point. Building is what can fail after every
// precondition has passed — packing, signing, running out of space — so doing it
// first is what makes a `repo add` or `repo remove` that exits non-zero leave
// polypkg-repo.yaml byte-identical. The residual is the mirror image and a much
// smaller one: if the atomic manifest write itself fails, the repository has
// been rebuilt but the manifest has not caught up, which the operator is told
// about and fixes by re-running the same command.
func (p *buildPreflight) buildEdit(cmd *cobra.Command, edit *repo.ManifestEdit) (repo.Result, error) {
	if err := p.builder.SetManifest(edit.Manifest, p.manifest, p.keyDir); err != nil {
		return repo.Result{}, mapPublishError(err)
	}
	res, err := p.build(cmd)
	if err != nil {
		return repo.Result{}, err
	}
	if err := edit.Commit(); err != nil {
		return repo.Result{}, &CLIError{
			Msg:  "cannot write the repo manifest",
			Hint: "the repository was rebuilt but polypkg-repo.yaml could not be updated; check permissions on the manifest and its directory, then re-run",
			Err:  err,
		}
	}
	return res, nil
}

// noteValidForNotApplied tells the operator when an explicitly-passed
// --valid-for was discarded. A rebuild that changes no content reuses the
// window the previous build stamped, as long as it is still above its half-life
// (renewing only past half-life keeps no-op rebuilds idempotent). That is the
// right behavior, but exiting 0 with "already up to date" while dropping a flag
// the operator typed sends them debugging the wrong thing. Silent when the flag
// was not passed or the window was applied.
func noteValidForNotApplied(cmd *cobra.Command, res repo.Result) {
	if res.ValidForApplied || !cmd.Flags().Changed("valid-for") {
		return
	}
	msg := fmt.Sprintf("note: --valid-for not applied; the published metadata is still fresh (expires %s)", res.Expires)
	// RestampAfter is the half-life of the window the published document was
	// actually issued with, which is exactly the window this run did not get to
	// apply — deriving it from the rejected flag would name the wrong instant.
	if res.RestampAfter != "" {
		msg = fmt.Sprintf("%s and re-stamps on the next build after %s", msg, res.RestampAfter)
	}
	fmt.Fprintln(cmd.ErrOrStderr(), msg)
}

func newRepoBuildCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Reconcile the output directory: (re)build and sign changed packages, index, and trust doc",
		Long: `Builds any package whose source changed since the last build, regenerates the
signed index and trust document, and publishes atomically. Unchanged packages
are reused from the build cache.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "repo build", runRepoBuild(cmd, format))
		},
	}
	addRepoCommonFlags(cmd)
	addRepoKeyPasswordFlag(cmd)
	addRepoBuildFlags(cmd)
	return cmd
}

func runRepoBuild(cmd *cobra.Command, format Format) error {
	pf, err := newBuildPreflight(cmd)
	if err != nil {
		return err
	}
	res, err := pf.build(cmd)
	if err != nil {
		return err
	}
	data := map[string]any{"changed": res.Changed, "serial": res.SerialAfter}
	if res.TrustBundle != nil {
		data["trust_bundle"] = res.TrustBundle
	}
	EmitResult(cmd, format, "repo build", data,
		func(w *bytes.Buffer, _ map[string]any) {
			if res.Changed {
				fmt.Fprintf(w, "Built and signed repository (serial %d)\n", res.SerialAfter)
			} else {
				fmt.Fprintf(w, "Repository already up to date (serial %d)\n", res.SerialAfter)
			}
			writeTrustBundleChange(w, res.TrustBundle, false)
		})
	return nil
}

// writeTrustBundleChange renders what a build did, or would do, to the
// published trust bundle, so whoever reviews a sigstore_roots or trust_bundle
// edit sees the trust it adds: each sigstore root's Fulcio root fingerprint
// and validity window, and each builder key's id and window. pending words it
// for `repo status`. A nil c writes nothing.
func writeTrustBundleChange(w *bytes.Buffer, c *repo.TrustBundleChange, pending bool) {
	if c == nil {
		return
	}
	if c.Withdrawn {
		verb := "Withdrew"
		if pending {
			verb = "Would withdraw"
		}
		fmt.Fprintf(w, "%s the published trust bundle: the manifest no longer names a sigstore root or carried trust bundle\n", verb)
		return
	}
	verb := "now vouches"
	if pending {
		verb = "would vouch"
	}
	fmt.Fprintf(w, "The trust bundle %s for:\n", verb)
	for _, r := range c.Roots {
		until := r.ValidUntil
		if until == "" {
			until = "open-ended"
		}
		fmt.Fprintf(w, "  sigstore root: Fulcio root sha256:%s, valid %s to %s\n", r.FulcioRootSHA256, r.ValidFrom, until)
	}
	for _, k := range c.BuilderKeys {
		until := k.ValidUntil
		if until == "" {
			until = "open-ended"
		}
		fmt.Fprintf(w, "  builder key: %s, valid %s to %s\n", k.KeyID, k.ValidFrom, until)
	}
}

func newRepoStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show whether `repo build` would change anything (exit 2 if changes are pending)",
		Long: `Reports pending changes without writing any files.

Exit codes: 0 = repository is up to date, 2 = build would change output, 1 = error.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return runRepoStatus(cmd, format)
		},
	}
	addRepoCommonFlags(cmd)
	return cmd
}

func runRepoStatus(cmd *cobra.Command, format Format) error {
	manifest, _ := cmd.Flags().GetString("manifest")
	keyDir, err := resolveKeyDir(cmd)
	if err != nil {
		return WrapError(cmd, format, "repo status", err)
	}
	insp, err := repo.NewInspector(manifest, keyDir)
	if err != nil {
		return WrapError(cmd, format, "repo status", mapPublishError(err))
	}
	pending, reason, err := insp.Pending()
	if err != nil {
		return WrapError(cmd, format, "repo status", mapPublishError(err))
	}
	// Pending reports the first reason it finds, so the trust bundle is asked
	// separately: a package change must not hide a trust change.
	var tbChange *repo.TrustBundleChange
	if pending {
		if tbChange, err = insp.TrustBundleChange(); err != nil {
			return WrapError(cmd, format, "repo status", mapPublishError(err))
		}
	}
	data := map[string]any{"pending": pending, "reason": reason}
	if tbChange != nil {
		data["trust_bundle"] = tbChange
	}
	EmitResult(cmd, format, "repo status", data,
		func(w *bytes.Buffer, _ map[string]any) {
			if pending {
				fmt.Fprintf(w, "Changes pending (%s): run `polypkg repo build`\n", reason)
				writeTrustBundleChange(w, tbChange, true)
			} else {
				fmt.Fprintln(w, "Up to date")
			}
		})
	// Emit the status envelope before returning the exit-2 sentinel.
	// StatusError.Quiet=true suppresses any additional stderr rendering.
	if pending {
		return &StatusError{Code: 2, Quiet: true, Msg: "changes pending"}
	}
	return nil
}

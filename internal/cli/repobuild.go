package cli

import (
	"bytes"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/repo"
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

// buildRepo performs the reconcile and returns the Result. It does not emit
// any output, making it reusable by build, add, and remove subcommands.
func buildRepo(cmd *cobra.Command) (repo.Result, error) {
	manifest, _ := cmd.Flags().GetString("manifest")
	keyDir, err := resolveKeyDir(cmd)
	if err != nil {
		return repo.Result{}, err
	}
	pw, err := repoKeyPassword(cmd)
	if err != nil {
		return repo.Result{}, err
	}
	b, err := repo.NewBuilder(manifest, keyDir, pw)
	if err != nil {
		return repo.Result{}, mapPublishError(err)
	}
	validFor, _ := cmd.Flags().GetDuration("valid-for")
	skipAtt, _ := cmd.Flags().GetBool("skip-attestations")
	res, err := b.Build(repo.BuildOptions{ValidFor: validFor, SkipAttestations: skipAtt})
	if err != nil {
		return repo.Result{}, mapPublishError(err)
	}
	return res, nil
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
	res, err := buildRepo(cmd)
	if err != nil {
		return err
	}
	EmitResult(cmd, format, "repo build",
		map[string]any{"changed": res.Changed, "serial": res.SerialAfter},
		func(w *bytes.Buffer, _ map[string]any) {
			if res.Changed {
				fmt.Fprintf(w, "Built and signed repository (serial %d)\n", res.SerialAfter)
			} else {
				fmt.Fprintf(w, "Repository already up to date (serial %d)\n", res.SerialAfter)
			}
		})
	return nil
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
	EmitResult(cmd, format, "repo status",
		map[string]any{"pending": pending, "reason": reason},
		func(w *bytes.Buffer, _ map[string]any) {
			if pending {
				fmt.Fprintf(w, "Changes pending (%s): run `polypkg repo build`\n", reason)
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

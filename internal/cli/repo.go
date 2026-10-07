package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/paths"
	"github.com/trevor-vaughan/polypkg/internal/repo"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func newRepoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "repo",
		Short: "Build and manage a polypkg package repository",
		Long: `Build, sign, and maintain a polypkg repository that clients install from.

A repository is described declaratively by polypkg-repo.yaml. 'repo add' and
'repo remove' edit that manifest; 'repo build' reconciles the output directory,
(re)signing only what changed. Signing keys are stored encrypted, outside the
published directory.`,
		Args: cobra.ArbitraryArgs,
		RunE: requireSubcommand(""),
	}
	// Subcommands are grouped by repository lifecycle, mirroring the top-level
	// command grouping (see AGENTS.md). The table is the single source of truth:
	// each entry registers its group and tags its commands, and slice order
	// drives both group display order and the order within each group.
	for _, g := range []struct {
		id    string
		title string
		cmds  []*cobra.Command
	}{
		{"getting-started", "Getting started:", []*cobra.Command{
			newRepoInitCmd(),
		}},
		{"contents", "Repository contents:", []*cobra.Command{
			newRepoAddCmd(), newRepoRemoveCmd(),
		}},
		{"build", "Build & status:", []*cobra.Command{
			newRepoBuildCmd(), newRepoExportBundleCmd(), newRepoStatusCmd(),
		}},
		{"signing", "Signing keys:", []*cobra.Command{
			newRepoKeyCmd(),
		}},
		{"revocation", "Revocation:", []*cobra.Command{
			newRepoRevokeCmd(),
		}},
	} {
		cmd.AddGroup(&cobra.Group{ID: g.id, Title: g.title})
		for _, c := range g.cmds {
			c.GroupID = g.id
			cmd.AddCommand(c)
		}
	}
	return cmd
}

// repoKeyPassword resolves the signing-key password from --key-password-file or
// the POLYPKG_REPO_KEY_PASSWORD env var. It never accepts a bare flag value.
func repoKeyPassword(cmd *cobra.Command) (string, error) {
	if pf, _ := cmd.Flags().GetString("key-password-file"); pf != "" {
		b, err := os.ReadFile(pf) //nolint:gosec // path is user-supplied via --key-password-file flag
		if err != nil {
			return "", &CLIError{Msg: "cannot read --key-password-file", Hint: "check the path and permissions", Err: err}
		}
		return string(bytes.TrimRight(b, "\r\n")), nil
	}
	if v := os.Getenv("POLYPKG_REPO_KEY_PASSWORD"); v != "" {
		return v, nil
	}
	return "", &CLIError{
		Msg:  "no signing-key password provided",
		Hint: "set POLYPKG_REPO_KEY_PASSWORD or pass --key-password-file <path>",
	}
}

// defaultKeyDir returns the XDG data location for repo signing keys.
func defaultKeyDir() (string, error) {
	dataHome, err := paths.UserDataHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(dataHome, "repo-keys"), nil
}

// mapPublishError maps a repo.PublishError onto the shared CLIError contract,
// naming a filesystem cause the publisher can act on (see fsFailureMsg).
func mapPublishError(err error) error {
	var pe *repo.PublishError
	if errors.As(err, &pe) {
		return &CLIError{Msg: fsFailureMsg(pe.Msg, pe.Err), Hint: pe.HintText(), Err: pe.Unwrap()}
	}
	return err
}

func newRepoInitCmd() *cobra.Command {
	var source, keyDir, kdf string
	cmd := &cobra.Command{
		Use:   "init <dir>",
		Short: "Scaffold a new repository (directory, signing key, manifest)",
		Long:  "Creates <dir> with a polypkg-repo.yaml manifest, generates an encrypted signing key (stored outside <dir>), and exports the public trust root.",
		Args:  needsArgs(1, 1, "<dir>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "repo init", runRepoInit(cmd, args[0], source, keyDir, kdf, format))
		},
	}
	cmd.Flags().StringVar(&source, "source", "", "Source name bound into the signed trust document (required)")
	cmd.Flags().StringVar(&keyDir, "key-dir", "", "Directory for the encrypted signing key (default: XDG data repo-keys)")
	cmd.Flags().StringVar(&kdf, "kdf", "scrypt", "Key-encryption KDF: scrypt (default) or pbkdf2 (FIPS)")
	cmd.Flags().String("key-password-file", "", "File containing the signing-key password")
	requireFlags(cmd, "source")
	return cmd
}

func runRepoInit(cmd *cobra.Command, dir, source, keyDir, kdf string, format Format) error {
	// The source name becomes <key-dir>/<source>.key, so it is checked before
	// anything is created: a separator would otherwise silently override the
	// --key-dir the operator passed.
	if err := schema.ValidateSourceName(source); err != nil {
		return &CLIError{
			Msg:  fmt.Sprintf("--source %q is not a valid slug", source),
			Hint: "a source is a NAME, not a path or URL; it must match " + schema.SourceNamePattern + " (e.g. --source myrepo)",
			Err:  err,
		}
	}
	pw, err := repoKeyPassword(cmd)
	if err != nil {
		return err
	}
	if keyDir == "" {
		keyDir, err = defaultKeyDir()
		if err != nil {
			return err
		}
	}
	k := repo.KDF(kdf)
	if k != repo.KDFScrypt && k != repo.KDFPBKDF2 {
		return &CLIError{Msg: fmt.Sprintf("invalid --kdf %q", kdf), Hint: "use scrypt or pbkdf2"}
	}
	res, err := repo.InitRepo(repo.InitOptions{Dir: dir, KeyDir: keyDir, Source: source, Password: pw, KDF: k})
	if err != nil {
		return mapPublishError(err)
	}
	EmitResult(cmd, format, "repo init",
		map[string]any{"manifest": res.ManifestPath, "key": res.KeyPath, "trust_root": res.TrustRootPath},
		func(w *bytes.Buffer, d map[string]any) {
			fmt.Fprintf(w, "Initialized repository at %s\n", dir)
			fmt.Fprintf(w, "  manifest:   %s\n  key:        %s (keep this secret)\n  trust root: %s\n", d["manifest"], d["key"], d["trust_root"])
			fmt.Fprintf(w, "Next: polypkg repo add <package-source-dir>; give clients %s as their trust_root\n", d["trust_root"])
		})
	return nil
}

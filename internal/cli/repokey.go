package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/repo"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func newRepoKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Inspect the repository signing key",
		Long:  "Subcommands for inspecting the repository's signing key. The private key is never printed.",
	}
	cmd.AddCommand(newRepoKeyShowCmd())
	return cmd
}

func newRepoKeyShowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Print the public signing key and its fingerprint (never the secret)",
		Long:  "Decrypts the signing key and prints only its public key material and key id; the private key is never written to output.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "repo key show", runRepoKeyShow(cmd, format))
		},
	}
	addRepoCommonFlags(cmd)
	addRepoKeyPasswordFlag(cmd)
	return cmd
}

func runRepoKeyShow(cmd *cobra.Command, format Format) error {
	manifestPath, _ := cmd.Flags().GetString("manifest")
	f, err := os.Open(manifestPath) //nolint:gosec // G304: path is user-supplied manifest location from --manifest flag
	if err != nil {
		return &CLIError{Msg: "cannot open repo manifest", Hint: "run `polypkg repo init <dir>` first", Err: err}
	}
	defer func() { _ = f.Close() }()
	m, err := schema.ParseRepoManifest(f)
	if err != nil {
		return mapPublishError(err)
	}
	pw, err := repoKeyPassword(cmd)
	if err != nil {
		return err
	}
	// Resolve key.path relative to the manifest directory for hand-authored
	// manifests that use a relative path. Absolute paths are unchanged.
	keyPath := m.Key.Path
	if !filepath.IsAbs(keyPath) {
		keyPath = filepath.Join(filepath.Dir(manifestPath), keyPath)
	}
	kp, err := repo.LoadKey(keyPath, pw)
	if err != nil {
		return &CLIError{Msg: "cannot unlock signing key", Hint: "set POLYPKG_REPO_KEY_PASSWORD or pass --key-password-file", Err: err}
	}
	EmitResult(cmd, format, "repo key show",
		map[string]any{"key_id": kp.KeyIDHex(), "pubkey": kp.PublicKeyBase64()},
		func(w *bytes.Buffer, d map[string]any) {
			fmt.Fprint(w, kp.PublicKeyFile("polypkg "+m.Source+" trust root"))
			fmt.Fprintf(w, "key id: %s\n", d["key_id"])
		})
	return nil
}

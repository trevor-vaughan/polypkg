package cli

import (
	"bytes"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/repo"
)

func newRepoRevokeCmd() *cobra.Command {
	var attestations, builderKeys []string
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Author and publish the repository's signed revocation list",
		Long: `Revoke a compromised builder key or a bad attestation.

'repo revoke' authors, signs, and publishes revocations.json (plus its detached
signature) in the repository output directory, bumping the list's serial and
stamping a fresh freshness window. Revocations are cumulative: each call merges
its targets into the already-published set and never removes an entry. Clients
fetch revocations.json and refuse any package whose attestation content-hash or
builder key it names.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "repo revoke", runRepoRevoke(cmd, attestations, builderKeys, format))
		},
	}
	addRepoCommonFlags(cmd)
	addRepoKeyPasswordFlag(cmd)
	cmd.Flags().StringArrayVar(&attestations, "attestation", nil, "Attestation content-hash to revoke (blake3:<hex>); repeatable")
	cmd.Flags().StringArrayVar(&builderKeys, "builder-key", nil, "Builder key id to revoke; repeatable")
	cmd.Flags().Duration("valid-for", repo.DefaultValidFor, "Freshness window stamped into the signed revocation list")
	return cmd
}

func runRepoRevoke(cmd *cobra.Command, attestations, builderKeys []string, format Format) error {
	manifest, _ := cmd.Flags().GetString("manifest")
	keyDir, err := resolveKeyDir(cmd)
	if err != nil {
		return err
	}
	pw, err := repoKeyPassword(cmd)
	if err != nil {
		return err
	}
	b, err := repo.NewBuilder(manifest, keyDir, pw)
	if err != nil {
		return mapPublishError(err)
	}
	validFor, _ := cmd.Flags().GetDuration("valid-for")
	res, err := b.Revoke(repo.RevokeOptions{
		Attestations: attestations,
		BuilderKeys:  builderKeys,
		ValidFor:     validFor,
	})
	if err != nil {
		return mapPublishError(err)
	}
	EmitResult(cmd, format, "repo revoke",
		map[string]any{
			"revocations":          res.RevocationsPath,
			"signature":            res.SignaturePath,
			"serial":               res.Serial,
			"revoked_attestations": res.RevokedAttestations,
			"revoked_builder_keys": res.RevokedBuilderKeys,
		},
		func(w *bytes.Buffer, d map[string]any) {
			fmt.Fprintf(w, "Published revocation list (serial %v)\n", d["serial"])
			fmt.Fprintf(w, "  revocations: %s\n  signature:   %s\n", d["revocations"], d["signature"])
			fmt.Fprintf(w, "  revoked attestations: %d  revoked builder keys: %d\n",
				len(res.RevokedAttestations), len(res.RevokedBuilderKeys))
			fmt.Fprintf(w, "Clients pick this up on their next fetch; re-run `polypkg repo export-bundle` if you distribute via bundles.\n")
		})
	return nil
}

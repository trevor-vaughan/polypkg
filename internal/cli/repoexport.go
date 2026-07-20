package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/repo"
)

func newRepoExportBundleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export-bundle",
		Short: "Export a signed, self-contained tarball mirror of the built repository",
		Long: `Packs the built repository into one tarball for offline transport to an
air-gapped site. The bundle carries the selected packages' artifacts and
attestations, all signed metadata documents, the trust root, and a signed
completeness manifest (polypkg.pool-manifest/v1). Verify it with
'polypkg mirror verify'; extract it and point a polypkg-native file:// source at
it to re-serve.

Selection: with no --package/--from-file the whole repository is exported. A
'name' selector exports every version of that package; 'name@version' exports
one version. --package is repeatable and unions with --from-file.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "repo export-bundle", runRepoExportBundle(cmd, format))
		},
	}
	addRepoCommonFlags(cmd)
	addRepoKeyPasswordFlag(cmd)
	cmd.Flags().StringArray("package", nil, "Select a package to export: name or name@version (repeatable)")
	cmd.Flags().String("from-file", "", "Read additional selectors, one per line (blank lines and # comments ignored)")
	cmd.Flags().StringP("output", "o", "", "Path to write the bundle tarball (required)")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

func runRepoExportBundle(cmd *cobra.Command, format Format) error {
	manifest, _ := cmd.Flags().GetString("manifest")
	keyDir, err := resolveKeyDir(cmd)
	if err != nil {
		return err
	}
	pw, err := repoKeyPassword(cmd)
	if err != nil {
		return err
	}
	selectors, _ := cmd.Flags().GetStringArray("package")
	if ff, _ := cmd.Flags().GetString("from-file"); ff != "" {
		more, ferr := readSelectorFile(ff)
		if ferr != nil {
			return ferr
		}
		selectors = append(selectors, more...)
	}
	output, _ := cmd.Flags().GetString("output")

	b, err := repo.NewBuilder(manifest, keyDir, pw)
	if err != nil {
		return mapPublishError(err)
	}
	res, err := b.ExportBundle(selectors, output)
	if err != nil {
		return mapPublishError(err)
	}
	EmitResult(cmd, format, "repo export-bundle",
		map[string]any{"bundle": res.BundlePath, "entries": res.Entries, "serial": res.Serial, "expires": res.Expires},
		func(w *bytes.Buffer, d map[string]any) {
			fmt.Fprintf(w, "Exported %v files to %s (serial %v, expires %v)\n", d["entries"], res.BundlePath, d["serial"], d["expires"])
			fmt.Fprintf(w, "Verify with: polypkg mirror verify %s\n", res.BundlePath)
		})
	return nil
}

// readSelectorFile reads package selectors, one per line; blank lines and lines
// beginning with '#' are ignored.
func readSelectorFile(path string) ([]string, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, &CLIError{Msg: "cannot read --from-file", Hint: "check the path and permissions", Err: err}
	}
	var sels []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sels = append(sels, line)
	}
	return sels, nil
}

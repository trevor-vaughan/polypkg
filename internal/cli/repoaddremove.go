package cli

import (
	"bytes"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/repo"
)

func newRepoAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add <package-source-dir>",
		Short: "Register a package source in the manifest and build",
		Long:  "Reads the package's polypkg.yaml for its name, registers packages.<name>.source in the manifest, then reconciles the repository.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "repo add", runRepoAdd(cmd, args[0], format))
		},
	}
	addRepoCommonFlags(cmd)
	addRepoKeyPasswordFlag(cmd)
	addRepoBuildFlags(cmd)
	return cmd
}

func runRepoAdd(cmd *cobra.Command, srcDir string, format Format) error {
	manifest, _ := cmd.Flags().GetString("manifest")
	pkg, err := repo.ReadPackageSource(srcDir)
	if err != nil {
		return &CLIError{
			Msg:  fmt.Sprintf("cannot read package source %q", srcDir),
			Hint: "the directory must contain a polypkg.yaml (schema polypkg.package/v1) and a content/ tree",
			Err:  err,
		}
	}

	// Normalize srcDir to be manifest-relative so Build resolves it correctly
	// regardless of the cwd that `repo add` was run from.
	storedSrc := normalizeSrcPath(manifest, srcDir)

	if err := repo.AddPackage(manifest, pkg.Name, storedSrc); err != nil {
		return mapPublishError(err)
	}
	res, err := buildRepo(cmd)
	if err != nil {
		return err
	}
	EmitResult(cmd, format, "repo add",
		map[string]any{"package": pkg.Name, "version": pkg.Version, "serial": res.SerialAfter},
		func(w *bytes.Buffer, d map[string]any) {
			fmt.Fprintf(w, "Added %s@%s and rebuilt the repository (serial %d)\n", d["package"], d["version"], d["serial"])
		})
	return nil
}

// normalizeSrcPath converts srcDir to a path relative to the directory that
// holds the repo manifest so that Build can resolve it correctly regardless of
// the cwd used when `repo add` was invoked. If the manifest path cannot be
// made absolute or if filepath.Rel produces a path that still escapes (i.e.
// starts with "..") and is therefore ugly, the absolute form of srcDir is
// stored instead — still correct, though less portable.
func normalizeSrcPath(manifestPath, srcDir string) string {
	manifestAbs, err := filepath.Abs(manifestPath)
	if err != nil {
		return srcDir
	}
	srcAbs, err := filepath.Abs(srcDir)
	if err != nil {
		return srcDir
	}
	manifestDir := filepath.Dir(manifestAbs)
	rel, err := filepath.Rel(manifestDir, srcAbs)
	if err != nil {
		return srcAbs
	}
	return rel
}

func newRepoRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a package from the manifest and rebuild",
		Long:  "Removes packages.<name> from the manifest, then reconciles the repository so the package drops out of the signed index.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "repo remove", runRepoRemove(cmd, args[0], format))
		},
	}
	addRepoCommonFlags(cmd)
	addRepoKeyPasswordFlag(cmd)
	addRepoBuildFlags(cmd)
	return cmd
}

func runRepoRemove(cmd *cobra.Command, name string, format Format) error {
	manifest, _ := cmd.Flags().GetString("manifest")
	if err := repo.RemovePackage(manifest, name); err != nil {
		return mapPublishError(err)
	}
	res, err := buildRepo(cmd)
	if err != nil {
		return err
	}
	EmitResult(cmd, format, "repo remove",
		map[string]any{"package": name, "serial": res.SerialAfter},
		func(w *bytes.Buffer, d map[string]any) {
			fmt.Fprintf(w, "Removed %s and rebuilt the repository (serial %d)\n", d["package"], d["serial"])
		})
	return nil
}

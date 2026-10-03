package cli

import (
	"bytes"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/repo"
)

// Manifest-mutation invariant for this file:
//
//	A `repo add` or `repo remove` that exits non-zero has not modified
//	polypkg-repo.yaml.
//
// Both commands edit the manifest and reconcile the repository, so anything that
// can fail after the edit reaches disk turns a rejected command into a staged
// one: the operator sees a clear error and a non-zero exit, but the edit
// survives and the next bare `repo build` publishes — or unpublishes — it. That
// is how `repo remove hello --valid-for 0` used to silently queue an unpublish,
// and how a build that died while packing or signing used to leave a package
// half-added.
//
// Nothing writes the manifest until everything that could fail has run.
// Preconditions are settled first — the package source directory
// (repo.ReadPackageSource), --manifest, --key-dir, --valid-for, the key
// password, and the unlocking of the signing key itself (newBuildPreflight) —
// and then the edit is computed in memory (repo.PlanAddPackage /
// repo.PlanRemovePackage), reconciled against, and persisted only on success
// (buildPreflight.buildEdit). Keep it that way: new work belongs before the
// commit, not after it.

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
	pkg, err := repo.ReadPackageSource(srcDir)
	if err != nil {
		return &CLIError{
			Msg:  fmt.Sprintf("cannot read package source %q", srcDir),
			Hint: "the directory must contain a polypkg.yaml (schema polypkg.package/v1) and a content/ tree",
			Err:  err,
		}
	}
	pf, err := newBuildPreflight(cmd)
	if err != nil {
		return err
	}

	// Normalize srcDir to be manifest-relative so Build resolves it correctly
	// regardless of the cwd that `repo add` was run from.
	storedSrc := normalizeSrcPath(pf.manifest, srcDir)

	edit, err := repo.PlanAddPackage(pf.manifest, pkg.Name, storedSrc)
	if err != nil {
		return mapPublishError(err)
	}
	res, err := pf.buildEdit(cmd, edit)
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
	pf, err := newBuildPreflight(cmd)
	if err != nil {
		return err
	}
	edit, err := repo.PlanRemovePackage(pf.manifest, name)
	if err != nil {
		return mapPublishError(err)
	}
	res, err := pf.buildEdit(cmd, edit)
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

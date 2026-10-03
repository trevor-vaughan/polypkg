package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/repo"
	"github.com/trevor-vaughan/polypkg/internal/schema"
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
		Use:   "remove <name>[@<version>]",
		Short: "Remove a package, or one of its versions, from the manifest and rebuild",
		Long: "Removes packages.<name> from the manifest, or with @<version>, just the entry that " +
			"publishes that version, then reconciles the repository so the removed package or " +
			"version drops out of the signed index.",
		Args: cobra.ExactArgs(1),
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

func runRepoRemove(cmd *cobra.Command, arg string, format Format) error {
	pf, err := newBuildPreflight(cmd)
	if err != nil {
		return err
	}

	name, version, hasVersion := strings.Cut(arg, "@")

	var edit *repo.ManifestEdit
	if !hasVersion {
		edit, err = repo.PlanRemovePackage(pf.manifest, name)
		if err != nil {
			return mapPublishError(err)
		}
	} else {
		identifier, rerr := resolveVersionIdentifier(pf.manifest, name, version)
		if rerr != nil {
			return rerr
		}
		edit, err = repo.PlanRemovePackageSource(pf.manifest, name, identifier)
		if err != nil {
			return mapPublishError(err)
		}
	}

	res, err := pf.buildEdit(cmd, edit)
	if err != nil {
		return err
	}
	data := map[string]any{"package": name, "serial": res.SerialAfter}
	if hasVersion {
		data["version"] = version
	}
	EmitResult(cmd, format, "repo remove", data,
		func(w *bytes.Buffer, d map[string]any) {
			if v, ok := d["version"]; ok {
				fmt.Fprintf(w, "Removed %s@%s and rebuilt the repository (serial %d)\n", d["package"], v, d["serial"])
			} else {
				fmt.Fprintf(w, "Removed %s and rebuilt the repository (serial %d)\n", d["package"], d["serial"])
			}
		})
	return nil
}

// resolveVersionIdentifier finds which entry registered under name in the
// manifest at manifestPath declares version, and returns that entry's
// manifest identifier (repo.EntryIdentifier: a source path or prebuilt
// artifact path) for repo.PlanRemovePackageSource.
//
// The manifest deliberately does not record versions (see
// internal/repo/version_resolve.go), so resolving "@<version>" costs reading
// every entry via repo.EntryVersion until one matches - a YAML read for a
// source entry, a full extraction for a prebuilt one. That cost is accepted
// rather than routed through the build cache: the cache lives at a path
// (keyDir + source-derived filename, internal/repo/build.go) that only
// layoutFor computes, and duplicating that formula here would silently drift
// if the convention ever changed. `repo remove` is a rare interactive
// command, so the extraction cost is not worth that coupling.
func resolveVersionIdentifier(manifestPath, name, version string) (string, error) {
	f, err := os.Open(manifestPath) //nolint:gosec // G304: path is user-supplied manifest location from --manifest flag
	if err != nil {
		return "", &CLIError{Msg: "cannot open repo manifest", Hint: "run `polypkg repo init <dir>` first", Err: err}
	}
	defer func() { _ = f.Close() }()
	m, err := schema.ParseRepoManifest(f)
	if err != nil {
		return "", mapPublishError(err)
	}

	entries, ok := m.Packages[name]
	if !ok || len(entries) == 0 {
		return "", &CLIError{
			Msg:  "package " + name + " is not in the repo manifest",
			Hint: "run `polypkg repo status` to list registered packages",
		}
	}

	manifestDir := filepath.Dir(manifestPath)
	available := make([]string, 0, len(entries))
	for _, e := range entries {
		v, verr := repo.EntryVersion(manifestDir, e)
		if verr != nil {
			return "", mapPublishError(verr)
		}
		if v == version {
			return repo.EntryIdentifier(e), nil
		}
		available = append(available, v)
	}
	return "", &CLIError{
		Msg:  fmt.Sprintf("package %s has no published version %s", name, version),
		Hint: fmt.Sprintf("published versions of %s: %s", name, strings.Join(available, ", ")),
	}
}

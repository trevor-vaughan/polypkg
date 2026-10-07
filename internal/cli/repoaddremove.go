package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/platform"
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
// Preconditions are settled first — every package source directory
// (repo.ReadPackageSource), --manifest, --key-dir, --valid-for, the key
// password, and the unlocking of the signing key itself (newBuildPreflight) —
// and then the edit is computed in memory (repo.PlanAddPackage /
// repo.PlanRemovePackage), reconciled against, and persisted only on success
// (buildPreflight.buildEdit). Keep it that way: new work belongs before the
// commit, not after it.

func newRepoAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add <package-source-dir>...",
		Short: "Register package sources in the manifest and build",
		Long: "Reads each package's polypkg.yaml for its name, registers packages.<name>.source in the manifest, " +
			"then reconciles the repository once. Several directories (for example one per platform of a release) " +
			"are added together: if any of them cannot be read or built, none is added and polypkg-repo.yaml is " +
			"left unchanged.",
		Args: needsArgs(1, -1, "at least one <package-source-dir>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "repo add", runRepoAdd(cmd, args, format))
		},
	}
	addRepoCommonFlags(cmd)
	addRepoKeyPasswordFlag(cmd)
	addRepoBuildFlags(cmd)
	return cmd
}

func runRepoAdd(cmd *cobra.Command, srcDirs []string, format Format) error {
	// A directory given twice is refused before anything else, so the operator
	// is not asked to unlock the signing key for a batch that cannot run.
	seen := make(map[string]string, len(srcDirs))
	for _, srcDir := range srcDirs {
		abs, err := filepath.Abs(filepath.Clean(srcDir))
		if err != nil {
			abs = filepath.Clean(srcDir)
		}
		if prev, dup := seen[abs]; dup {
			return &CLIError{
				Msg:  fmt.Sprintf("package source %q is given more than once (also as %q)", srcDir, prev),
				Hint: "pass each package source directory once",
			}
		}
		seen[abs] = srcDir
	}
	pkgs := make([]*schema.Package, len(srcDirs))
	for i, srcDir := range srcDirs {
		pkg, err := repo.ReadPackageSource(srcDir)
		if err != nil {
			return &CLIError{
				Msg:  fmt.Sprintf("cannot read package source %q", srcDir),
				Hint: "the directory must contain a polypkg.yaml (schema polypkg.package/v1) and a content/ tree",
				Err:  err,
			}
		}
		pkgs[i] = pkg
	}
	pf, err := newBuildPreflight(cmd)
	if err != nil {
		return err
	}

	// Normalize each srcDir to be manifest-relative so Build resolves it
	// correctly regardless of the cwd that `repo add` was run from. Two
	// arguments naming the same directory would otherwise collapse into one
	// entry while the result reported both.
	adds := make([]repo.PackageAdd, len(srcDirs))
	given := make(map[string]string, len(srcDirs))
	for i, srcDir := range srcDirs {
		storedSrc := normalizeSrcPath(pf.manifest, srcDir)
		if prev, dup := given[storedSrc]; dup {
			return &CLIError{
				Msg:  fmt.Sprintf("package source %q is given more than once (also as %q)", srcDir, prev),
				Hint: "pass each package source directory once",
			}
		}
		given[storedSrc] = srcDir
		adds[i] = repo.PackageAdd{Name: pkgs[i].Name, Source: storedSrc}
	}

	edit, err := repo.PlanAddPackage(pf.manifest, adds...)
	if err != nil {
		return mapPublishError(err)
	}
	res, err := pf.buildEdit(cmd, edit)
	if err != nil {
		return err
	}
	added := make([]map[string]string, len(adds))
	for i, a := range adds {
		added[i] = map[string]string{
			"package":  a.Name,
			"version":  pkgs[i].Version,
			"platform": platform.Display(pkgs[i].Platform),
			"source":   a.Source,
		}
	}
	// package and version name the first source, as they did when `repo add`
	// took exactly one directory; added lists every source.
	data := map[string]any{"package": pkgs[0].Name, "version": pkgs[0].Version, "serial": res.SerialAfter, "added": added}
	if res.TrustBundle != nil {
		data["trust_bundle"] = res.TrustBundle
	}
	EmitResult(cmd, format, "repo add", data,
		func(w *bytes.Buffer, d map[string]any) {
			entries, _ := d["added"].([]map[string]string)
			if len(entries) == 1 {
				fmt.Fprintf(w, "Added %s@%s and rebuilt the repository (serial %d)\n", d["package"], d["version"], d["serial"])
			} else {
				fmt.Fprintf(w, "Added %d package sources and rebuilt the repository (serial %d)\n", len(entries), d["serial"])
				for _, e := range entries {
					fmt.Fprintf(w, "  %s@%s (%s)\n", e["package"], e["version"], e["platform"])
				}
			}
			writeTrustBundleChange(w, res.TrustBundle, false)
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
		Long: "Removes packages.<name> from the manifest, or with @<version>, every entry that " +
			"publishes that version (one per platform for a per-platform release), then reconciles " +
			"the repository so the removed package or version drops out of the signed index.",
		Args: needsArgs(1, 1, "<name>[@<version>]"),
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
	var removed []removedEntry
	if !hasVersion {
		edit, err = repo.PlanRemovePackage(pf.manifest, name)
		if err != nil {
			return mapPublishError(err)
		}
	} else {
		removed, err = resolveVersionEntries(pf.manifest, name, version)
		if err != nil {
			return err
		}
		identifiers := make([]string, len(removed))
		for i, r := range removed {
			identifiers[i] = r.identifier
		}
		edit, err = repo.PlanRemovePackageSource(pf.manifest, name, identifiers...)
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
		entries := make([]map[string]string, len(removed))
		for i, r := range removed {
			entries[i] = map[string]string{"entry": r.identifier, "platform": r.platform}
		}
		data["removed"] = entries
	}
	if res.TrustBundle != nil {
		data["trust_bundle"] = res.TrustBundle
	}
	EmitResult(cmd, format, "repo remove", data,
		func(w *bytes.Buffer, d map[string]any) {
			if v, ok := d["version"]; ok {
				fmt.Fprintf(w, "Removed %s@%s and rebuilt the repository (serial %d)\n", d["package"], v, d["serial"])
				// Render from d, the same data the JSON result carries. A version
				// published as one platform-agnostic entry keeps the single line
				// this command has always printed.
				entries, _ := d["removed"].([]map[string]string)
				if len(entries) > 1 || (len(entries) == 1 && entries[0]["platform"] != platform.Any) {
					for _, e := range entries {
						fmt.Fprintf(w, "  %s (%s)\n", e["entry"], e["platform"])
					}
				}
			} else {
				fmt.Fprintf(w, "Removed %s and rebuilt the repository (serial %d)\n", d["package"], d["serial"])
			}
			writeTrustBundleChange(w, res.TrustBundle, false)
		})
	return nil
}

// removedEntry is one manifest entry `repo remove <name>@<version>` withdraws.
type removedEntry struct {
	identifier string // repo.EntryIdentifier: a source path or prebuilt artifact path
	platform   string // the entry's platform, or platform.Any when platform-agnostic
}

// resolveVersionEntries finds every entry registered under name in the manifest
// at manifestPath that builds version, in manifest order: one per platform for a
// per-platform release, otherwise exactly one. Each carries the entry's
// manifest identifier (repo.EntryIdentifier) for repo.PlanRemovePackageSource
// and its platform for the command's result.
//
// The manifest deliberately does not record versions or platforms (see
// internal/repo/version_resolve.go), so resolving "@<version>" costs reading
// every entry via repo.EntryVersion - a YAML read for a source entry, a full
// extraction for a prebuilt one. Every entry is read, not just up to the first
// match, because a version's platform builds need not be adjacent. That cost
// is accepted rather than routed through the build cache: the cache lives at a
// path (keyDir + source-derived filename, internal/repo/build.go) that only
// layoutFor computes, and duplicating that formula here would silently drift
// if the convention ever changed. `repo remove` is a rare interactive
// command, so the extraction cost is not worth that coupling.
func resolveVersionEntries(manifestPath, name, version string) ([]removedEntry, error) {
	f, err := os.Open(manifestPath) //nolint:gosec // G304: path is user-supplied manifest location from --manifest flag
	if err != nil {
		return nil, &CLIError{Msg: "cannot open repo manifest", Hint: "run `polypkg repo init <dir>` first", Err: err}
	}
	defer func() { _ = f.Close() }()
	m, err := schema.ParseRepoManifest(f)
	if err != nil {
		return nil, mapPublishError(err)
	}

	entries, ok := m.Packages[name]
	if !ok || len(entries) == 0 {
		return nil, &CLIError{
			Msg:  "package " + name + " is not in the repo manifest",
			Hint: "run `polypkg repo status` to list registered packages",
		}
	}

	manifestDir := filepath.Dir(manifestPath)
	matched := make([]removedEntry, 0, len(entries))
	available := make([]string, 0, len(entries))
	for _, e := range entries {
		v, plat, verr := repo.EntryVersion(manifestDir, e)
		if verr != nil {
			// One unreadable entry could be another build of this version, so
			// resolving stops rather than withdrawing a partial set.
			id := repo.EntryIdentifier(e)
			reason := "entry " + id + " cannot be read"
			var pe *repo.PublishError
			if errors.As(verr, &pe) {
				reason = pe.Msg
			}
			return nil, &CLIError{
				Msg: fmt.Sprintf("cannot resolve %s@%s: %s, and every entry of %s must be readable to find "+
					"all builds of a version", name, version, reason, name),
				Hint: fmt.Sprintf("fix the entry %s under packages.%s in polypkg-repo.yaml, or delete it", id, name),
				Err:  verr,
			}
		}
		if v == version {
			matched = append(matched, removedEntry{identifier: repo.EntryIdentifier(e), platform: platform.Display(plat)})
			continue
		}
		if !slices.Contains(available, v) {
			available = append(available, v)
		}
	}
	if len(matched) == 0 {
		return nil, &CLIError{
			Msg:  fmt.Sprintf("package %s has no published version %s", name, version),
			Hint: fmt.Sprintf("published versions of %s: %s", name, strings.Join(available, ", ")),
		}
	}
	return matched, nil
}

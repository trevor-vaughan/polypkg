package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/lock"
	"github.com/trevor-vaughan/polypkg/internal/planner"
	"github.com/trevor-vaughan/polypkg/internal/profileedit"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func newInstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "install <package>[@<constraint>]...",
		Aliases: []string{"add"},
		Short:   "Add packages to the profile and apply",
		Long: `Resolves each package against the configured sources, writes it into the
profile, and applies so the new generation contains it.

A bare name (hello) pins the newest available version as a floor (">=X.Y.Z").
A bare version (hello@1.2.3) pins it exactly ("=1.2.3"). A constraint tail
(hello@">=1.2") is written verbatim.

Validation is all-or-nothing: if any requested package is unknown or has no
satisfying version, nothing is written.`,
		Example: "  # Install the newest version of hello\n" +
			"  polypkg install hello\n\n" +
			"  # Pin an exact version\n" +
			"  polypkg install hello@1.2.3\n\n" +
			"  # Install multiple packages at once\n" +
			"  polypkg install hello ripgrep fd",
		Args: needsArgs(1, -1, "at least one <package>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "install", runInstall(cmd, args, format))
		},
	}
	addScopeFlags(cmd)
	cmd.Flags().String("profile", "", "Profile file to edit (overrides scope-default discovery)")
	return cmd
}

// editAction classifies what an install request does to the profile.
type editAction string

const (
	editAdd    editAction = "add"
	editUpdate editAction = "update"
	editKept   editAction = "kept"
)

// installEdit is one resolved install request: the package name, the resulting
// constraint, the action it implies, and (for an update) the prior constraint.
type installEdit struct {
	Name       string
	Constraint string
	Action     editAction
	Old        string // prior constraint, set only when Action == editUpdate
}

// parsePackageArg splits a package argument into its name and version tail.
// The grammar is "<name>" or "<name>@<tail>". A bare name yields an empty tail
// and bare=true. A tail beginning with a digit is a bare version (bare=false,
// tail is the version); a tail beginning with a constraint operator is a
// verbatim constraint (bare=false, tail is the constraint). An empty tail
// after "@", an empty name, or a name failing the package-name grammar is a
// CLIError.
func parsePackageArg(arg string) (name, tail string, bare bool, err error) {
	name, rest, hasAt := strings.Cut(arg, "@")
	if !validPackageName(name) {
		return "", "", false, &CLIError{
			Msg:  fmt.Sprintf("invalid package name %q", name),
			Hint: "package names contain only letters, digits, underscores, and dashes",
		}
	}
	if !hasAt {
		return name, "", true, nil
	}
	if rest == "" {
		return "", "", false, &CLIError{
			Msg:  fmt.Sprintf("invalid package argument %q", arg),
			Hint: `use <name>, <name>@<version>, or <name>@<constraint> (e.g. hello, hello@1.2.0, hello@">=1.2")`,
		}
	}
	return name, rest, false, nil
}

// constraintForArg builds the profile constraint a parsed argument writes.
// A bare version becomes an exact pin ("=1.2.3"). A constraint tail is written
// verbatim. A bare name uses the resolved-newest version as a ">=" floor.
// A bare version tail with a leading 'v' or 'V' (e.g. "v1.0.0") is
// normalised to its canonical digit form ("=1.0.0") because semver does not
// include the prefix and the profile should hold the canonical form.
func constraintForArg(tail string, bare bool, newest string) string {
	if bare {
		return ">=" + newest
	}
	if isConstraintTail(tail) {
		return tail
	}
	// Strip a leading v/V from bare version tails before writing the pin.
	normalised := tail
	if tail != "" && (tail[0] == 'v' || tail[0] == 'V') {
		normalised = tail[1:]
	}
	return "=" + normalised
}

// isConstraintTail reports whether a version tail is a constraint expression
// (begins with an operator) rather than a bare version (begins with a digit).
func isConstraintTail(tail string) bool {
	if tail == "" {
		return false
	}
	switch tail[0] {
	case '=', '>', '<', '^', '~', '*':
		return true
	default:
		return false
	}
}

// classifyEdit decides what writing want does to a package currently pinned at
// current ("" means absent): add when absent, kept when unchanged, update
// otherwise.
func classifyEdit(current, want string) editAction {
	switch current {
	case "":
		return editAdd
	case want:
		return editKept
	default:
		return editUpdate
	}
}

// renderInstallEdits writes the per-package edit-summary lines to w.
func renderInstallEdits(w *bytes.Buffer, edits []installEdit) {
	for _, e := range edits {
		switch e.Action {
		case editAdd:
			fmt.Fprintf(w, "installing %s (%q)\n", e.Name, e.Constraint)
		case editKept:
			fmt.Fprintf(w, "%s is already in the profile (%q)\n", e.Name, e.Constraint)
		case editUpdate:
			fmt.Fprintf(w, "updating %s: %q -> %q\n", e.Name, e.Old, e.Constraint)
		}
	}
}

// notChangedError appends "(the profile was not changed)" to err's user-facing
// message, signaling that a post-edit failure was rolled back. A CLIError keeps
// its hint and wrapped cause; a plain error is wrapped into a CLIError carrying
// the original as the cause.
func notChangedError(err error) error {
	const suffix = " (the profile was not changed)"
	var ce *CLIError
	if errors.As(err, &ce) {
		return &CLIError{Msg: ce.Msg + suffix, Hint: ce.Hint, Err: ce.Err}
	}
	return &CLIError{Msg: err.Error() + suffix, Err: err}
}

// restoreFailedError reports a post-edit failure whose rollback also failed:
// the profile is now in an unknown state and the backup could not be written.
// It names both problems so the operator can recover by hand. verb names the
// command to re-run (install, remove, upgrade) so the hint stays accurate
// regardless of which profile-writing verb invoked the restore.
func restoreFailedError(profilePath, verb string, postErr, restoreErr error) error {
	return &CLIError{
		Msg: fmt.Sprintf(
			"apply failed (%s) and the profile could not be restored (%s); the profile at %s may be partially edited",
			postErr, restoreErr, profilePath),
		Hint: fmt.Sprintf("inspect the profile and re-run `polypkg %s` once it is correct", verb),
		Err:  errors.Join(postErr, restoreErr),
	}
}

// restoreOnFailure rolls a profile back to its pre-edit bytes after a post-edit
// failure (typically an apply error), choosing the user-facing error to return.
// On a clean restore it wraps applyErr with the not-changed annotation; if the
// restore itself fails it returns a restoreFailedError naming both problems and
// the verb to re-run. It is the shared post-edit rollback seam for the
// profile-writing verbs (install, remove, upgrade): each verb calls it with the
// pre-edit bytes it captured and its own verb name.
func restoreOnFailure(profilePath string, original []byte, applyErr error, verb string) error {
	if rerr := profileedit.Restore(profilePath, original); rerr != nil {
		return restoreFailedError(profilePath, verb, applyErr, rerr)
	}
	return notChangedError(applyErr)
}

// runInstall implements the install command: validate every requested package
// against the catalog under the apply lock, write the profile edits, release
// the lock, then run the apply pipeline. On any post-edit failure the profile
// is restored to its pre-edit bytes.
func runInstall(cmd *cobra.Command, args []string, format Format) error {
	profilePath, err := installProfilePath(cmd)
	if err != nil {
		return err
	}

	// Parse the profile up front so we can read existing constraints and so a
	// malformed profile fails before any catalog work. The profile is also
	// required by resolveScope to honour the profile.scopes.<scope>.prefix
	// precedence tier — parsing before scope resolution ensures the lock and
	// catalog fetch both use the same stateHome that applyProfile will use.
	p, err := parseProfileAt(cmd, profilePath)
	if err != nil {
		return err
	}

	// Resolve scope and prefix through the same path applyProfile uses so that
	// env-sourced or profile-sourced prefixes produce the same stateHome for
	// both the pre-validation lock and the subsequent apply lock.
	scope, prefix, err := resolveScope(cmd, p)
	if err != nil {
		return err
	}
	_, stateHome, err := scopeHomes(scope, prefix)
	if err != nil {
		return err
	}

	// Resolve and validate every request under the apply lock, then write the
	// edits. The lock is released before the apply pipeline re-acquires it.
	edits, original, err := resolveAndEdit(cmd, scope, stateHome, profilePath, p, args)
	if err != nil {
		return err
	}

	// All requested packages already present at their resulting constraint:
	// nothing to apply. Report and exit 0 without running apply.
	if original == nil {
		emitInstallNoApply(cmd, format, edits)
		return nil
	}

	// Edits are written and the catalog lock is released. Run the apply
	// pipeline (which re-acquires the apply lock). On any failure restore the
	// pre-edit profile bytes so install is all-or-nothing.
	out, applyErr := applyProfile(cmd, profilePath, false, false)
	if applyErr != nil {
		return restoreOnFailure(profilePath, original, applyErr, "install")
	}

	emitInstallResult(cmd, format, edits, out)
	return nil
}

// resolveAndEdit validates every requested package against the catalog under
// the apply lock and writes the profile edits. It returns the per-package
// edits, the pre-edit profile bytes (for rollback), and any error. When every
// requested package is already present at its resulting constraint, no edit is
// written and original is returned nil (the caller skips apply).
//
// resolveAndEdit owns only install's catalog-fetch-and-resolve stage: it holds
// the apply lock while fetching the catalog and classifying each request, then
// releases it and delegates the write portion to writeEditsUnderLock (the
// shared lock→edit→release spine). The lock is dropped and re-acquired between
// the two stages; the TOCTOU window is acceptable because applyProfile
// re-fetches and re-verifies the catalog, so a source advancing in that window
// cannot let a bad pin through.
func resolveAndEdit(
	cmd *cobra.Command,
	scope, stateHome, profilePath string,
	p *schema.Profile,
	args []string,
) (edits []installEdit, original []byte, err error) {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	if err := os.MkdirAll(stateHome, scopeDirMode(scope)); err != nil {
		return nil, nil, fmt.Errorf("create state home: %w", err)
	}

	lockPath := filepath.Join(stateHome, "apply.lock")
	l, lerr := lock.Acquire(ctx, lockPath, lock.Options{TxID: "install", Command: "polypkg install"})
	if lerr != nil {
		return nil, nil, lockError(lockPath, lerr)
	}

	fr, fetchErr := planner.FetchCatalog(ctx, p, planner.Options{
		StateHome:         stateHome,
		Scope:             scope,
		ForceCatalogFetch: true,
	})
	if fetchErr != nil {
		_ = l.Release()
		return nil, nil, planExecError(fetchErr)
	}

	edits, err = resolveEdits(scope, p, fr, args)
	if err != nil {
		_ = l.Release()
		return nil, nil, err
	}
	_ = l.Release()

	// If no package needs writing (all kept), skip the edit entirely.
	pending := make([]profileedit.Edit, 0, len(edits))
	for _, e := range edits {
		if e.Action != editKept {
			pending = append(pending, profileedit.Edit{Scope: scope, Name: e.Name, Version: e.Constraint})
		}
	}
	if len(pending) == 0 {
		return edits, nil, nil
	}

	original, aerr := writeEditsUnderLock(cmd, stateHome, profilePath, scope, "install", "polypkg install", pending)
	if aerr != nil {
		return nil, nil, aerr
	}
	return edits, original, nil
}

// resolveEdits resolves every requested package against the catalog and builds
// the install edits, returning a typed CLIError on the first unknown name or
// unsatisfiable constraint (all-or-nothing: the caller writes nothing on error).
func resolveEdits(scope string, p *schema.Profile, fr *planner.FetchResult, args []string) ([]installEdit, error) {
	current := map[string]string{}
	for name, ref := range p.Packages[scope] {
		current[name] = ref.Version
	}

	edits := make([]installEdit, 0, len(args))
	for _, arg := range args {
		name, tail, bare, perr := parsePackageArg(arg)
		if perr != nil {
			return nil, perr
		}

		newest := ""
		if bare {
			if fr.Catalog == nil {
				// No catalog means the profile requests no packages for this scope;
				// a bare name cannot be resolved. Surface a typed unknown-name error.
				return nil, &CLIError{
					Msg:  fmt.Sprintf("package %q is not available from any configured source", name),
					Hint: "check the package name and the sources in your profile",
				}
			}
			cand, nerr := fr.Catalog.Newest(name, "")
			if nerr != nil {
				return nil, planExecError(nerr)
			}
			newest = cand.Version
		} else {
			// Validate the explicit constraint resolves to a concrete version.
			constraint := tail
			if !isConstraintTail(tail) {
				constraint = "=" + tail
			}
			if fr.Catalog == nil {
				return nil, &CLIError{
					Msg:  fmt.Sprintf("package %q is not available from any configured source", name),
					Hint: "check the package name and the sources in your profile",
				}
			}
			if _, nerr := fr.Catalog.Newest(name, constraint); nerr != nil {
				return nil, planExecError(nerr)
			}
		}

		want := constraintForArg(tail, bare, newest)
		old := current[name]
		edits = append(edits, installEdit{
			Name:       name,
			Constraint: want,
			Action:     classifyEdit(old, want),
			Old:        old,
		})
	}
	return edits, nil
}

// installProfilePath resolves the profile install edits: the --profile flag
// (highest precedence, install-family-specific) overrides the scope-default
// discovery resolveProfilePath performs.
//
// When no profile is found, the returned CLIError hints the user to pass
// --profile <path> rather than a positional argument, because install/remove/
// upgrade take package names positionally (not a profile-file).
func installProfilePath(cmd *cobra.Command) (string, error) {
	if cmd.Flags().Changed("profile") {
		v, _ := cmd.Flags().GetString("profile")
		if v != "" {
			return v, nil
		}
	}
	p, err := resolveProfilePath(cmd, nil)
	if err != nil {
		var ce *CLIError
		if errors.As(err, &ce) {
			// Replace the "<command> <profile-file>" positional hint with the
			// flag-based form; package verbs don't accept a profile positional.
			ce.Hint = "run `polypkg init` to create a profile, or pass one with --profile <path>"
		}
		return "", err
	}
	return p, nil
}

// parseProfileAt opens and parses the profile at profilePath, returning the
// shaped open/parse errors.
func parseProfileAt(cmd *cobra.Command, profilePath string) (*schema.Profile, error) {
	f, ferr := openProfileFile(cmd, profilePath)
	if ferr != nil {
		return nil, ferr
	}
	p, perr := schema.ParseProfile(f, profilePath)
	_ = f.Close()
	if perr != nil {
		return nil, perr
	}
	return p, nil
}

// installEditsData builds the JSON data list for the install envelope.
func installEditsData(edits []installEdit) []any {
	list := make([]any, len(edits))
	for i, e := range edits {
		list[i] = map[string]any{
			"name":       e.Name,
			"constraint": e.Constraint,
			"action":     string(e.Action),
		}
	}
	return list
}

// emitInstallNoApply emits the install result when every requested package was
// already present at its resulting constraint and no apply was run.
func emitInstallNoApply(cmd *cobra.Command, format Format, edits []installEdit) {
	data := map[string]any{"edits": installEditsData(edits)}
	EmitResult(cmd, format, "install", data, func(w *bytes.Buffer, _ map[string]any) {
		renderInstallEdits(w, edits)
	})
}

// emitInstallResult emits the install result after a successful apply: the edit
// summary plus the same applied-generation and host-integration data apply
// reports.
func emitInstallResult(cmd *cobra.Command, format Format, edits []installEdit, out *applyOutcome) {
	data := out.data()
	data["edits"] = installEditsData(edits)
	EmitResult(cmd, format, "install", data, func(w *bytes.Buffer, _ map[string]any) {
		renderInstallEdits(w, edits)
		out.renderText(w, nil)
	})
}

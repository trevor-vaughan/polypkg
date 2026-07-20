package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/lock"
	"github.com/trevor-vaughan/polypkg/internal/profileedit"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func newRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "remove <package>...",
		Aliases: []string{"rm", "uninstall"},
		Short:   "Remove packages from the profile and apply",
		Long: `Removes each named package from the profile and applies so the current
generation no longer contains them.

Validation is all-or-nothing: if any requested package is not present in the
profile's scope section, nothing is written.`,
		Args: needsArgs(1, -1, "at least one <package>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "remove", runRemove(cmd, args, format))
		},
	}
	addScopeFlags(cmd)
	cmd.Flags().String("profile", "", "Profile file to edit (overrides scope-default discovery)")
	return cmd
}

// runRemove implements the remove command: validate every requested package
// against the profile (no catalog needed), write the profile edits under the
// apply lock, release the lock, then run the apply pipeline. On any post-edit
// failure the profile is restored to its pre-edit bytes.
func runRemove(cmd *cobra.Command, args []string, format Format) error {
	profilePath, err := installProfilePath(cmd) // reuses the --profile flag logic
	if err != nil {
		return err
	}

	p, err := parseProfileAt(cmd, profilePath)
	if err != nil {
		return err
	}

	scope, prefix, err := resolveScope(cmd, p)
	if err != nil {
		return err
	}
	_, stateHome, err := scopeHomes(scope, prefix)
	if err != nil {
		return err
	}

	// Build the known-names map from the profile before any edit.
	known := profilePackageNames(p, scope)

	// All-or-nothing: validate every name before touching the profile.
	if verr := validateRemoveNames(args, known, scope); verr != nil {
		return verr
	}

	// Build the profileedit.Edit slice: Version="" means remove.
	pending := make([]profileedit.Edit, len(args))
	for i, name := range args {
		pending[i] = profileedit.Edit{Scope: scope, Name: name, Version: ""}
	}

	// Acquire the apply lock, write the edits, release the lock.
	original, err := writeEditsUnderLock(cmd, stateHome, profilePath, scope, "remove", "polypkg remove", pending)
	if err != nil {
		return err
	}

	// Run the apply pipeline. On failure restore the profile.
	out, applyErr := applyProfile(cmd, profilePath, false, false)
	if applyErr != nil {
		return restoreOnFailure(profilePath, original, applyErr, "remove")
	}

	emitRemoveResult(cmd, format, args, out)
	return nil
}

// writeEditsUnderLock acquires the apply lock under stateHome, writes pending
// edits atomically to profilePath, and releases the lock before returning. It
// returns the pre-edit profile bytes so the caller can restore on a later
// failure. txID and command label the lock for the verb invoking it (remove,
// upgrade, install) so a contending operator sees the right holder.
//
// This is the shared lock→edit→release spine for the profile-writing verbs:
// remove and upgrade call it directly; install's resolveAndEdit calls it for
// the write portion after its catalog-fetch stage. Each verb's
// catalog-validation or pre-check logic stays in its own function; only the
// lock lifecycle is shared. The caller is responsible for running applyProfile
// after this returns.
func writeEditsUnderLock(
	cmd *cobra.Command,
	stateHome, profilePath, scope, txID, command string,
	edits []profileedit.Edit,
) (original []byte, err error) {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	if err := os.MkdirAll(stateHome, scopeDirMode(scope)); err != nil {
		return nil, fmt.Errorf("create state home: %w", err)
	}

	lockPath := filepath.Join(stateHome, "apply.lock")
	l, lerr := lock.Acquire(ctx, lockPath, lock.Options{TxID: txID, Command: command})
	if lerr != nil {
		return nil, lockError(lockPath, lerr)
	}
	defer func() { _ = l.Release() }()

	original, aerr := profileedit.Apply(profilePath, edits)
	if aerr != nil {
		return nil, aerr
	}
	return original, nil
}

// profilePackageNames returns a name→constraint copy of the packages map for
// scope from the parsed profile.
func profilePackageNames(p *schema.Profile, scope string) map[string]string {
	result := make(map[string]string, len(p.Packages[scope]))
	for name, ref := range p.Packages[scope] {
		result[name] = ref.Version
	}
	return result
}

// validateRemoveNames returns a CLIError if any name in names is absent from
// known. The check is all-or-nothing: the first missing name terminates early.
func validateRemoveNames(names []string, known map[string]string, scope string) error {
	for _, name := range names {
		if _, ok := known[name]; !ok {
			knownNames := make([]string, 0, len(known))
			for k := range known {
				knownNames = append(knownNames, k)
			}
			sort.Strings(knownNames)
			return &CLIError{
				Msg:  fmt.Sprintf("%s is not in the profile", name),
				Hint: knownPackageHint(knownNames, scope),
			}
		}
	}
	return nil
}

// knownPackageHint builds the hint listing known package names for a
// remove-validation error. Shows up to 10 names sorted with "+N more" when
// the list is longer. Returns the empty-profile message when names is empty.
func knownPackageHint(names []string, scope string) string {
	if len(names) == 0 {
		return fmt.Sprintf("the profile has no packages in scope %s", scope)
	}
	const maxShown = 10
	shown := names
	extra := 0
	if len(names) > maxShown {
		shown = names[:maxShown]
		extra = len(names) - maxShown
	}
	hint := "packages in the profile: " + strings.Join(shown, ", ")
	if extra > 0 {
		hint += fmt.Sprintf(" +%d more", extra)
	}
	return hint
}

// renderRemoveEdits writes one "removing <name>" line per package to w.
func renderRemoveEdits(w *bytes.Buffer, names []string) {
	for _, name := range names {
		fmt.Fprintf(w, "removing %s\n", name)
	}
}

// emitRemoveResult emits the remove result after a successful apply: the
// removing lines plus the same applied-generation and host-integration data
// apply reports.
func emitRemoveResult(cmd *cobra.Command, format Format, names []string, out *applyOutcome) {
	editsData := make([]any, len(names))
	for i, name := range names {
		editsData[i] = map[string]any{"name": name, "action": "remove"}
	}
	data := out.data()
	data["edits"] = editsData
	EmitResult(cmd, format, "remove", data, func(w *bytes.Buffer, _ map[string]any) {
		renderRemoveEdits(w, names)
		out.renderText(w, nil)
	})
}

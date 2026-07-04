package cli

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/lock"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

func newPurgeCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "purge <package>",
		Short: "Delete a package's persistent state (destructive, irreversible)",
		Long: "Deletes the package's stable state directory (the `state` action's data), which " +
			"normally survives apply, generation swaps, GC, and rollback. The package must not be " +
			"present in the current generation: remove it from your profile and apply first.",
		Args: needsArgs(1, 1, "<package>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "purge", runPurge(cmd, args[0], yes, format))
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "Skip the confirmation prompt (required in non-interactive sessions)")
	return cmd
}

var packageNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// validPackageName reports whether pkg matches the package-name grammar
// (mirrors the package manifest's name pattern). Rejects empty, separators,
// and "."/".." so a purge argument cannot traverse out of the state area.
func validPackageName(pkg string) bool {
	return packageNameRe.MatchString(pkg)
}

func runPurge(cmd *cobra.Command, pkg string, yes bool, format Format) error {
	if !validPackageName(pkg) {
		return &CLIError{
			Msg:  fmt.Sprintf("invalid package name %q", pkg),
			Hint: "package names contain only letters, digits, underscores, and dashes",
		}
	}
	ctx := cmd.Context()
	sub, stateHome, err := openUserStore()
	if err != nil {
		return err
	}
	lockPath := filepath.Join(stateHome, "apply.lock")
	l, err := lock.Acquire(ctx, lockPath,
		lock.Options{TxID: "purge", Command: "polypkg purge"})
	if err != nil {
		return lockError(lockPath, err)
	}
	defer func() { _ = l.Release() }()

	prior, _, _, err := sub.CurrentOwnership()
	switch {
	case errors.Is(err, substrate.ErrNoCurrentGeneration):
		// No active generation: nothing can be active; proceed.
	case err != nil:
		return fmt.Errorf("load current ownership: %w", err)
	default:
		if aerr := ensureNotActive(prior, pkg); aerr != nil {
			return aerr
		}
	}

	if !yes {
		if !isInteractive(cmd) {
			return &CLIError{
				Msg:  "purge needs confirmation but stdin is not a terminal",
				Hint: "re-run with --yes to confirm non-interactively",
			}
		}
		ok, cerr := confirmPurge(cmd.InOrStdin(), cmd.OutOrStdout(), pkg)
		if cerr != nil {
			return cerr
		}
		if !ok {
			return &CLIError{Msg: "purge aborted (answer was not yes)"}
		}
	}

	if err := sub.PurgeState(pkg); err != nil {
		return err
	}
	EmitResult(cmd, format, "purge", map[string]any{"package": pkg},
		func(w *bytes.Buffer, d map[string]any) {
			fmt.Fprintf(w, "purged persistent state for %s\n", d["package"])
		})
	return nil
}

// ensureNotActive returns an error if pkg owns any entry in the current
// generation's ownership index (its artifacts are still live).
func ensureNotActive(prior *schema.Ownership, pkg string) error {
	if prior == nil {
		return nil
	}
	for i := range prior.Entries {
		if prior.Entries[i].Package == pkg {
			return &CLIError{
				Msg:  fmt.Sprintf("package %q is still active in the current generation", pkg),
				Hint: "remove it from your profile and run `polypkg apply`, then purge",
			}
		}
	}
	return nil
}

// confirmPurge prompts on out and reads a y/N answer from in. Only "y"/"Y"
// confirms. Extracted for direct testing (TTY is unavailable under test).
func confirmPurge(in io.Reader, out io.Writer, pkg string) (bool, error) {
	fmt.Fprintf(out, "Permanently delete all persistent state for %s?\nThis cannot be undone.\nProceed? [y/N]: ", pkg)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	line = strings.TrimSpace(line)
	return line == "y" || line == "Y", nil
}

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/alternatives"
	"github.com/trevor-vaughan/polypkg/internal/lock"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

func newRollbackCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Rollback to the previous generation",
		Long: `Each time polypkg apply runs it creates a generation: an immutable snapshot of
the packages and links active at that moment. rollback activates a previous
generation without running apply again, making that snapshot the current state.

With no arguments, rollback activates the newest complete generation older
than the current one. A generation that an interrupted apply left incomplete
(it has no manifest) is skipped, and --to refuses one. So is a generation
whose manifest is damaged (corruption or tampering), with a warning. Use --to
to target a specific generation by id. Run 'polypkg status -v' to list the
generation ids retained in the store and choose one.

After rollback, alternatives and host-integration links (bin, completions,
desktop entries, MIME types) are reconciled to match the activated generation.`,
		Example: "  # Roll back to the generation before the current one\n" +
			"  polypkg rollback\n\n" +
			"  # List retained generations, then roll back to a specific one\n" +
			"  polypkg status -v\n" +
			"  polypkg rollback --to 3",
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "rollback", runRollback(cmd, format))
		},
	}
	cmd.Flags().Int("to", 0, "Generation id to roll back to (see 'polypkg status -v' for the list)")
	_ = cmd.RegisterFlagCompletionFunc("to", completeGenerations)
	return cmd
}

func runRollback(cmd *cobra.Command, format Format) error {
	to, _ := cmd.Flags().GetInt("to")
	dataHome, stateHome, err := scopeHomes("user", "")
	if err != nil {
		return err
	}
	sub, err := substrate.New("store", dataHome)
	if err != nil {
		return fmt.Errorf("open substrate: %w", err)
	}
	genDir := func(id int) string { return filepath.Join(dataHome, "generations", strconv.Itoa(id)) }
	lockPath := filepath.Join(stateHome, "apply.lock")
	l, err := lock.Acquire(cmd.Context(), lockPath,
		lock.Options{TxID: "rollback", Command: "polypkg rollback"})
	if err != nil {
		return lockError(lockPath, err)
	}
	defer func() { _ = l.Release() }()

	current, err := sub.CurrentGeneration()
	if err != nil {
		if errors.Is(err, substrate.ErrNoCurrentGeneration) || errors.Is(err, fs.ErrNotExist) {
			return &CLIError{
				Msg:  "nothing to roll back: no generation has been applied yet",
				Hint: "run `polypkg apply` first",
				Err:  err,
			}
		}
		return fmt.Errorf("read current: %w", err)
	}
	target := to
	if target == 0 {
		// Walk newest-first below current and stop at the first complete
		// generation, reading only the manifests needed (ListGenerations would
		// also parse every other manifest and size every generation).
		ids, lerr := sub.GenerationIDs()
		if lerr != nil {
			return fmt.Errorf("list generations: %w", lerr)
		}
		sort.Sort(sort.Reverse(sort.IntSlice(ids)))
		for _, id := range ids {
			if id >= current {
				continue
			}
			_, merr := sub.ReadManifest(id)
			switch {
			case merr == nil:
				target = id
			case errors.Is(merr, substrate.ErrIncompleteGeneration):
				continue
			case errors.Is(merr, substrate.ErrDamagedGeneration):
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: skipping generation %d: its manifest is damaged; inspect %s\n", id, genDir(id))
				continue
			default:
				return generationManifestError(id, genDir(id), "activated", merr)
			}
			break
		}
		if target == 0 && current > 1 {
			return &CLIError{
				Msg:  fmt.Sprintf("nothing to roll back: no complete generation older than generation %d is retained", current),
				Hint: "run `polypkg status -v` to list retained generations",
			}
		}
	}
	if target < 1 {
		return &CLIError{
			Msg:  "nothing to roll back: this is the first generation",
			Hint: "run `polypkg status -v` to list retained generations",
		}
	}
	if to != 0 {
		// Check an explicit target here rather than only through sub.Rollback,
		// whose error cannot tell a manifest read failure from a failed swap.
		if _, serr := os.Stat(genDir(target)); serr != nil {
			if errors.Is(serr, fs.ErrNotExist) {
				return &CLIError{
					Msg:  fmt.Sprintf("generation %d does not exist", target),
					Hint: "run `polypkg status -v` to list retained generations",
					Err:  serr,
				}
			}
			return fmt.Errorf("target generation %d: %w", target, serr)
		}
		if _, merr := sub.ReadManifest(target); merr != nil {
			return generationManifestError(target, genDir(target), "activated", merr)
		}
	}
	if err := sub.Rollback(target); err != nil {
		// The checks above ran under the apply lock, so only a change made
		// outside polypkg can still land here.
		if errors.Is(err, substrate.ErrIncompleteGeneration) || errors.Is(err, substrate.ErrDamagedGeneration) {
			return generationManifestError(target, genDir(target), "activated", err)
		}
		if errors.Is(err, fs.ErrNotExist) {
			return &CLIError{
				Msg:  fmt.Sprintf("generation %d does not exist", target),
				Hint: "run `polypkg status -v` to list retained generations",
				Err:  err,
			}
		}
		return err
	}
	// Rollback only repoints the active symlink; it does not re-run actions. The
	// alternatives middle links are non-generational, so reconcile them to the
	// now-active (rolled-back) generation, honoring any operator selections,
	// or bin/<name> could resolve to a provider that generation does not contain.
	own, _, _, oerr := sub.CurrentOwnership()
	if oerr != nil {
		return fmt.Errorf("rollback to generation %d succeeded but reading its ownership failed: %w", target, oerr)
	}
	stale, merr := alternatives.Reconcile(sub.AltRoot(),
		alternatives.SelectionsPath(sub.StateRoot()), own.Entries)
	if merr != nil {
		return fmt.Errorf("rollback to generation %d succeeded but reconciling alternatives failed (re-run apply or rollback to reconcile): %w", target, merr)
	}
	for _, name := range stale {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: manual alternatives selection for %q is no longer provided; reverted to auto\n", name)
	}
	// Reconcile ~/.local/bin to the rolled-back generation's command set (best
	// effort; the swap already committed, so a bridge failure is not fatal).
	bridgeRes, binDir, bridged := runBridgeReconcile(sub, "user", "")
	compRes, compDirs, comped := runCompletionReconcile(sub, "user", "")
	deskRes, deskDir, desked := runDesktopReconcile(sub, "user", "")
	mimeRes, mimeDir, mimed := runMimeReconcile(sub, "user", "")
	data := map[string]any{"target": target}
	if bridged {
		data["bridge"] = map[string]any{
			"linked": bridgeRes.Linked, "pruned": bridgeRes.Pruned, "skipped": skippedNames(bridgeRes),
		}
	}
	if comped {
		data["completion"] = completionResultData(compRes)
	}
	if desked {
		data["desktop"] = map[string]any{
			"linked": deskRes.Linked, "pruned": deskRes.Pruned, "skipped": skippedNames(deskRes),
		}
	}
	if mimed {
		data["mime"] = map[string]any{
			"linked": mimeRes.Linked, "pruned": mimeRes.Pruned, "skipped": skippedNames(mimeRes),
		}
	}
	manNudge := manFollowersPresent(sub)
	if manNudge {
		data["manpath"] = sub.ActiveManDir()
	}
	EmitResult(cmd, format, "rollback", data, func(w *bytes.Buffer, d map[string]any) {
		fmt.Fprintf(w, "rolled back to generation %d\n", d["target"])
		if bridged {
			writeBridgeSummary(w, bridgeRes, binDir)
		}
		if comped {
			writeCompletionSummary(w, compRes, compDirs)
		}
		if desked {
			writeDesktopSummary(w, deskRes, deskDir)
		}
		if mimed {
			writeMimeSummary(w, mimeRes, mimeDir)
		}
		if manNudge {
			fmt.Fprintln(w, manNudgeLine(sub.ActiveManDir()))
		}
	})
	return nil
}

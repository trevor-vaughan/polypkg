package cli

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/audit"
	"github.com/trevor-vaughan/polypkg/internal/extractstore"
	"github.com/trevor-vaughan/polypkg/internal/gc"
	"github.com/trevor-vaughan/polypkg/internal/lock"
	"github.com/trevor-vaughan/polypkg/internal/paths"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

// sweepExtracts removes extract-store dirs no retained generation references.
// It is fail-open: if any retained manifest cannot be read, the sweep is
// skipped entirely — deleting a dir a generation still symlinks through would
// recreate exactly the integrity bug the content-addressed store fixed. Both
// layouts are kept per entry: the content-addressed dir and the legacy
// name-version dir that generations committed by older binaries resolve
// through. Entries younger than extractstore.DefaultMinAge are always kept
// (see that constant for the in-flight-apply race this defends against).
// Callers hold the apply lock (gc) or run just after a successful apply
// released it.
func sweepExtracts(sub substrate.Substrate, stateHome string, stderr io.Writer) int {
	gens, err := sub.ListGenerations()
	if err != nil {
		fmt.Fprintf(stderr, "warn: extract sweep skipped: %v\n", err)
		return 0
	}
	keep := map[string]bool{}
	for _, g := range gens {
		m, err := sub.ReadManifest(g.ID)
		if err != nil {
			fmt.Fprintf(stderr, "warn: extract sweep skipped: generation %d: %v\n", g.ID, err)
			return 0
		}
		for i := range m.Entries {
			e := &m.Entries[i]
			keep[extractstore.DirName(e.Name, e.Version, e.ContentHash)] = true
			keep[extractstore.LegacyDirName(e.Name, e.Version)] = true
		}
	}
	removed, err := extractstore.Sweep(stateHome, keep, extractstore.DefaultMinAge)
	if err != nil {
		fmt.Fprintf(stderr, "warn: extract sweep incomplete: %v\n", err)
	}
	return removed
}

// newGCCmd is the standalone `polypkg gc` command. Defaults match the
// user-scope retention defaults from apply-semantics §4.3 (5 generations,
// 30 days). --force-pin <id> may be specified multiple times to unpin and
// then evict otherwise-pinned generations in the same pass.
func newGCCmd() *cobra.Command {
	var (
		count     int
		ageStr    string
		forcePins []int
	)
	cmd := &cobra.Command{
		Use:   "gc",
		Short: "Run garbage collection over the generation store",
		Long: `Each time polypkg apply runs it creates an immutable generation: a snapshot
of the packages and links active at that moment. Over time these accumulate and
consume disk space. gc removes old generations to reclaim that space.

The retention policy has two parameters. --count sets the minimum number of
newest generations to keep, so there is always something to roll back to.
--age keeps any generation committed within that window regardless of count,
which is useful for preserving recent history even when many applies have run.
Both parameters apply simultaneously; a generation is only removed when it
falls outside both.

Pinned generations (see 'polypkg generation pin') are never removed by gc,
even if they fall outside the retention window. To remove a pinned generation
in the same pass, use --force-pin with its id.

Run 'polypkg status' first to preview exactly which generations gc would
remove before committing to a collection pass.`,
		Example: "  # Preview what gc would remove\n" +
			"  polypkg status\n\n" +
			"  # Run gc with the default policy (keep the newest 5, and anything under 30 days)\n" +
			"  polypkg gc\n\n" +
			"  # Keep more history\n" +
			"  polypkg gc --count 10 --age 90d\n\n" +
			"  # Remove the pin on generation 3, then collect\n" +
			"  polypkg gc --force-pin 3",
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			age, err := gc.ParseAge(ageStr)
			if err != nil {
				return WrapError(cmd, format, "gc", &CLIError{
					Msg:  fmt.Sprintf("invalid --age %q", ageStr),
					Hint: "accepted forms: 30d, 2w, 12h, 30m (d=days, w=weeks, h/m/s from time.ParseDuration)",
					Err:  err,
				})
			}
			policy := gc.Policy{Count: count, Age: age}
			if err := policy.Validate(); err != nil {
				return WrapError(cmd, format, "gc", &CLIError{
					Msg:  err.Error(),
					Hint: "use --count N (N >= 1) to keep N generations, or --age to prune by age",
					Err:  err,
				})
			}
			return WrapError(cmd, format, "gc", runGC(cmd, policy, forcePins, format))
		},
	}
	cmd.Flags().IntVar(&count, "count", 5, "Always keep at least this many of the newest generations")
	cmd.Flags().StringVar(&ageStr, "age", "30d", "Retain generations within this window (e.g. 30d, 2w, 12h)")
	cmd.Flags().IntSliceVar(&forcePins, "force-pin", nil, "Remove the pin on these generation ids before collecting (repeatable)")
	return cmd
}

func runGC(cmd *cobra.Command, policy gc.Policy, forcePins []int, format Format) error {
	ctx := cmd.Context()
	dataHome, err := paths.UserDataHome()
	if err != nil {
		return err
	}
	stateHome, err := paths.UserStateHome()
	if err != nil {
		return err
	}
	sub, err := substrate.New("store", dataHome)
	if err != nil {
		return fmt.Errorf("open substrate: %w", err)
	}
	lockPath := filepath.Join(stateHome, "apply.lock")
	l, err := lock.Acquire(ctx, lockPath,
		lock.Options{TxID: "gc", Command: "polypkg gc"})
	if err != nil {
		return lockError(lockPath, err)
	}
	defer func() { _ = l.Release() }()

	w, err := audit.NewFileWriter(filepath.Join(stateHome, "audit.log"))
	if err != nil {
		return fmt.Errorf("open audit writer: %w", err)
	}
	defer func() { _ = w.Close() }()

	for _, id := range forcePins {
		if err := sub.UnpinGeneration(id); err != nil {
			return fmt.Errorf("--force-pin %d: %w", id, err)
		}
	}

	gens, err := sub.ListGenerations()
	if err != nil {
		return fmt.Errorf("list generations: %w", err)
	}
	algGens := make([]gc.Generation, 0, len(gens))
	pinnedCount := 0
	byID := map[int]substrate.GenInfo{}
	for _, g := range gens {
		algGens = append(algGens, gc.Generation{
			ID: g.ID, CommittedAt: g.CommittedAt, Pinned: g.Pinned, IsCurrent: g.IsCurrent,
		})
		if g.Pinned {
			pinnedCount++
		}
		byID[g.ID] = g
	}
	dec := gc.Decide(algGens, policy, time.Now())

	removed, failed, bytesReclaimed := 0, 0, int64(0)
	for _, id := range dec.Remove {
		if err := sub.RemoveGeneration(id); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warn: remove generation %d: %v\n", id, err)
			failed++
			continue
		}
		removed++
		bytesReclaimed += byID[id].BytesOnDisk
	}
	extractsRemoved := sweepExtracts(sub, stateHome, cmd.ErrOrStderr())
	_ = w.Write(audit.Event{
		Scope: "user", TxID: "gc", Event: "gc.run",
		Fields: map[string]any{
			"trigger":                    "explicit",
			"generations_removed":        removed,
			"generations_remove_failed":  failed,
			"generations_skipped_pinned": pinnedCount,
			"bytes_reclaimed":            bytesReclaimed,
			"extract_dirs_removed":       extractsRemoved,
		},
	})
	if removed == 0 && failed > 0 {
		return &CLIError{
			Msg:  fmt.Sprintf("gc: %d removal(s) failed and none succeeded", failed),
			Hint: "failed generations are listed above; check permissions under the generations directory",
		}
	}
	ageStr, _ := cmd.Flags().GetString("age")
	EmitResult(cmd, format, "gc", map[string]any{
		"removed":              removed,
		"failed":               failed,
		"bytes_reclaimed":      bytesReclaimed,
		"extract_dirs_removed": extractsRemoved,
		"kept_by_age":          len(dec.KeptByAge),
	}, func(w *bytes.Buffer, d map[string]any) {
		fmt.Fprintf(w, "gc: removed %d, failed %d, bytes reclaimed %d\n", d["removed"], d["failed"], d["bytes_reclaimed"])
		if n, ok := d["extract_dirs_removed"].(int); ok && n > 0 {
			fmt.Fprintf(w, "gc: swept %d stale extract dir(s)\n", n)
		}
		// A run that reclaimed nothing is otherwise indistinguishable from a
		// broken one. Both retention predicates apply at once, so an explicit
		// --count is routinely overruled by the default --age window; name the
		// generations that held and the flag that releases them.
		if removed == 0 && len(dec.KeptByAge) > 0 {
			fmt.Fprintf(w, "gc: kept %d generation(s) inside --age %s that --count %d alone would have removed; pass --age 0 to collect by count alone\n",
				len(dec.KeptByAge), ageStr, policy.Count)
		}
	})
	return nil
}

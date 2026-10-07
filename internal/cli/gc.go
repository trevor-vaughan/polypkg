package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/audit"
	"github.com/trevor-vaughan/polypkg/internal/extractstore"
	"github.com/trevor-vaughan/polypkg/internal/gc"
	"github.com/trevor-vaughan/polypkg/internal/lock"
	"github.com/trevor-vaughan/polypkg/internal/paths"
	"github.com/trevor-vaughan/polypkg/internal/source"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

// storeSweep names what one sweepStores pass removed. Both lists are non-nil
// so the JSON envelope renders [] rather than null.
type storeSweep struct {
	extractDirs    []string // extract-store basenames
	cacheArtifacts []string // "<source>/<file>" under source.CacheRoot
}

// sweepStores removes extract-store dirs and cached downloads that no
// retained generation references. Retained means every generation still on
// disk after generation GC, so pinned and age-retained ones count.
//
// It is fail-safe: deleting a dir a generation still symlinks through would
// recreate exactly the integrity bug the content-addressed store fixed, so
// the sweep runs only when it knows every reference. The same rules govern
// both stores, because the manifest is the only record of either.
//   - A generation with no manifest (incomplete) is skipped: it records no
//     references, can never be activated, and gc removes it. The exception is
//     the current generation: it is live, its payload may symlink into any
//     dir, and nothing records which, so the sweep stops and keeps everything.
//     A concurrent apply's not-yet-committed generation looks the same; the
//     dirs and downloads it uses were created or reused within
//     extractstore.DefaultMinAge, which the sweep never removes.
//   - A generation whose manifest is damaged stops the sweep, keeping every
//     extract dir and cached download. Its references cannot be known: the
//     manifest is their only record. It may be the current generation, its
//     files may be evidence of what was installed, and its payload may be
//     tampered with too, so walking it is no substitute. The cost is disk
//     space until an operator deals with it.
//   - Any other manifest read failure also stops the sweep.
//
// Extract dirs keep both layouts per entry: the content-addressed dir and the
// legacy name-version dir that generations committed by older binaries
// resolve through. The download cache is keyed by base name
// (source.NativeBackend.Fetch): an entry keeps path.Base(SourceURL) and each
// attestation it records keeps <hex>.att.json. Entries younger than
// extractstore.DefaultMinAge are always kept in both stores (see that
// constant for the in-flight-apply race this defends against). Callers hold
// the apply lock (gc) or run just after a successful apply released it.
func sweepStores(sub substrate.Substrate, stateHome string, stderr io.Writer) storeSweep {
	out := storeSweep{extractDirs: []string{}, cacheArtifacts: []string{}}
	gens, err := sub.ListGenerations()
	if err != nil {
		fmt.Fprintf(stderr, "warn: store sweep skipped: %v\n", err)
		return out
	}
	for _, g := range gens {
		if g.Incomplete && g.IsCurrent {
			fmt.Fprintf(stderr, "warn: store sweep skipped: the current generation %d has no manifest, so what it references is unknown\n", g.ID)
			return out
		}
		if g.Damaged {
			fmt.Fprintf(stderr, "warn: store sweep skipped, keeping every extract dir and cached download: generation %d's manifest is damaged, so what it references is unknown\n", g.ID)
			return out
		}
	}
	keepExtract := map[string]bool{}
	// keepCache is not per-source: a base name any retained entry records is
	// kept in every source's cache, which errs toward keeping. Only the
	// attestation hashes a manifest records are kept; any other cached
	// .att.json (e.g. a package's second native ref) may be pruned after the
	// grace period and is re-fetched and re-verified on the next plan, which
	// always needs the network for the index anyway.
	keepCache := map[string]bool{}
	for _, g := range gens {
		if g.Incomplete {
			continue
		}
		m, err := sub.ReadManifest(g.ID)
		if errors.Is(err, substrate.ErrIncompleteGeneration) {
			continue
		}
		if err != nil {
			fmt.Fprintf(stderr, "warn: store sweep skipped: generation %d: %v\n", g.ID, err)
			return out
		}
		for i := range m.Entries {
			e := &m.Entries[i]
			keepExtract[extractstore.DirName(e.Name, e.Version, e.ContentHash)] = true
			keepExtract[extractstore.LegacyDirName(e.Name, e.Version)] = true
			if e.SourceURL != "" {
				keepCache[path.Base(e.SourceURL)] = true
			}
			if a := e.Attestation; a != nil {
				if a.AttestationHash != "" {
					keepCache[strings.TrimPrefix(a.AttestationHash, "blake3:")+".att.json"] = true
				}
				for j := range a.CarriedBindings {
					if h := a.CarriedBindings[j].AttestationHash; h != "" {
						keepCache[strings.TrimPrefix(h, "blake3:")+".att.json"] = true
					}
				}
			}
		}
	}
	if out.extractDirs, err = extractstore.Sweep(stateHome, keepExtract, extractstore.DefaultMinAge); err != nil {
		fmt.Fprintf(stderr, "warn: extract sweep incomplete: %v\n", err)
	}
	if out.cacheArtifacts, err = source.SweepArtifactCache(stateHome, keepCache, extractstore.DefaultMinAge); err != nil {
		fmt.Fprintf(stderr, "warn: artifact cache sweep incomplete: %v\n", err)
	}
	return out
}

// prunedListLimit caps how many pruned names gc's text output lists per
// store; --format json always carries the full list.
const prunedListLimit = 20

// writePrunedList writes names one per line, indented, stopping after
// prunedListLimit with a line counting the rest.
func writePrunedList(w *bytes.Buffer, names []string) {
	for i, name := range names {
		if i == prunedListLimit {
			fmt.Fprintf(w, "  …and %d more (use --format json for the full list)\n", len(names)-prunedListLimit)
			return
		}
		fmt.Fprintf(w, "  %s\n", name)
	}
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
consume disk space. gc removes old generations to reclaim that space, then
prunes the extracted packages and cached downloads that no remaining
generation uses (anything touched in the last hour is kept for a concurrent
apply), and lists what it pruned.

The retention policy has two parameters. --count sets the minimum number of
newest generations to keep, so there is always something to roll back to.
--age keeps any generation committed within that window regardless of count,
which is useful for preserving recent history even when many applies have run.
Both parameters apply simultaneously; a generation is only removed when it
falls outside both.

A generation that an interrupted apply left incomplete (it has no manifest)
can never be activated, so gc removes it regardless of --count and --age
unless it is the current generation or pinned.

A generation whose manifest is present but damaged (it does not parse, or names
another generation) was corrupted or tampered with; a crash cannot cause that.
gc never removes it and names it in its output, so a person can inspect it and
delete it by hand if it is not needed as evidence.

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
	damaged := []int{}
	byID := map[int]substrate.GenInfo{}
	for _, g := range gens {
		if g.Damaged {
			damaged = append(damaged, g.ID)
		}
		algGens = append(algGens, gc.Generation{
			ID: g.ID, CommittedAt: g.CommittedAt, Pinned: g.Pinned, IsCurrent: g.IsCurrent,
			Incomplete: g.Incomplete, Damaged: g.Damaged,
		})
		if g.Pinned {
			pinnedCount++
		}
		byID[g.ID] = g
	}
	sort.Ints(damaged)
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
	sweep := sweepStores(sub, stateHome, cmd.ErrOrStderr())
	_ = w.Write(audit.Event{
		Scope: "user", TxID: "gc", Event: "gc.run",
		Fields: map[string]any{
			"trigger":                    "explicit",
			"generations_removed":        removed,
			"generations_remove_failed":  failed,
			"generations_skipped_pinned": pinnedCount,
			"bytes_reclaimed":            bytesReclaimed,
			"extract_dirs_removed":       len(sweep.extractDirs),
			"cache_artifacts_removed":    len(sweep.cacheArtifacts),
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
		"removed":                 removed,
		"failed":                  failed,
		"bytes_reclaimed":         bytesReclaimed,
		"extract_dirs_removed":    len(sweep.extractDirs),
		"extract_dirs_pruned":     sweep.extractDirs,
		"cache_artifacts_removed": len(sweep.cacheArtifacts),
		"cache_artifacts_pruned":  sweep.cacheArtifacts,
		"kept_by_age":             len(dec.KeptByAge),
		"damaged":                 damaged,
	}, func(w *bytes.Buffer, d map[string]any) {
		fmt.Fprintf(w, "gc: removed %d, failed %d, bytes reclaimed %d\n", d["removed"], d["failed"], d["bytes_reclaimed"])
		if n := len(sweep.extractDirs); n > 0 {
			fmt.Fprintf(w, "gc: swept %d stale extract dir(s)\n", n)
			writePrunedList(w, sweep.extractDirs)
		}
		if n := len(sweep.cacheArtifacts); n > 0 {
			fmt.Fprintf(w, "gc: pruned %d cached artifact(s)\n", n)
			writePrunedList(w, sweep.cacheArtifacts)
		}
		// A run that reclaimed nothing is otherwise indistinguishable from a
		// broken one. Both retention predicates apply at once, so an explicit
		// --count is routinely overruled by the default --age window; name the
		// generations that held and the flag that releases them.
		if removed == 0 && len(dec.KeptByAge) > 0 {
			fmt.Fprintf(w, "gc: kept %d generation(s) inside --age %s that --count %d alone would have removed; pass --age 0 to collect by count alone\n",
				len(dec.KeptByAge), ageStr, policy.Count)
		}
		// A damaged manifest means corruption or tampering, never a crash, so
		// gc keeps the generation as evidence and leaves the call to a person.
		for _, id := range damaged {
			fmt.Fprintf(w, "gc: generation %d's manifest is damaged; inspect %s, then delete it by hand if it is not needed as evidence\n",
				id, filepath.Join(dataHome, "generations", strconv.Itoa(id)))
		}
	})
	return nil
}

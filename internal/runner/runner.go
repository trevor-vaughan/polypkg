// Package runner coordinates polypkg transactions: lock, transaction
// begin, action dispatch, manifest commit, audit log, lock release.
package runner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/trevor-vaughan/polypkg/internal/action"
	"github.com/trevor-vaughan/polypkg/internal/alternatives"
	"github.com/trevor-vaughan/polypkg/internal/audit"
	"github.com/trevor-vaughan/polypkg/internal/conflict"
	"github.com/trevor-vaughan/polypkg/internal/drift"
	"github.com/trevor-vaughan/polypkg/internal/gc"
	"github.com/trevor-vaughan/polypkg/internal/lock"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/starlarkeval"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

// Options configures a Runner.
type Options struct {
	Substrate         substrate.Substrate
	AuditWriter       audit.Writer
	LockPath          string
	Scope             string
	DirMode           os.FileMode // dir-creation mode for action scopes; 0 => 0o700
	StarlarkLimits    starlarkeval.Limits
	HealDrift         bool
	NoDriftCheck      bool
	AcceptedDriftPath string     // path to accepted-drift.json; "" disables accept-drift
	ResetsPath        string     // path to pending-resets.json; "" disables reset consumption
	GCPolicy          *gc.Policy // nil disables opportunistic GC
	// Progress is an optional callback for live phase updates. Called at
	// phase loop boundaries. Nil disables all callbacks.
	Progress func(stage, detail string)
}

// progress calls opts.Progress when it is non-nil.
func (o Options) progress(stage, detail string) {
	if o.Progress != nil {
		o.Progress(stage, detail)
	}
}

// RunEntry is one package the runner should dispatch actions for.
type RunEntry struct {
	Package *schema.Package
	PkgRoot string // path to extracted package directory
}

// Runner orchestrates one apply transaction at a time.
type Runner struct {
	opts Options
}

// New constructs a Runner.
func New(opts Options) *Runner {
	return &Runner{opts: opts}
}

// Run dispatches actions for every entry in phase order, then commits the
// manifest. apply.start is a hard error (fail-closed: never begin a
// transaction we cannot audit). apply.complete is a best-effort warning
// post-swap — the generation is already active so we return (gen, nil)
// regardless. Pre-swap phase failures abort and record apply.failed.
// Post-swap phase failures record service.warning only (no abort).
func (r *Runner) Run(ctx context.Context, m *schema.Manifest, entries []RunEntry) (int, error) {
	txID := "tx-" + uuid.NewString()
	start := time.Now()

	l, err := lock.Acquire(ctx, r.opts.LockPath, lock.Options{TxID: txID, Command: "polypkg apply"})
	if err != nil {
		return 0, fmt.Errorf("acquire lock: %w", err)
	}
	defer func() { _ = l.Release() }()

	// Drift detection runs under the lock and BEFORE apply.start, so a refused
	// apply has zero side effects — no transaction, no swap, no orphaned start
	// event in the audit log. (apply-semantics §5.3 step 4.)
	st, err := r.checkDrift(txID)
	if err != nil {
		return 0, err
	}
	driftHealed := st.healed

	resetSet, resets, err := r.loadResets()
	if err != nil {
		_ = r.audit(audit.Event{
			Scope: r.opts.Scope, TxID: txID, Event: "apply.failed",
			Fields: map[string]any{"error": err.Error(), "stage": "pending-resets"},
		})
		return 0, err
	}

	// Pre-commit audit is a hard error: fail-closed so we never apply without
	// a written start record.
	if err := r.audit(audit.Event{
		Scope: r.opts.Scope, TxID: txID, Event: "apply.start",
		Fields: map[string]any{"manifest_schema": m.Schema, "entry_count": len(entries)},
	}); err != nil {
		return 0, fmt.Errorf("audit start: %w", err)
	}

	if err := r.opts.Substrate.BeginTransaction(txID); err != nil {
		_ = r.audit(audit.Event{
			Scope: r.opts.Scope, TxID: txID, Event: "apply.failed",
			Fields: map[string]any{"error": err.Error(), "stage": "begin"},
		})
		return 0, fmt.Errorf("begin transaction: %w", err)
	}

	activeRoot, err := r.opts.Substrate.StagingRoot(txID)
	if err != nil {
		_ = r.opts.Substrate.Abort(txID)
		_ = r.audit(audit.Event{Scope: r.opts.Scope, TxID: txID, Event: "apply.failed",
			Fields: map[string]any{"error": err.Error(), "stage": "staging-root"}})
		return 0, fmt.Errorf("staging root: %w", err)
	}

	ev := starlarkeval.NewEvaluator(r.opts.StarlarkLimits)

	own := &schema.Ownership{Schema: "polypkg.ownership/v1", Scope: r.opts.Scope, Entries: []schema.OwnershipEntry{}}
	configBases := map[string][]byte{}
	var pendingWarnings []action.ConfigWarning
	var appliedResets []string

	// Pre-swap phases: a failure aborts the transaction.
	for _, phase := range []string{"pre-place", "post-place", "pre-activate"} {
		for i, e := range entries {
			r.opts.progress("placing", fmt.Sprintf("%s %d/%d", phase, i+1, len(entries)))
			scope := action.Scope{
				ActiveRoot:  activeRoot,
				LiveRoot:    st.liveRoot,
				PriorGenDir: st.priorGenDir,
				StateRoot:   r.opts.Substrate.StateRoot(),
				AltRoot:     r.opts.Substrate.AltRoot(),
				PackageName: e.Package.Name,
				DirMode:     r.opts.DirMode,
			}
			out, err := DispatchActions(ctx, e.Package, e.PkgRoot, scope, phase, ev, st.preserveActions, st.prior, resetSet)
			if err != nil {
				_ = r.opts.Substrate.Abort(txID)
				_ = r.audit(audit.Event{
					Scope: r.opts.Scope, TxID: txID, Event: "apply.failed",
					Fields: map[string]any{"error": err.Error(), "stage": phase, "pkg": e.Package.Name},
				})
				return 0, fmt.Errorf("phase %s pkg %s: %w", phase, e.Package.Name, err)
			}
			own.Entries = append(own.Entries, out.Entries...)
			maps.Copy(configBases, out.ConfigBases)
			pendingWarnings = append(pendingWarnings, out.Warnings...)
			appliedResets = append(appliedResets, out.ResetPaths...)
		}
	}

	// Shared-path conflict check: runs after all pre-swap entries are assembled
	// and before the irreversible commit/swap, so a refused apply leaves the
	// prior active generation fully intact. The path action places shared
	// bin/<name> symlinks outside the per-package namespace, so two packages
	// can claim the same path; refuse rather than let one silently clobber the
	// other.
	if conflicts := conflict.Detect(own.Entries); len(conflicts) > 0 {
		summary := conflict.Summary(conflicts)
		_ = r.opts.Substrate.Abort(txID)
		_ = r.audit(audit.Event{
			Scope: r.opts.Scope, TxID: txID, Event: "apply.failed",
			Fields: map[string]any{"error": summary, "stage": "conflict"},
		})
		return 0, fmt.Errorf("apply refused: shared-path conflict: %s; give the commands distinct names, or expose the command via the alternatives action (priority-arbitrated) instead of path", summary)
	}

	// Reconcile the alternatives middle links (selection-aware) in the stable
	// area before the commit/swap. The conflict check above guarantees no
	// path/mixed conflict among these entries; Reconcile selects the per-name
	// winner (operator selection overrides priority) and writes the middle
	// links so the constant consumer links resolve the instant the swap lands.
	// A stale selection (chosen provider no longer present) is dropped and the
	// name falls back to auto, with a warning. A failure aborts like conflict.
	stale, merr := alternatives.Reconcile(r.opts.Substrate.AltRoot(),
		alternatives.SelectionsPath(r.opts.Substrate.StateRoot()), own.Entries)
	if merr != nil {
		_ = r.opts.Substrate.Abort(txID)
		_ = r.audit(audit.Event{
			Scope: r.opts.Scope, TxID: txID, Event: "apply.failed",
			Fields: map[string]any{"error": merr.Error(), "stage": "alternatives"},
		})
		return 0, fmt.Errorf("apply failed: materialize alternatives: %w", merr)
	}
	for _, name := range stale {
		slog.Warn("manual alternatives selection no longer provided; reverted to auto", "name", name)
	}

	r.opts.progress("committing", "")
	gen, err := r.opts.Substrate.CommitGeneration(txID, m, own, configBases)
	if err != nil {
		_ = r.opts.Substrate.Abort(txID)
		// The pre-swap alternatives.Reconcile above mutated the shared, swap-stable
		// AltRoot for the new generation, but the swap did not land. Restore the
		// middle links to the prior generation so the stable area matches what is
		// still active; otherwise a removed or repointed alternative would dangle
		// the still-live consumer link until the next apply.
		r.restoreAlternatives(st)
		_ = r.audit(audit.Event{
			Scope: r.opts.Scope, TxID: txID, Event: "apply.failed",
			Fields: map[string]any{"error": err.Error(), "stage": "commit"},
		})
		return 0, fmt.Errorf("commit: %w", err)
	}

	// Post-commit: emit the config actions' service.warning events. Deferred until
	// after the swap so a warning is never logged for an aborted apply.
	for _, w := range pendingWarnings {
		fields := make(map[string]any, len(w.Fields)+1)
		for k, v := range w.Fields {
			fields[k] = v
		}
		fields["warning"] = w.Kind
		_ = r.audit(audit.Event{Scope: r.opts.Scope, TxID: txID, Event: "service.warning", Fields: fields})
	}

	// Post-commit: emit reset audit events and clear the queue file.
	// Clearing happens only after a successful commit so reset intent is
	// preserved if the apply aborted.
	if resets != nil {
		priorHash := map[string]string{}
		if st.prior != nil {
			for i := range st.prior.Entries {
				priorHash[st.prior.Entries[i].Path] = st.prior.Entries[i].Expected.ContentHash
			}
		}
		appliedSet := map[string]bool{}
		for _, p := range appliedResets {
			appliedSet[p] = true
			_ = r.audit(audit.Event{
				Scope: r.opts.Scope, TxID: txID, Event: "config.reset_applied",
				Fields: map[string]any{"path": p, "prior_content_hash": priorHash[p]},
			})
		}
		for _, p := range resets.Paths {
			if !appliedSet[p] {
				_ = r.audit(audit.Event{
					Scope: r.opts.Scope, TxID: txID, Event: "service.warning",
					Fields: map[string]any{"warning": "config_reset_skipped", "path": p, "reason": "no_matching_entry"},
				})
			}
		}
		// All matched-scope paths are consumed (applied or skipped); clear the file.
		if err := os.Remove(r.opts.ResetsPath); err != nil && !os.IsNotExist(err) {
			slog.Warn("apply committed but clearing pending-resets failed", "path", r.opts.ResetsPath, "error", err)
		}
	}

	// Post-swap phases: the generation is already active; failures are warnings only.
	for _, phase := range []string{"post-activate", "pre-deactivate", "post-deactivate"} {
		for _, e := range entries {
			scope := action.Scope{ActiveRoot: activeRoot, PackageName: e.Package.Name, DirMode: r.opts.DirMode}
			if _, err := DispatchActions(ctx, e.Package, e.PkgRoot, scope, phase, ev, nil, nil, nil); err != nil {
				_ = r.audit(audit.Event{
					Scope: r.opts.Scope, TxID: txID, Event: "service.warning",
					Fields: map[string]any{"error": err.Error(), "stage": phase, "pkg": e.Package.Name},
				})
			}
		}
	}

	// Post-swap: CommitGeneration has completed the atomic swap, so the
	// generation is already active. A failed completion-audit is a warning,
	// not a transaction failure — return (gen, nil) regardless.
	if err := r.audit(audit.Event{
		Scope: r.opts.Scope, TxID: txID, Event: "apply.complete",
		Fields: map[string]any{
			"gen_id":             gen,
			"duration_ms":        time.Since(start).Milliseconds(),
			"drift_healed_count": driftHealed,
		},
	}); err != nil {
		slog.Warn("apply committed but completion audit failed", "tx_id", txID, "gen", gen, "error", err)
	}

	// Opportunistic GC runs under the still-held apply lock after
	// apply.complete (apply-semantics §5.3 step 9). Best-effort: failures
	// emit service.warning but do NOT fail the apply -- the swap has
	// already committed.
	if r.opts.GCPolicy != nil {
		r.runOpportunisticGC(txID)
	}
	return gen, nil
}

// restoreAlternatives reverts the stable alternatives middle links to the prior
// generation's state. It is called when the commit/swap fails after the pre-swap
// Reconcile has already mutated the shared AltRoot, so the links would otherwise
// reflect a generation that never became active. A nil prior (first apply)
// reconciles against the empty set, dropping the speculative links. Best-effort:
// a failed restore is logged and left for the next apply to reconcile.
func (r *Runner) restoreAlternatives(st *preApplyState) {
	var priorEntries []schema.OwnershipEntry
	if st != nil && st.prior != nil {
		priorEntries = st.prior.Entries
	}
	if _, err := alternatives.Reconcile(r.opts.Substrate.AltRoot(),
		alternatives.SelectionsPath(r.opts.Substrate.StateRoot()), priorEntries); err != nil {
		slog.Warn("commit failed and restoring prior alternatives links also failed; next apply will reconcile",
			"error", err)
	}
}

// runOpportunisticGC sweeps the generation store using gc.Decide and the
// substrate's primitives. Per-gen RemoveGeneration failures are logged and
// counted into the gc.run audit but never propagate out: the apply itself
// is already complete.
func (r *Runner) runOpportunisticGC(txID string) {
	gens, err := r.opts.Substrate.ListGenerations()
	if err != nil {
		slog.Warn("opportunistic GC: list failed", "error", err)
		_ = r.audit(audit.Event{
			Scope: r.opts.Scope, TxID: txID, Event: "service.warning",
			Fields: map[string]any{"stage": "opportunistic-gc", "error": err.Error()},
		})
		return
	}
	algGens := make([]gc.Generation, 0, len(gens))
	pinnedCount := 0
	byID := map[int]substrate.GenInfo{}
	for _, g := range gens {
		algGens = append(algGens, gc.Generation{
			ID:          g.ID,
			CommittedAt: g.CommittedAt,
			Pinned:      g.Pinned,
			IsCurrent:   g.IsCurrent,
			Incomplete:  g.Incomplete,
			Damaged:     g.Damaged,
		})
		if g.Pinned {
			pinnedCount++
		}
		byID[g.ID] = g
	}
	dec := gc.Decide(algGens, *r.opts.GCPolicy, time.Now())

	removed, failed, bytes := 0, 0, int64(0)
	for _, id := range dec.Remove {
		if err := r.opts.Substrate.RemoveGeneration(id); err != nil {
			slog.Warn("opportunistic GC: remove failed", "gen", id, "error", err)
			failed++
			continue
		}
		removed++
		bytes += byID[id].BytesOnDisk
	}
	_ = r.audit(audit.Event{
		Scope: r.opts.Scope, TxID: txID, Event: "gc.run",
		Fields: map[string]any{
			"trigger":                    "opportunistic",
			"generations_removed":        removed,
			"generations_remove_failed":  failed,
			"generations_skipped_pinned": pinnedCount,
			"bytes_reclaimed":            bytes,
		},
	})
}

// audit writes e to the configured AuditWriter, or is a no-op when
// AuditWriter is nil.
func (r *Runner) audit(e audit.Event) error {
	if r.opts.AuditWriter == nil {
		return nil
	}
	return r.opts.AuditWriter.Write(e)
}

// preApplyState carries the prior-generation context the config action needs:
// drift-derived preserve actions, the prior ownership index, and the prior
// generation's live root / directory. All fields are zero on first apply.
type preApplyState struct {
	healed          int
	preserveActions map[string]string
	prior           *schema.Ownership
	liveRoot        string
	priorGenDir     string
}

// checkDrift loads the current generation's ownership and runs drift detection.
// It always calls CurrentOwnership (even under --no-drift-check) so that the
// config action's sticky-preserve mechanism has the prior-generation context it
// needs. On first apply (ErrNoCurrentGeneration) it returns an empty state.
//
// Under --no-drift-check the drift inspection and refusal logic are skipped;
// if CurrentOwnership fails under that flag, the error is logged and an empty
// state is returned (don't block). Otherwise a CurrentOwnership error is fatal.
//
// The returned state's healed count is for apply.complete's drift_healed_count
// field. The preserveActions map carries drifted config paths whose action is
// "preserved", keyed by ownership path to the observed content hash.
//
// Note on the silent_heal suppression rule: a per-path drift.detected event is
// emitted for every entry EXCEPT when policy=silent_heal AND action=healed
// (the normal no-op case the operator opted out of seeing). A silent_heal
// path whose action is "accepted"/"refused"/"preserved" is still audited
// because those represent operator-relevant state changes.
func (r *Runner) checkDrift(txID string) (*preApplyState, error) {
	own, curGen, activeRoot, err := r.opts.Substrate.CurrentOwnership()
	if errors.Is(err, substrate.ErrNoCurrentGeneration) {
		return &preApplyState{}, nil
	}
	if err != nil {
		if r.opts.NoDriftCheck {
			slog.Warn("no-drift-check: current ownership unreadable; proceeding without prior context", "error", err)
			return &preApplyState{}, nil
		}
		_ = r.audit(audit.Event{
			Scope: r.opts.Scope, TxID: txID, Event: "apply.failed",
			Fields: map[string]any{"error": err.Error(), "stage": "ownership"},
		})
		return nil, fmt.Errorf("load current ownership: %w", err)
	}
	st := &preApplyState{
		prior:           own,
		liveRoot:        activeRoot,
		priorGenDir:     filepath.Dir(activeRoot),
		preserveActions: map[string]string{},
	}
	if r.opts.NoDriftCheck {
		slog.Warn("drift check skipped by --no-drift-check", "scope", r.opts.Scope)
		return st, nil
	}
	drifted, err := drift.Inspect(own, activeRoot)
	if err != nil {
		_ = r.audit(audit.Event{
			Scope: r.opts.Scope, TxID: txID, Event: "apply.failed",
			Fields: map[string]any{"error": err.Error(), "stage": "drift"},
		})
		return nil, fmt.Errorf("inspect drift: %w", err)
	}
	altDrifted, err := drift.InspectAlternatives(own, activeRoot, r.opts.Substrate.AltRoot(), alternatives.SelectionsPath(r.opts.Substrate.StateRoot()))
	if err != nil {
		_ = r.audit(audit.Event{
			Scope: r.opts.Scope, TxID: txID, Event: "apply.failed",
			Fields: map[string]any{"error": err.Error(), "stage": "drift"},
		})
		return nil, fmt.Errorf("inspect alternatives drift: %w", err)
	}
	drifted = append(drifted, altDrifted...)
	accepted := loadAccepted(r.opts.AcceptedDriftPath, curGen)

	var refused []string
	for i := range drifted {
		d := drifted[i]
		taken := decide(d, r.opts.HealDrift, accepted)
		if d.Owned.DriftPolicy != "silent_heal" || taken != "healed" {
			_ = r.audit(audit.Event{
				Scope: r.opts.Scope, TxID: txID, Event: "drift.detected",
				Fields: map[string]any{
					"action":       d.Owned.Action,
					"target":       d.Owned.Path,
					"policy":       d.Owned.DriftPolicy,
					"action_taken": taken,
					"reason":       string(d.Reason),
					"prior_hash":   d.Owned.Expected.ContentHash,
					"new_hash":     d.Observed,
				},
			})
		}
		switch taken {
		case "refused":
			refused = append(refused, d.Owned.Path)
		case "healed":
			st.healed++
		case "preserved":
			if d.Owned.Action == "config" {
				st.preserveActions[d.Owned.Path] = d.Observed
			}
		}
	}
	if len(refused) > 0 {
		_ = r.audit(audit.Event{
			Scope: r.opts.Scope, TxID: txID, Event: "apply.failed",
			Fields: map[string]any{"stage": "drift", "refused_paths": refused},
		})
		return nil, fmt.Errorf("apply refused: drift on %d path(s): %v (pass --heal-drift to override or polypkg accept-drift to adopt)",
			len(refused), refused)
	}
	return st, nil
}

// loadResets reads the pending-resets queue. A missing file yields (nil, nil, nil).
// A present-but-corrupt file is a hard error (operator-authored; silent loss of
// reset intent is worse than a blocked apply). A scope mismatch is ignored.
func (r *Runner) loadResets() (map[string]bool, *schema.Resets, error) {
	if r.opts.ResetsPath == "" {
		return nil, nil, nil
	}
	f, err := os.Open(filepath.Clean(r.opts.ResetsPath))
	if err != nil {
		return nil, nil, nil // missing is normal
	}
	defer func() { _ = f.Close() }()
	rs, err := schema.ParseResets(f)
	if err != nil {
		return nil, nil, fmt.Errorf("pending-resets: %w", schema.WithPath(err, r.opts.ResetsPath))
	}
	if rs.Scope != r.opts.Scope {
		return nil, nil, nil // belongs to a different scope's apply
	}
	set := make(map[string]bool, len(rs.Paths))
	for _, p := range rs.Paths {
		set[p] = true
	}
	return set, rs, nil
}

// loadAccepted reads the accepted-drift overrides file at path (if any) and
// returns it only when its recorded generation equals curGen. A missing,
// malformed, or stale (generation mismatch) record yields nil with no error.
func loadAccepted(path string, curGen int) *schema.AcceptedDrift {
	if path == "" || curGen == 0 {
		return nil
	}
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil // missing is normal
	}
	defer func() { _ = f.Close() }()
	a, err := schema.ParseAcceptedDrift(f)
	if err != nil {
		slog.Warn("accepted-drift parse failed; ignoring", "path", path, "error", err)
		return nil
	}
	if a.Generation != curGen {
		return nil // stale: a new generation reset the baseline
	}
	return a
}

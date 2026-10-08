package runner

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/trevor-vaughan/polypkg/internal/action"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/starlarkeval"
)

// DispatchOutput is the aggregate result of running a package's actions for one phase.
type DispatchOutput struct {
	Entries     []schema.OwnershipEntry
	ConfigBases map[string][]byte      // source hash -> incoming bytes (config actions)
	Warnings    []action.ConfigWarning // service.warning payloads to emit post-commit
	ResetPaths  []string               // ownership paths of config actions that were reset
}

// DispatchActions runs every action in pkg whose phase matches and returns the
// ownership entries produced by file-placing actions, plus config-action side data.
// preserveActions, prior, and resets drive the config action's preserve/sticky/reset
// decisions; they are nil for phases or runs with no prior generation.
func DispatchActions(ctx context.Context, pkg *schema.Package, pkgRoot string, scope action.Scope, phase string, ev *starlarkeval.Evaluator, preserveActions map[string]string, prior *schema.Ownership, resets map[string]bool) (*DispatchOutput, error) {
	scope.PackageRoot = pkgRoot

	var inputs starlarkeval.Inputs
	inputs.Package.Name = pkg.Name
	inputs.Package.Version = pkg.Version
	inputs.Host.OS = runtime.GOOS
	inputs.Host.Arch = runtime.GOARCH

	out := &DispatchOutput{}
	for _, v := range pkg.Actions {
		if v.Phase != phase {
			continue
		}
		params, err := substituteParams(ctx, v.Params, scope.ActiveRoot, pkgRoot, inputs, ev)
		if err != nil {
			return nil, fmt.Errorf("action %s (pkg %s): %w", v.Action, pkg.Name, err)
		}
		inv := action.Invocation{
			Action:      v.Action,
			PackageName: pkg.Name,
			Phase:       action.Phase(v.Phase),
			Params:      params,
		}
		spec, ok := action.Registry[v.Action]
		if !ok {
			return nil, fmt.Errorf("unknown action %q in package %q", v.Action, pkg.Name)
		}
		// config needs contextual inputs the other actions don't: the preserve/
		// reset maps and the prior generation's ownership entry for its dest.
		if v.Action == "config" {
			inv.PreserveActions = preserveActions
			inv.ResetPaths = resets
			if dest, ok := params["dest"].(string); ok && prior != nil {
				op := ownershipKey(scope.ActiveRoot, dest)
				for i := range prior.Entries {
					if prior.Entries[i].Path == op {
						inv.PriorEntry = &prior.Entries[i]
						break
					}
				}
			}
		}
		// A single-result action is the one-element case of a multi-result one,
		// so both feed the same per-Result recording below.
		var results []action.Result
		var herr error
		if spec.MultiHandler != nil {
			results, herr = spec.MultiHandler(inv, scope)
		} else {
			var res action.Result
			res, herr = spec.Handler(inv, scope)
			results = []action.Result{res}
		}
		if herr != nil {
			return nil, fmt.Errorf("action %s (pkg %s): %w", v.Action, pkg.Name, herr)
		}
		for i := range results {
			res := &results[i]
			if res.Outcome != "ok" {
				return nil, fmt.Errorf("action %s (pkg %s) failed: %s", v.Action, pkg.Name, res.ErrorMsg)
			}
			out.Warnings = append(out.Warnings, res.Warnings...)
			if !action.IsFilePlacing(v.Action) {
				continue
			}
			rel, err := filepath.Rel(scope.ActiveRoot, res.Path)
			if err != nil {
				return nil, fmt.Errorf("action %s (pkg %s): relativize %q: %w", v.Action, pkg.Name, res.Path, err)
			}
			ownPath := filepath.ToSlash(rel)
			// The action may choose its own drift policy (config does, from its
			// replacement policy); otherwise fall back to the declared drift or
			// the notify_heal default.
			policy := res.DriftPolicy
			if policy == "" {
				policy = v.Drift
				if policy == "" {
					policy = "notify_heal"
				}
			}
			out.Entries = append(out.Entries, schema.OwnershipEntry{
				Path:        ownPath,
				Package:     pkg.Name,
				Version:     pkg.Version,
				Action:      v.Action,
				Expected:    res.Expected,
				DriftPolicy: policy,
				Stat:        res.Stat,
			})
			if v.Action == "config" && res.SourceBytes != nil {
				if out.ConfigBases == nil {
					out.ConfigBases = map[string][]byte{}
				}
				out.ConfigBases[res.Expected.SourceHash] = res.SourceBytes
				if resets[ownPath] {
					out.ResetPaths = append(out.ResetPaths, ownPath)
				}
			}
		}
	}
	return out, nil
}

// ownershipKey returns dest expressed as an ownership path (relative to
// ActiveRoot, slash-separated). A relativization error yields the raw dest so
// the key is never silently dropped.
func ownershipKey(activeRoot, dest string) string {
	rel, err := filepath.Rel(activeRoot, dest)
	if err != nil {
		return dest
	}
	return filepath.ToSlash(rel)
}

func substituteParams(ctx context.Context, in map[string]any, active, pkgRoot string, inputs starlarkeval.Inputs, ev *starlarkeval.Evaluator) (map[string]any, error) {
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch val := v.(type) {
		case schema.StarlarkExpr:
			computed, err := ev.Eval(ctx, val.Source, inputs)
			if err != nil {
				return nil, fmt.Errorf("compute param %q: %w", k, err)
			}
			computed = strings.ReplaceAll(computed, "$ACTIVE", active)
			computed = strings.ReplaceAll(computed, "$PKG", pkgRoot)
			out[k] = computed
		case string:
			s := strings.ReplaceAll(val, "$ACTIVE", active)
			s = strings.ReplaceAll(s, "$PKG", pkgRoot)
			out[k] = s
		default:
			out[k] = v
		}
	}
	return out, nil
}

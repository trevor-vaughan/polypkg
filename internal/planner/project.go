package planner

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/trevor-vaughan/polypkg/internal/action"
	"github.com/trevor-vaughan/polypkg/internal/runner"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/starlarkeval"
)

// ProjectOwnership computes the ownership entries each package's actions would
// produce at apply time, without dispatching them. Paths use the literal
// activeRootPlaceholder (typically "$ACTIVE") because no transaction is
// open. Expected fields are populated per action type. Stat is left zero —
// diff doesn't need it for change detection.
func ProjectOwnership(
	entries []runner.RunEntry,
	activeRootPlaceholder string,
	ev *starlarkeval.Evaluator,
	scope string,
) (*schema.Ownership, error) {
	own := &schema.Ownership{
		Schema: "polypkg.ownership/v1", Scope: scope,
		Entries: []schema.OwnershipEntry{},
	}
	ctx := context.Background()

	for i := range entries {
		e := entries[i]
		var inputs starlarkeval.Inputs
		inputs.Package.Name = e.Package.Name
		inputs.Package.Version = e.Package.Version
		inputs.Host.OS = runtime.GOOS
		inputs.Host.Arch = runtime.GOARCH

		for _, v := range e.Package.Actions {
			if !action.IsFilePlacing(v.Action) {
				continue
			}
			params, err := substituteParams(ctx, v.Params, activeRootPlaceholder, e.PkgRoot, inputs, ev)
			if err != nil {
				return nil, fmt.Errorf("action %s (pkg %s): %w", v.Action, e.Package.Name, err)
			}
			path, err := projectPath(v.Action, params, activeRootPlaceholder)
			if err != nil {
				return nil, fmt.Errorf("action %s (pkg %s): %w", v.Action, e.Package.Name, err)
			}
			rel, err := filepath.Rel(activeRootPlaceholder, path)
			if err != nil {
				return nil, fmt.Errorf("action %s (pkg %s): relativize %q: %w", v.Action, e.Package.Name, path, err)
			}
			policy := v.Drift
			if policy == "" {
				policy = "notify_heal"
			}
			expected, err := projectExpected(v.Action, params, e.PkgRoot)
			if err != nil {
				return nil, fmt.Errorf("action %s (pkg %s): %w", v.Action, e.Package.Name, err)
			}
			own.Entries = append(own.Entries, schema.OwnershipEntry{
				Path:        filepath.ToSlash(rel),
				Package:     e.Package.Name,
				Version:     e.Package.Version,
				Action:      v.Action,
				Expected:    expected,
				DriftPolicy: policy,
			})
		}
	}
	return own, nil
}

// projectPath reconstructs the absolute filesystem path each action's runner site
// builds for Result.Path, so the planner relativizes it to the identical
// ownership key the runner records at apply time. Actions that target a shared
// per-generation area (path/alternatives → bin/<name>, completion →
// completions/<shell>/<hostfile>, desktop → applications/<base>, mime →
// mime/<base>) derive their path from name/shell/source rather than a dest/path
// param; the default branch covers dest/path-carrying actions (install, symlink,
// dir, perms, config, ...). Each shared-area case mirrors a specific runner site
// — see the keep-in-sync back-pointers there (internal/action/{path,alternatives,
// completion,desktop,mime}.go).
func projectPath(actionName string, params map[string]any, activeRoot string) (string, error) {
	switch actionName {
	case "path", "alternatives":
		if master, _ := params["master"].(string); master != "" {
			link, _ := params["link"].(string)
			return filepath.Join(activeRoot, link), nil
		}
		name, _ := params["name"].(string)
		return filepath.Join(activeRoot, action.SharedBinDir, name), nil
	case "completion":
		shell, _ := params["shell"].(string)
		name, _ := params["name"].(string)
		hostFile, ok := action.CompletionHostFile(shell, name)
		if !ok {
			return "", fmt.Errorf("completion: invalid or missing 'shell' (want bash, zsh, or fish)")
		}
		return filepath.Join(activeRoot, action.SharedCompletionsDir, shell, hostFile), nil
	case "desktop":
		source, _ := params["source"].(string)
		return filepath.Join(activeRoot, action.SharedApplicationsDir, filepath.Base(source)), nil
	case "mime":
		source, _ := params["source"].(string)
		return filepath.Join(activeRoot, action.SharedMimeDir, filepath.Base(source)), nil
	default:
		path, _ := params["dest"].(string)
		if path == "" {
			path, _ = params["path"].(string)
		}
		return path, nil
	}
}

// projectExpected builds the Expected an apply-time action would record, so the
// diff against stored ownership converges by construction. The mode is
// canonicalized to the runner's "%#o" form and the install content_hash is
// computed from the same package source the install action hashes — without
// these two, a converged system reports false drift (apply stores "0755" and a
// real symlink hash; a naive projection would carry "0o755" and an empty hash).
func projectExpected(actionName string, params map[string]any, pkgRoot string) (schema.Expected, error) {
	target, _ := params["src"].(string)
	policy, _ := params["policy"].(string)
	switch actionName {
	case "install":
		fileType := "regular"
		if policy == "symlink" {
			fileType = "symlink"
		}
		hash, err := action.HashInstallSource(pkgRoot, target)
		if err != nil {
			return schema.Expected{}, fmt.Errorf("hash install source %q: %w", target, err)
		}
		return schema.Expected{FileType: fileType, ContentHash: hash}, nil
	case "symlink":
		return schema.Expected{FileType: "symlink", Target: target}, nil
	case "dir":
		// The dir action defaults an absent mode to 0o755 before recording it,
		// so the projection must too — otherwise an empty projected mode
		// false-diffs against the stored "0755".
		raw, _ := params["mode"].(string)
		if raw == "" {
			raw = fmt.Sprintf("%#o", action.DefaultDirMode.Perm())
		}
		mode, err := action.CanonicalMode(raw)
		if err != nil {
			return schema.Expected{}, fmt.Errorf("canonicalize mode %q: %w", raw, err)
		}
		return schema.Expected{FileType: "dir", Mode: mode}, nil
	case "perms":
		// An absent perms mode projects empty: the action skips chmod and records
		// the live post-chmod mode, which the projection cannot predict. A
		// present mode is canonicalized to the action's stored "%#o" form.
		raw, _ := params["mode"].(string)
		if raw == "" {
			return schema.Expected{}, nil
		}
		mode, err := action.CanonicalMode(raw)
		if err != nil {
			return schema.Expected{}, fmt.Errorf("canonicalize mode %q: %w", raw, err)
		}
		return schema.Expected{Mode: mode}, nil
	case "path", "completion", "desktop", "mime":
		// Each records a symlink whose target is the $ACTIVE-expanded source the
		// runner stores (substituteParams already expanded $ACTIVE). The host
		// path differs per action (computed in projectPath) but the recorded
		// Expected is identical — mirror the runner sites field for field.
		src, _ := params["source"].(string)
		return schema.Expected{FileType: "symlink", Target: src}, nil
	case "alternatives":
		src, _ := params["source"].(string)
		if master, _ := params["master"].(string); master != "" {
			return schema.Expected{FileType: "symlink", Target: src, Master: master}, nil
		}
		pr := coerceProjPriority(params["priority"])
		return schema.Expected{FileType: "symlink", Target: src, Priority: pr}, nil
	default:
		return schema.Expected{}, nil
	}
}

// coerceProjPriority mirrors action.paramInt (unexported there): it coerces a
// params priority value to an int, accepting int/int64/float64 and a numeric
// string (the form a Starlark-resolved param takes). Returns 0 for missing or
// non-numeric values — the projection is best-effort preview; the action itself
// is the authoritative validator at apply time.
// A 0 fallback is safe: Expected.Priority is omitempty and 0 is the lowest valid tier (see schema.Expected.Priority); the action's paramInt is the authoritative validator that rejects a missing priority at apply time.
func coerceProjPriority(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case string:
		if p, err := strconv.Atoi(n); err == nil {
			return p
		}
	}
	return 0
}

// substituteParams mirrors runner/dispatch.go's substituteParams — string
// values get $ACTIVE/$PKG substitution; !starlark values are evaluated
// then substituted.
func substituteParams(ctx context.Context, in map[string]any, active, pkgRoot string, inputs starlarkeval.Inputs, ev *starlarkeval.Evaluator) (map[string]any, error) {
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch val := v.(type) {
		case schema.StarlarkExpr:
			if ev == nil {
				return nil, fmt.Errorf("starlark param %q encountered but no evaluator provided", k)
			}
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

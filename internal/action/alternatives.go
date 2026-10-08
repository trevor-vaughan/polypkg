package action

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// altNameRe is the generic-name grammar: a single safe path component. It
// compiles the registry's shared NamePattern so the runtime check and the
// declarative lint table cannot diverge.
var altNameRe = regexp.MustCompile(NamePattern)

// Alternatives registers this package as a provider of the generic command
// `name` at the given `priority`, exposing the package's own file `source`
// (confined to the package namespace). It creates only the CONSTANT consumer
// link <ActiveRoot>/bin/<name> -> <AltRoot>/<name> (identical for every provider
// of name) and records a provider-registration ownership entry carrying the
// source (Expected.Target) and priority (Expected.Priority). The winner-dependent
// middle link <AltRoot>/<name> is materialized centrally (internal/alternatives)
// after arbitration; the consumer link may dangle until then.
func Alternatives(inv Invocation, scope Scope) (Result, error) {
	if master, ok := inv.Params["master"].(string); ok && master != "" {
		return alternativesFollower(inv, scope, master)
	}
	name, _ := inv.Params["name"].(string)
	if !altNameRe.MatchString(name) {
		return Result{Action: "alternatives", Outcome: "error"},
			fmt.Errorf("alternatives: invalid or missing 'name' (must match [a-zA-Z0-9_-]+)")
	}
	source, _ := inv.Params["source"].(string)
	if source == "" {
		return Result{Action: "alternatives", Outcome: "error"}, fmt.Errorf("alternatives: 'source' is required")
	}
	if !scope.Allows(source) {
		return Result{Action: "alternatives", Outcome: "error"},
			fmt.Errorf("alternatives: source %q is outside the package scope", source)
	}
	priority, ok := paramInt(inv.Params["priority"])
	if !ok {
		return Result{Action: "alternatives", Outcome: "error"},
			fmt.Errorf("alternatives: 'priority' is required and must be an integer")
	}
	// The consumer link target is the stable middle link, constant across providers.
	target := filepath.Join(scope.AltRoot, name)
	root, err := scope.openSharedSubtree(SharedBinDir) // confined to <ActiveRoot>/bin
	if err != nil {
		return Result{Action: "alternatives", Outcome: "error"}, fmt.Errorf("alternatives: %w", err)
	}
	defer func() { _ = root.Close() }()
	_ = root.Remove(name)
	if err := root.Symlink(target, name); err != nil {
		return Result{Action: "alternatives", Outcome: "error"},
			fmt.Errorf("alternatives: symlink %q: %w", name, err)
	}
	absPath := filepath.Join(scope.ActiveRoot, SharedBinDir, name) // absolute; dispatch relativizes to the bin/<name> ownership entry
	stat, err := capturedStat(root, name)
	if err != nil {
		return Result{Action: "alternatives", Path: absPath, Outcome: "error"},
			fmt.Errorf("alternatives: stat: %w", err)
	}
	return Result{
		Action:  "alternatives",
		Path:    absPath,
		Outcome: "ok",
		// source is the scope-confined $ACTIVE-expanded absolute provider target.
		// Planner mirrors this in projectExpected ("alternatives" case), expanding
		// $ACTIVE against the diff baseline's active root so a converged plan
		// compares equal — keep in sync (covers the follower site below too).
		Expected: schema.Expected{FileType: "symlink", Target: source, Priority: priority},
		Stat:     stat,
	}, nil
}

// followersDir is the reserved subtree under <AltRoot> holding follower middle
// links. It mirrors alternatives.FollowersDir; a string literal is used here to
// avoid importing the alternatives package into action (see altName's note).
const followersDir = ".followers"

// alternativesFollower handles a follower (slave) invocation: it registers a
// secondary symlink keyed to master that tracks master's winning provider. It
// places only the CONSTANT consumer link <ActiveRoot>/<link> -> <AltRoot>/
// .followers/<link> (identical for every provider) and records an ownership
// entry with Expected.Master=master; the winner-dependent middle link is
// materialized centrally after arbitration. A follower has no independent name
// or priority — both are rejected.
func alternativesFollower(inv Invocation, scope Scope, master string) (Result, error) {
	if !altNameRe.MatchString(master) {
		return Result{Action: "alternatives", Outcome: "error"},
			fmt.Errorf("alternatives: invalid 'master' %q (must match [a-zA-Z0-9_-]+)", master)
	}
	if _, ok := inv.Params["name"]; ok {
		return Result{Action: "alternatives", Outcome: "error"},
			fmt.Errorf("alternatives: 'name' is not allowed with 'master' (a follower has no independent name)")
	}
	if _, ok := inv.Params["priority"]; ok {
		return Result{Action: "alternatives", Outcome: "error"},
			fmt.Errorf("alternatives: 'priority' is not allowed with 'master' (a follower inherits its master's winner)")
	}
	link, _ := inv.Params["link"].(string)
	rel, ok := followerLink(link)
	if !ok {
		return Result{Action: "alternatives", Outcome: "error"},
			fmt.Errorf("alternatives: invalid 'link' %q (must be a clean relative path with at least two components under %s/ or %s/)",
				link, SharedBinDir, SharedManDir)
	}
	source, _ := inv.Params["source"].(string)
	if source == "" {
		return Result{Action: "alternatives", Outcome: "error"}, fmt.Errorf("alternatives: 'source' is required")
	}
	if !scope.Allows(source) {
		return Result{Action: "alternatives", Outcome: "error"},
			fmt.Errorf("alternatives: source %q is outside the package scope", source)
	}
	target := filepath.Join(scope.AltRoot, followersDir, rel)
	dir, base := filepath.Split(rel)
	root, err := scope.openSharedSubtree(filepath.Clean(dir))
	if err != nil {
		return Result{Action: "alternatives", Outcome: "error"}, fmt.Errorf("alternatives: %w", err)
	}
	defer func() { _ = root.Close() }()
	_ = root.Remove(base)
	if err := root.Symlink(target, base); err != nil {
		return Result{Action: "alternatives", Outcome: "error"},
			fmt.Errorf("alternatives: symlink %q: %w", rel, err)
	}
	absPath := filepath.Join(scope.ActiveRoot, rel)
	stat, err := capturedStat(root, base)
	if err != nil {
		return Result{Action: "alternatives", Path: absPath, Outcome: "error"},
			fmt.Errorf("alternatives: stat: %w", err)
	}
	return Result{
		Action:   "alternatives",
		Path:     absPath,
		Outcome:  "ok",
		Expected: schema.Expected{FileType: "symlink", Target: source, Master: master},
		Stat:     stat,
	}, nil
}

// followerLink validates a follower's consumer link path and returns it cleaned.
// It must be a clean, relative, non-escaping path whose leading component is the
// bin or man shared subtree and which has at least one component beyond it. A
// bin follower must be a single flat name (bin/<name>): the ~/.local/bin bridge
// exposes only flat command names, so a nested bin/<dir>/<name> would land in the
// active tree but never reach $PATH. Man followers keep their section depth
// (man/man<N>/<page>), consumed via $MANPATH.
func followerLink(link string) (string, bool) {
	if link == "" || filepath.IsAbs(link) {
		return "", false
	}
	clean := filepath.Clean(link)
	if clean != link { // rejects "..", trailing/duplicate slashes, "."
		return "", false
	}
	parts := strings.SplitN(clean, "/", 2)
	if len(parts) != 2 || parts[1] == "" {
		return "", false
	}
	if parts[0] != SharedBinDir && parts[0] != SharedManDir {
		return "", false
	}
	if parts[0] == SharedBinDir && strings.Contains(parts[1], "/") {
		return "", false // bin followers must be flat (bin/<name>); see doc above
	}
	return clean, true
}

// paramInt coerces a params value to an int. Plain YAML/JSONC numeric scalars
// decode to int (the yaml.v3/JSONC path), while a !starlark-computed priority
// arrives as the decimal string the evaluator emits (dispatch resolves every
// Starlark expression to a string). Both forms are accepted; missing or
// non-numeric values return ok=false.
// paramInt is package-local; the planner re-coerces priority inline rather than
// importing it, matching the existing package boundary.
func paramInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case string:
		i, err := strconv.Atoi(n)
		if err != nil {
			return 0, false
		}
		return i, true
	default:
		return 0, false
	}
}

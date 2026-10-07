package action

import (
	"fmt"
	"path/filepath"
	"regexp"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// completionNameRe is the completion-name grammar: a single safe path
// component. It compiles the registry's shared NamePattern so the runtime
// check and the declarative lint table cannot diverge.
var completionNameRe = regexp.MustCompile(NamePattern)

// completionShells maps a declared shell to the on-disk completion file name for
// a given command name. bash loads "<name>", zsh "_<name>", fish "<name>.fish".
var completionShells = map[string]func(name string) string{
	"bash": func(name string) string { return name },
	"zsh":  func(name string) string { return "_" + name },
	"fish": func(name string) string { return name + ".fish" },
}

// CompletionHostFile returns the on-disk completion file name a given shell loads
// for command name, and whether shell is supported. It is the single source of
// the per-shell naming convention: the Completion action derives the file it writes
// from it, and the planner's projectOwnership mirrors the same name when it
// projects the completions/<shell>/<hostfile> ownership path — keep the two in
// sync through this function rather than duplicating the bash/zsh/fish rules.
func CompletionHostFile(shell, name string) (string, bool) {
	host, ok := completionShells[shell]
	if !ok {
		return "", false
	}
	return host(name), true
}

// Completion installs a package's shell-completion script into the shared
// per-shell area of the active tree (<ActiveRoot>/completions/<shell>/<hostfile>)
// as a symlink to the package's own script. The shared path makes two packages
// shipping the same shell+name collide (refused by internal/conflict). The
// source is confined to the package's own namespace, so a package may only ship
// its own completion. Result.Path is absolute; dispatch relativizes it to the
// completions/<shell>/<hostfile> ownership path.
func Completion(inv Invocation, scope Scope) (Result, error) {
	shell, _ := inv.Params["shell"].(string)
	if _, ok := completionShells[shell]; !ok {
		return Result{Action: "completion", Outcome: "error"},
			fmt.Errorf("completion: invalid or missing 'shell' (want bash, zsh, or fish)")
	}
	name, _ := inv.Params["name"].(string)
	if !completionNameRe.MatchString(name) {
		return Result{Action: "completion", Outcome: "error"},
			fmt.Errorf("completion: invalid or missing 'name' (must match [a-zA-Z0-9_-]+)")
	}
	source, _ := inv.Params["source"].(string)
	if source == "" {
		return Result{Action: "completion", Outcome: "error"}, fmt.Errorf("completion: 'source' is required")
	}
	if !scope.Allows(source) {
		return Result{Action: "completion", Outcome: "error"},
			fmt.Errorf("completion: source %q is outside the package scope", source)
	}
	// hostFile is the per-shell on-disk completion file name; the planner mirrors
	// this derivation via action.CompletionHostFile when projecting the ownership
	// path — keep in sync. ok is guaranteed true: shell was validated above.
	hostFile, _ := CompletionHostFile(shell, name)
	root, err := scope.openSharedSubtree(filepath.Join(SharedCompletionsDir, shell))
	if err != nil {
		return Result{Action: "completion", Outcome: "error"}, fmt.Errorf("completion: %w", err)
	}
	defer func() { _ = root.Close() }()
	_ = root.Remove(hostFile)
	if err := root.Symlink(source, hostFile); err != nil {
		return Result{Action: "completion", Outcome: "error"},
			fmt.Errorf("completion: symlink %q: %w", hostFile, err)
	}
	// absPath relativizes to the completions/<shell>/<hostfile> ownership path;
	// the planner mirrors this path and records source as the symlink target in
	// projectOwnership/projectExpected ("completion" case) — keep in sync.
	absPath := filepath.Join(scope.ActiveRoot, SharedCompletionsDir, shell, hostFile) // absolute; dispatch relativizes
	stat, err := capturedStat(root, hostFile)
	if err != nil {
		return Result{Action: "completion", Path: absPath, Outcome: "error"},
			fmt.Errorf("completion: stat: %w", err)
	}
	return Result{
		Action:   "completion",
		Path:     absPath,
		Outcome:  "ok",
		Expected: schema.Expected{FileType: "symlink", Target: source},
		Stat:     stat,
	}, nil
}

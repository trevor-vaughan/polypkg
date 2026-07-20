package action

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// mimeIDRe is the shared-mime-info package-file stem grammar: a single safe
// filename stem that may contain interior dots (reverse-DNS ids like
// org.foo.Bar), starting with an alphanumeric so it can never be "."/".." or a
// dotfile.
var mimeIDRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// Mime installs a package's own shared-mime-info XML into the shared
// per-generation mime area (<ActiveRoot>/mime/<base>) as a symlink to the
// package's own file, where <base> is the source's basename. The shared path
// makes two packages shipping the same .xml basename collide (refused by
// internal/conflict). The source is confined to the package's own namespace.
// Result.Path is absolute; dispatch relativizes it to the mime/<base> ownership
// path.
func Mime(inv Invocation, scope Scope) (Result, error) {
	source, _ := inv.Params["source"].(string)
	if source == "" {
		return Result{Action: "mime", Outcome: "error"}, fmt.Errorf("mime: 'source' is required")
	}
	// base is the source basename; the ownership path is mime/<base> and the
	// recorded target is the $ACTIVE-expanded source. The planner mirrors both in
	// projectExpected/ProjectOwnership ("mime" case) — keep in sync.
	base := filepath.Base(source)
	stem := strings.TrimSuffix(base, ".xml")
	if stem == base || !mimeIDRe.MatchString(stem) {
		return Result{Action: "mime", Outcome: "error"},
			fmt.Errorf("mime: source basename %q must be <id>.xml with id matching [a-zA-Z0-9][a-zA-Z0-9._-]*", base)
	}
	if !scope.Allows(source) {
		return Result{Action: "mime", Outcome: "error"},
			fmt.Errorf("mime: source %q is outside the package scope", source)
	}
	root, err := scope.openSharedSubtree(SharedMimeDir)
	if err != nil {
		return Result{Action: "mime", Outcome: "error"}, fmt.Errorf("mime: %w", err)
	}
	defer func() { _ = root.Close() }()
	_ = root.Remove(base)
	if err := root.Symlink(source, base); err != nil {
		return Result{Action: "mime", Outcome: "error"}, fmt.Errorf("mime: symlink %q: %w", base, err)
	}
	absPath := filepath.Join(scope.ActiveRoot, SharedMimeDir, base) // absolute; dispatch relativizes
	stat, err := capturedStat(root, base)
	if err != nil {
		return Result{Action: "mime", Path: absPath, Outcome: "error"}, fmt.Errorf("mime: stat: %w", err)
	}
	return Result{
		Action:   "mime",
		Path:     absPath,
		Outcome:  "ok",
		Expected: schema.Expected{FileType: "symlink", Target: source},
		Stat:     stat,
	}, nil
}

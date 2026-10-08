package action

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// desktopIDRe is the .desktop id grammar: a single safe filename stem that may
// contain interior dots (reverse-DNS ids like org.foo.Bar), starting with an
// alphanumeric so it can never be "."/".." or a dotfile.
var desktopIDRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// Desktop installs a package's own .desktop application entry into the shared
// per-generation applications area (<ActiveRoot>/applications/<base>) as a
// symlink to the package's own file, where <base> is the source's basename. The
// shared path makes two packages shipping the same .desktop basename collide
// (refused by internal/conflict). The source is confined to the package's own
// namespace. Result.Path is absolute; dispatch relativizes it to the
// applications/<base> ownership path.
func Desktop(inv Invocation, scope Scope) (Result, error) {
	source, _ := inv.Params["source"].(string)
	if source == "" {
		return Result{Action: "desktop", Outcome: "error"}, fmt.Errorf("desktop: 'source' is required")
	}
	// base is the source basename; the ownership path is applications/<base> and
	// the recorded target is the $ACTIVE-expanded source. The planner mirrors both
	// in projectExpected/projectOwnership ("desktop" case) — keep in sync.
	base := filepath.Base(source)
	stem := strings.TrimSuffix(base, ".desktop")
	if stem == base || !desktopIDRe.MatchString(stem) {
		return Result{Action: "desktop", Outcome: "error"},
			fmt.Errorf("desktop: source basename %q must be <id>.desktop with id matching [a-zA-Z0-9][a-zA-Z0-9._-]*", base)
	}
	if !scope.Allows(source) {
		return Result{Action: "desktop", Outcome: "error"},
			fmt.Errorf("desktop: source %q is outside the package scope", source)
	}
	root, err := scope.openSharedSubtree(SharedApplicationsDir)
	if err != nil {
		return Result{Action: "desktop", Outcome: "error"}, fmt.Errorf("desktop: %w", err)
	}
	defer func() { _ = root.Close() }()
	_ = root.Remove(base)
	if err := root.Symlink(source, base); err != nil {
		return Result{Action: "desktop", Outcome: "error"}, fmt.Errorf("desktop: symlink %q: %w", base, err)
	}
	absPath := filepath.Join(scope.ActiveRoot, SharedApplicationsDir, base) // absolute; dispatch relativizes
	stat, err := capturedStat(root, base)
	if err != nil {
		return Result{Action: "desktop", Path: absPath, Outcome: "error"}, fmt.Errorf("desktop: stat: %w", err)
	}
	return Result{
		Action:   "desktop",
		Path:     absPath,
		Outcome:  "ok",
		Expected: schema.Expected{FileType: "symlink", Target: source},
		Stat:     stat,
	}, nil
}

// Package action implements polypkg's declarative install-time actions
// (install, symlink, dir, perms in M1) with scope enforcement.
package action

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// Phase identifies when an action runs during the apply lifecycle.
type Phase string

const (
	// PhasePrePlace runs before artifact files are placed into the store.
	PhasePrePlace Phase = "pre-place"
	// PhasePostPlace runs after artifact files are placed into the store.
	PhasePostPlace Phase = "post-place"
	// PhasePreActivate runs before a generation is promoted to active.
	PhasePreActivate Phase = "pre-activate"
	// PhasePostActivate runs after a generation is promoted to active.
	PhasePostActivate Phase = "post-activate"
	// PhasePreDeactivate runs before the active generation is retired.
	PhasePreDeactivate Phase = "pre-deactivate"
	// PhasePostDeactivate runs after the active generation is retired.
	PhasePostDeactivate Phase = "post-deactivate"
)

// Scope describes the path boundaries a package may operate within: dest paths
// must fall under ActiveRoot/PackageName, and install source paths must fall
// under PackageRoot (the package's own extracted files).
type Scope struct {
	ActiveRoot  string // e.g., /home/u/.local/share/polypkg/active
	LiveRoot    string // current active dir (prior gen); "" on first apply
	PriorGenDir string // <root>/generations/<cur>; "" on first apply
	StateRoot   string // <substrateRoot>/state ; "" disables the state action's stable placement
	AltRoot     string // <substrateRoot>/alternatives ; the stable middle-link area
	PackageName string
	PackageRoot string      // the extracted package directory ($PKG)
	DirMode     os.FileMode // dir-creation mode for openScope/openSharedSubtree; 0 => 0o700
}

// Allows reports whether a destination path is lexically within the package's
// scope (ActiveRoot/PackageName). Traversal that escapes the scope and siblings
// like "<pkg>-evil" are both rejected. This is a cheap first check; the actual
// filesystem operations go through openScope, which additionally refuses to
// traverse symlinks that escape the scope.
func (s Scope) Allows(path string) bool {
	_, ok := relWithin(filepath.Join(s.ActiveRoot, s.PackageName), path)
	return ok
}

// AllowsSource reports whether path is lexically within the package's own
// extracted files (PackageRoot). The install action reads from or links to src,
// so confining src to the package prevents a (signed-but-hostile) package from
// copying or linking arbitrary host files — e.g. /etc/shadow or a secret in an
// otherwise-unreachable directory — into the active root. Fails closed when
// PackageRoot is unset.
func (s Scope) AllowsSource(path string) bool {
	if s.PackageRoot == "" {
		return false
	}
	_, ok := relWithin(s.PackageRoot, path)
	return ok
}

// relWithin returns path expressed relative to root, and whether path is within
// root. It cleans both and rejects any path that resolves to root's parent or a
// sibling (so "<root>-evil" is not treated as inside "<root>"). The root itself
// maps to ".".
func relWithin(root, path string) (string, bool) {
	base := filepath.Clean(root)
	clean := filepath.Clean(path)
	if clean == base {
		return ".", true
	}
	rel, err := filepath.Rel(base, clean)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return rel, true
}

// dirPerm returns the effective directory-creation mode: DirMode, or 0o700 when
// unset (the user-private default). System scope sets 0o755 so the active tree
// is traversable by other users.
func (s Scope) dirPerm() os.FileMode {
	if s.DirMode == 0 {
		return 0o700
	}
	return s.DirMode
}

// openScope returns an os.Root confined to the package's scope
// (ActiveRoot/PackageName) together with dest expressed relative to it. Every
// operation through the returned root is rejected if it escapes the scope,
// including traversal through a symlink an earlier action may have planted, so
// callers get symlink-safe writes. The caller must Close the returned root.
func (s Scope) openScope(dest string) (*os.Root, string, error) {
	rel, ok := relWithin(filepath.Join(s.ActiveRoot, s.PackageName), dest)
	if !ok {
		return nil, "", fmt.Errorf("%q is outside the package scope", dest)
	}
	// ActiveRoot is polypkg-controlled (the staged generation root), so creating
	// it is safe. The package subdirectory and everything beneath it is created
	// through the root so a planted symlink cannot redirect it.
	if err := os.MkdirAll(s.ActiveRoot, s.dirPerm()); err != nil {
		return nil, "", fmt.Errorf("create active root: %w", err)
	}
	base, err := os.OpenRoot(s.ActiveRoot)
	if err != nil {
		return nil, "", fmt.Errorf("open active root: %w", err)
	}
	defer func() { _ = base.Close() }()
	if err := base.MkdirAll(s.PackageName, s.dirPerm()); err != nil {
		return nil, "", fmt.Errorf("create package scope: %w", err)
	}
	root, err := base.OpenRoot(s.PackageName)
	if err != nil {
		return nil, "", fmt.Errorf("open package scope: %w", err)
	}
	return root, rel, nil
}

// SharedBinDir is the active-tree subdirectory holding the shared command
// symlinks placed by the path action. It is reserved: no package may be named
// "bin" (a package named "bin" would namespace under <ActiveRoot>/bin and
// collide with this shared root).
const SharedBinDir = "bin"

// SharedCompletionsDir is the active-tree subdirectory holding per-shell
// completion symlinks placed by the completion action (<ActiveRoot>/completions/<shell>/<file>).
// It is reserved: no package may be named "completions".
const SharedCompletionsDir = "completions"

// SharedApplicationsDir is the active-tree subdirectory holding the .desktop
// entry symlinks placed by the desktop action (<ActiveRoot>/applications/<file>).
// It is reserved: no package may be named "applications".
const SharedApplicationsDir = "applications"

// SharedMimeDir is the active-tree subdirectory holding the shared-mime-info
// XML symlinks placed by the mime action (<ActiveRoot>/mime/<file>). It is
// reserved: no package may be named "mime".
const SharedMimeDir = "mime"

// SharedManDir is the active-tree subdirectory holding man-page symlinks placed
// as alternatives followers (<ActiveRoot>/man/man<section>/<file>). It is
// reserved: no package may be named "man". Consumed via $MANPATH (a nudge, not
// a bridge).
const SharedManDir = "man"

// openSharedSubtree returns an os.Root confined to <ActiveRoot>/rel, the shared
// (non-package-namespaced) active-tree area an action writes into (e.g. "bin",
// "completions/<shell>", "applications"). ActiveRoot is polypkg-controlled so
// creating it is safe; rel and everything beneath it is created through the root
// so a planted symlink cannot redirect a write. The caller must Close the root.
func (s Scope) openSharedSubtree(rel string) (*os.Root, error) {
	if err := os.MkdirAll(s.ActiveRoot, s.dirPerm()); err != nil {
		return nil, fmt.Errorf("create active root: %w", err)
	}
	base, err := os.OpenRoot(s.ActiveRoot)
	if err != nil {
		return nil, fmt.Errorf("open active root: %w", err)
	}
	defer func() { _ = base.Close() }()
	if err := base.MkdirAll(rel, s.dirPerm()); err != nil {
		return nil, fmt.Errorf("create shared subtree %q: %w", rel, err)
	}
	root, err := base.OpenRoot(rel)
	if err != nil {
		return nil, fmt.Errorf("open shared subtree %q: %w", rel, err)
	}
	return root, nil
}

// openPackage returns an os.Root confined to the package's extracted files
// (PackageRoot) together with src expressed relative to it. Used to read or
// link install sources without escaping the package's own files. The caller
// must Close the returned root.
func (s Scope) openPackage(src string) (*os.Root, string, error) {
	if s.PackageRoot == "" {
		return nil, "", fmt.Errorf("no package root configured")
	}
	rel, ok := relWithin(s.PackageRoot, src)
	if !ok {
		return nil, "", fmt.Errorf("%q is outside the package's files", src)
	}
	root, err := os.OpenRoot(s.PackageRoot)
	if err != nil {
		return nil, "", fmt.Errorf("open package root: %w", err)
	}
	return root, rel, nil
}

// Invocation is a single action to execute.
type Invocation struct {
	Action          string // e.g., "install"
	PackageName     string
	Phase           Phase
	Params          map[string]any
	PreserveActions map[string]string      // ownership-path -> live hash; nil for non-config
	PriorEntry      *schema.OwnershipEntry // prior gen's entry for this action's dest; nil if absent
	ResetPaths      map[string]bool        // ownership-paths queued for reset; nil if none
}

// ConfigWarning is a service.warning the runner emits on the action's behalf.
// Actions are pure functions with no audit writer, so they return warnings as data.
type ConfigWarning struct {
	Kind   string
	Fields map[string]any
}

// Result is the outcome of one invocation. Expected and Stat describe what the
// action materialized, for the per-generation ownership index.
type Result struct {
	Action      string
	Path        string
	Outcome     string // "ok" | "error"
	ErrorMsg    string
	Expected    schema.Expected
	Stat        schema.StatInfo
	DriftPolicy string          // action-chosen drift policy; "" => dispatch uses v.Drift / notify_heal
	SourceBytes []byte          // incoming package bytes for config actions; nil otherwise
	Warnings    []ConfigWarning // service.warning payloads; nil for most actions
}

// IsFilePlacing reports whether an action materializes filesystem objects that must
// be recorded in the ownership index. The answer comes from the action Registry,
// the single source of truth; unknown actions are not file-placing.
func IsFilePlacing(name string) bool {
	return Registry[name].FilePlacing
}

// IsPreSwapPhase reports whether phase runs before the atomic generation swap.
// File-placing actions may run only in these phases so the committed ownership
// index is complete (see apply-semantics §5.3).
func IsPreSwapPhase(phase string) bool {
	switch Phase(phase) {
	case PhasePrePlace, PhasePostPlace, PhasePreActivate:
		return true
	default:
		return false
	}
}

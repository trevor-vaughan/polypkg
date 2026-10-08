package runner

import "github.com/trevor-vaughan/polypkg/internal/schema"

// SupersedeModes leaves each path's mode to the last action that set it.
// The dir, perms and extract actions each chmod the path they record, so when
// two of a package's actions record a mode for one path, the earlier one's
// mode no longer describes the disk: enforcing it would report drift on every
// apply (refused forever under refuse, re-healed forever under notify_heal).
// For every (package, path) it clears Expected.Mode on all entries before the
// last one that carries a mode; their type, content hash and target are still
// enforced. entries must be in execution order (action.PreSwapPhases, then
// declaration order) and are modified in place. The runner applies it to the
// ownership it records and to the prior generation it checks for drift, and
// the planner to the ownership it projects, so all three agree.
//
// Paths are compared as written. A perms that reaches another entry's path
// through a symlink alias (a different ownership path to the same file) is
// not merged with it, so both modes are still enforced; this is a known
// limitation.
func SupersedeModes(entries []schema.OwnershipEntry) {
	type key struct{ pkg, path string }
	seen := make(map[key]bool, len(entries))
	for i := len(entries) - 1; i >= 0; i-- {
		e := &entries[i]
		if e.Expected.Mode == "" {
			continue
		}
		k := key{e.Package, e.Path}
		if seen[k] {
			e.Expected.Mode = ""
			continue
		}
		seen[k] = true
	}
}

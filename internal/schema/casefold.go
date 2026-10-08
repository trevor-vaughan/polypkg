package schema

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// CaseFoldCollisionError is two package names, or two versions of Package,
// whose spellings First and Second differ only in letter case.
type CaseFoldCollisionError struct {
	Package       string // the package whose versions collide; "" when two names do
	First, Second string
}

func (e *CaseFoldCollisionError) Error() string {
	if e.Package == "" {
		return fmt.Sprintf("package names %q and %q differ only in letter case, so they would share a directory on a case-insensitive filesystem", e.First, e.Second)
	}
	return fmt.Sprintf("package %q versions %q and %q differ only in letter case, so they would share a directory on a case-insensitive filesystem", e.Package, e.First, e.Second)
}

// CaseFoldCollision reports two package names in idx, or two version strings
// of one package, that differ only in letter case. Tools lay packages out on
// disk as <name>/<version>/ (mirror staging, pkg import), and on a
// case-insensitive filesystem, the default on macOS and Windows, such a pair
// shares one directory. Entries of one package that repeat one version
// string, one per platform, are not a collision. Names are checked in sorted
// order, so the error is deterministic. It returns the concrete type so a
// caller that explains the collision needs no fallback for another error.
func CaseFoldCollision(idx *Index) *CaseFoldCollisionError {
	names := map[string]string{} // folded name -> the name that folded to it
	for _, name := range slices.Sorted(maps.Keys(idx.Packages)) {
		if prev, ok := names[strings.ToLower(name)]; ok {
			return &CaseFoldCollisionError{First: prev, Second: name}
		}
		names[strings.ToLower(name)] = name
		versions := map[string]string{} // folded version -> the version that folded to it
		for i := range idx.Packages[name] {
			v := idx.Packages[name][i].Version
			if prev, ok := versions[strings.ToLower(v)]; ok && prev != v {
				return &CaseFoldCollisionError{Package: name, First: prev, Second: v}
			}
			versions[strings.ToLower(v)] = v
		}
	}
	return nil
}

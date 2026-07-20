// Package alternatives arbitrates shared-path providers registered by the
// alternatives action: several packages may provide the same generic command
// (e.g. "editor"); this package selects the winner and materializes the stable
// two-level indirection link group. Winner selection is pure (no I/O):
// highest priority wins, ties broken by package name ascending — deterministic
// and reproducible from a generation's ownership index alone.
package alternatives

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// FollowersDir is the reserved subtree under <AltRoot> holding follower (slave)
// middle links, mirroring the consumer link path: <AltRoot>/.followers/<link>.
// The leading "." keeps it out of the primary middle-link namespace (altName
// grammar excludes "."), so the top-level prune can skip it wholesale.
const FollowersDir = ".followers"

// Winner is the chosen provider for one alternative name. The map returned by
// Arbitrate is keyed by name, so no Name field is needed here.
type Winner struct {
	Package   string            // the winning package
	Source    string            // the winner's provider file (the middle link's target)
	Followers map[string]string // follower link (ownership path) -> source, winning package only
}

// Arbitrate groups alternatives PRIMARY registration entries (Expected.Master
// == "") by name and returns the winner per name (highest Expected.Priority;
// ties by package name ascending), then attaches each winner's followers —
// follower entries (Expected.Master != "") whose master is the name and whose
// package is the winner. Non-alternatives entries are ignored. Pure: no I/O.
func Arbitrate(entries []schema.OwnershipEntry) map[string]Winner {
	type cand struct {
		pkg, source string
		priority    int
	}
	best := map[string]cand{} // keyed by name, primaries only
	for i := range entries {
		e := &entries[i]
		if e.Action != "alternatives" || e.Expected.Master != "" {
			continue
		}
		name := altName(e.Path)
		c := cand{pkg: e.Package, source: e.Expected.Target, priority: e.Expected.Priority}
		cur, ok := best[name]
		if !ok || c.priority > cur.priority || (c.priority == cur.priority && c.pkg < cur.pkg) {
			best[name] = c
		}
	}
	out := make(map[string]Winner, len(best))
	for name, c := range best {
		out[name] = Winner{Package: c.pkg, Source: c.source}
	}
	attachFollowers(out, entries)
	return out
}

// attachFollowers records, for each winner, the follower links contributed by
// the winning package: follower entries (Master != "") whose Master has a
// winner and whose Package is that winner. Mutates winners in place.
func attachFollowers(winners map[string]Winner, entries []schema.OwnershipEntry) {
	for i := range entries {
		e := &entries[i]
		if e.Action != "alternatives" || e.Expected.Master == "" {
			continue
		}
		w, ok := winners[e.Expected.Master]
		if !ok || e.Package != w.Package {
			continue
		}
		if w.Followers == nil {
			w.Followers = map[string]string{}
		}
		w.Followers[e.Path] = e.Expected.Target
		winners[e.Expected.Master] = w
	}
}

// Resolve layers operator selections over auto arbitration. The auto winner
// (Arbitrate — the single source of truth for the priority/tie rule) stands for
// every name, except where a selection names a package that currently provides
// that name: there the selected package wins regardless of priority. A selection
// whose package is not a current provider of its name (including a name with no
// providers at all) is reported in stale and that name falls back to auto.
// Each returned winner carries the followers contributed by its resolved
// (selected or auto) package, so a selection switches its followers in lockstep.
// Pure: no I/O; does not mutate sel.
func Resolve(entries []schema.OwnershipEntry, sel Selections) (winners map[string]Winner, stale []string) {
	winners = Arbitrate(entries)
	// providers: name -> package -> source, over PRIMARY alternatives entries only.
	providers := map[string]map[string]string{}
	for i := range entries {
		e := &entries[i]
		if e.Action != "alternatives" || e.Expected.Master != "" {
			continue
		}
		name := altName(e.Path)
		if providers[name] == nil {
			providers[name] = map[string]string{}
		}
		providers[name][e.Package] = e.Expected.Target
	}
	for name, pkg := range sel {
		src, ok := providers[name][pkg]
		if !ok {
			stale = append(stale, name)
			continue
		}
		winners[name] = Winner{Package: pkg, Source: src} // followers cleared; re-attached below
	}
	attachFollowers(winners, entries) // re-attach against the selection-resolved winners
	sort.Strings(stale)
	return winners, stale
}

// materialize reconciles the stable middle-link area against the given winners:
// the flat primary middle links (<altRoot>/<name>) and the follower middle links
// (<altRoot>/.followers/<link>). It creates/updates every winner's links and
// prunes any pre-existing link no longer wanted, including now-empty follower
// directories. altRoot is created if absent. Writes are symlink-safe via os.Root.
func materialize(altRoot string, winners map[string]Winner) error {
	if err := os.MkdirAll(altRoot, 0o700); err != nil {
		return fmt.Errorf("create alternatives root: %w", err)
	}
	root, err := os.OpenRoot(altRoot)
	if err != nil {
		return fmt.Errorf("open alternatives root: %w", err)
	}
	defer func() { _ = root.Close() }()

	for name, w := range winners {
		if err := root.Remove(name); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("replace alternative %q: %w", name, err)
		}
		if err := root.Symlink(w.Source, name); err != nil {
			return fmt.Errorf("link alternative %q: %w", name, err)
		}
	}
	dents, err := os.ReadDir(altRoot)
	if err != nil {
		return fmt.Errorf("read alternatives root: %w", err)
	}
	for _, d := range dents {
		if d.Name() == FollowersDir {
			continue // the follower subtree is reconciled separately, never pruned here
		}
		if _, keep := winners[d.Name()]; !keep {
			if err := root.Remove(d.Name()); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("prune alternative %q: %w", d.Name(), err)
			}
		}
	}
	return materializeFollowers(root, altRoot, winners)
}

// materializeFollowers writes the winners' follower middle links under
// <altRoot>/.followers/<link> and prunes any follower link (and emptied dir)
// not wanted by the current winners.
func materializeFollowers(root *os.Root, altRoot string, winners map[string]Winner) error {
	expected := map[string]string{} // rel path under altRoot (".followers/<link>") -> source
	for _, w := range winners {
		for link, src := range w.Followers {
			expected[filepath.ToSlash(filepath.Join(FollowersDir, link))] = src
		}
	}
	for rel, src := range expected {
		if err := root.MkdirAll(filepath.Dir(rel), 0o700); err != nil {
			return fmt.Errorf("create follower dir for %q: %w", rel, err)
		}
		if err := root.Remove(rel); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("replace follower %q: %w", rel, err)
		}
		if err := root.Symlink(src, rel); err != nil {
			return fmt.Errorf("link follower %q: %w", rel, err)
		}
	}
	return pruneFollowers(root, altRoot, expected)
}

// pruneFollowers removes follower middle links under <altRoot>/.followers that
// are not in expected, then removes any directory left empty (deepest first).
// Listing uses os.ReadDir on the polypkg-controlled stable area (as the
// top-level prune does); removal goes through the symlink-safe root.
func pruneFollowers(root *os.Root, altRoot string, expected map[string]string) error {
	base := filepath.Join(altRoot, FollowersDir)
	info, err := os.Lstat(base)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat follower root: %w", err)
	}
	if !info.IsDir() {
		return nil
	}
	var dirs []string
	walkErr := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(altRoot, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if rel == FollowersDir {
			return nil
		}
		if d.IsDir() {
			dirs = append(dirs, rel)
			return nil
		}
		if _, keep := expected[rel]; !keep {
			if err := root.Remove(rel); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("prune follower %q: %w", rel, err)
			}
		}
		return nil
	})
	if walkErr != nil {
		return walkErr
	}
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) }) // deepest first
	for _, rel := range dirs {
		ents, rerr := os.ReadDir(filepath.Join(altRoot, rel))
		if rerr != nil {
			if os.IsNotExist(rerr) {
				continue
			}
			return fmt.Errorf("read follower dir %q: %w", rel, rerr)
		}
		if len(ents) == 0 {
			if err := root.Remove(rel); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("prune follower dir %q: %w", rel, err)
			}
		}
	}
	return nil
}

// Reconcile is the selection-aware materialization entry point. It loads
// selections from selectionsPath, resolves winners (a selection overrides the
// auto winner for its name), prunes any stale selection from the store and
// persists the pruned store, writes/reconciles the middle links for the
// winners, and returns the stale selection names so the caller can warn. A
// missing store is treated as empty selections.
func Reconcile(altRoot, selectionsPath string, entries []schema.OwnershipEntry) (stale []string, err error) {
	sel, err := LoadSelections(selectionsPath)
	if err != nil {
		return nil, err
	}
	winners, stale := Resolve(entries, sel)
	if len(stale) > 0 {
		for _, name := range stale {
			delete(sel, name)
		}
		if err := SaveSelections(selectionsPath, sel); err != nil {
			return nil, fmt.Errorf("prune stale selections: %w", err)
		}
	}
	if err := materialize(altRoot, winners); err != nil {
		return nil, err
	}
	return stale, nil
}

// altName extracts the generic name from an alternatives ownership path
// ("bin/editor" -> "editor"). The path is always "<SharedBinDir>/<name>".
func altName(path string) string {
	// Strip the leading "bin/" prefix. The literal matches action.SharedBinDir;
	// we use a string literal here rather than importing action to avoid an
	// import cycle (alternatives is consumed by action).
	return strings.TrimPrefix(path, "bin/")
}

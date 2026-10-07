// Package drift detects divergence between a generation's recorded ownership
// index (the baseline) and the live filesystem under the active root. It is
// pure with respect to policy and acceptance — those are the runner's job.
package drift

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/trevor-vaughan/polypkg/internal/alternatives"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// Reason names what diverged for a drifted entry.
type Reason string

// Drift reason constants name which aspect of a managed entry diverged from
// its recorded baseline; used in audit events and acceptance comparison.
const (
	ReasonMissing  Reason = "missing"
	ReasonContent  Reason = "content"
	ReasonFileType Reason = "filetype"
	ReasonTarget   Reason = "target"
	ReasonMode     Reason = "mode"
)

// Entry is one drifted ownership entry plus the observed state for audit.
type Entry struct {
	Owned    schema.OwnershipEntry
	Reason   Reason
	Observed string
}

// Inspect compares every baseline entry to its live counterpart and returns
// the drifted ones. A nil prior produces a nil result (first apply); an empty
// prior produces an empty (non-nil) result.
func Inspect(prior *schema.Ownership, activeRoot string) ([]Entry, error) {
	if prior == nil {
		return nil, nil
	}
	if len(prior.Entries) == 0 {
		return []Entry{}, nil
	}
	root, err := os.OpenRoot(activeRoot)
	if err != nil {
		return nil, fmt.Errorf("open active root: %w", err)
	}
	defer func() { _ = root.Close() }()

	out := make([]Entry, 0, len(prior.Entries))
	for i := range prior.Entries {
		entry, err := inspectEntry(root, prior.Entries[i])
		if err != nil {
			return nil, fmt.Errorf("inspect %q: %w", prior.Entries[i].Path, err)
		}
		if entry != nil {
			out = append(out, *entry)
		}
	}
	return out, nil
}

// InspectAlternatives checks the two-level alternatives indirection against the
// selection-aware winner. For each alternative name it resolves the winner
// (honoring any manual selection stored at selectionsPath) and verifies the consumer
// link (<activeRoot>/bin/<name> -> <altRoot>/<name>) and the middle link
// (<altRoot>/<name> -> the winner's source). It also checks each winner's
// follower links: the consumer link (<activeRoot>/<link> -> <altRoot>/.followers/<link>)
// and the follower middle link (<altRoot>/.followers/<link> -> the winner's
// follower source). A mismatch on any level is ReasonTarget drift (healed under
// notify_heal). Registration entries themselves are skipped by per-entry Inspect;
// this is the derived pass.
func InspectAlternatives(prior *schema.Ownership, activeRoot, altRoot, selectionsPath string) ([]Entry, error) {
	if prior == nil {
		return nil, nil
	}
	sel, err := alternatives.LoadSelections(selectionsPath)
	if err != nil {
		return nil, fmt.Errorf("load selections %q: %w", selectionsPath, err)
	}
	// stale selections are reconciled (pruned + warned) by apply/rollback, not here.
	winners, _ := alternatives.Resolve(prior.Entries, sel)
	if len(winners) == 0 {
		return []Entry{}, nil
	}
	// Map name -> a representative PRIMARY registration entry, for Entry.Owned.
	repr := map[string]schema.OwnershipEntry{}
	// Map follower link -> its representative entry, for follower Entry.Owned.
	followerRepr := map[string]schema.OwnershipEntry{}
	for i := range prior.Entries {
		e := prior.Entries[i]
		if e.Action != "alternatives" {
			continue
		}
		if e.Expected.Master != "" {
			if _, ok := followerRepr[e.Path]; !ok {
				followerRepr[e.Path] = e
			}
			continue
		}
		name := strings.TrimPrefix(e.Path, "bin/")
		if _, ok := repr[name]; !ok {
			repr[name] = e
		}
	}
	out := make([]Entry, 0)
	names := make([]string, 0, len(winners))
	for name := range winners {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		w := winners[name]
		consumer := filepath.Join(activeRoot, "bin", name)
		wantConsumer := filepath.Join(altRoot, name)
		ctgt, cerr := os.Readlink(consumer)
		if cerr != nil || ctgt != wantConsumer {
			obs := ctgt
			if cerr != nil {
				obs = ""
			}
			out = append(out, Entry{Owned: repr[name], Reason: ReasonTarget, Observed: obs})
			continue
		}
		middle := filepath.Join(altRoot, name)
		mtgt, merr := os.Readlink(middle)
		if merr != nil || mtgt != w.Source {
			obs := mtgt
			if merr != nil {
				obs = ""
			}
			out = append(out, Entry{Owned: repr[name], Reason: ReasonTarget, Observed: obs})
		}
		fLinks := make([]string, 0, len(w.Followers))
		for link := range w.Followers {
			fLinks = append(fLinks, link)
		}
		sort.Strings(fLinks)
		for _, link := range fLinks {
			fWantConsumer := filepath.Join(altRoot, alternatives.FollowersDir, link)
			fConsumer := filepath.Join(activeRoot, link)
			fctgt, fcerr := os.Readlink(fConsumer)
			if fcerr != nil || fctgt != fWantConsumer {
				obs := fctgt
				if fcerr != nil {
					obs = ""
				}
				out = append(out, Entry{Owned: followerRepr[link], Reason: ReasonTarget, Observed: obs})
				continue
			}
			fMiddle := filepath.Join(altRoot, alternatives.FollowersDir, link)
			ftgt, ferr := os.Readlink(fMiddle)
			if ferr != nil || ftgt != w.Followers[link] {
				obs := ftgt
				if ferr != nil {
					obs = ""
				}
				out = append(out, Entry{Owned: followerRepr[link], Reason: ReasonTarget, Observed: obs})
			}
		}
	}
	return out, nil
}

func inspectEntry(root *os.Root, e schema.OwnershipEntry) (*Entry, error) {
	// Non-placement actions own no drift-checkable artifact and are never
	// inspected. This is decided before any filesystem access so that an absent
	// path is not misreported as missing: unmanaged (ghost) creates nothing on
	// disk by design, and a state active-tree symlink may have been removed and
	// will be recreated by the next apply. The ownership entry is retained for
	// lifecycle tracking; the on-disk state of these paths is the app's concern.
	switch e.Action {
	case "unmanaged", "state", "alternatives":
		// alternatives registration entries are not 1:1 disk artifacts: several
		// providers share one bin/<name> path, and the live consumer/middle links
		// are a derived indirection. They are checked by InspectAlternatives (a
		// per-name pass that re-arbitrates), not by per-entry inspection.
		return nil, nil
	}

	info, err := root.Lstat(e.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return &Entry{Owned: e, Reason: ReasonMissing, Observed: "absent"}, nil
	}
	if err != nil {
		return nil, err
	}
	switch e.Action {
	case "install", "config":
		// config is a regular file managed by the operator; its drift rule is
		// identical to install (missing / filetype / content-hash). The runner's
		// decide() maps notify_preserve → "preserved" so the config action can
		// apply its sticky-preserve logic on the next apply.
		return inspectInstall(root, e, info)
	case "symlink", "path":
		return inspectSymlink(root, e, info)
	case "dir":
		return inspectDir(e, info), nil
	case "perms":
		return inspectPerms(e, info), nil
	case "extract":
		return inspectExtract(root, e, info)
	}
	// Actions without a drift rule are not checked.
	return nil, nil
}

func inspectDir(e schema.OwnershipEntry, info os.FileInfo) *Entry {
	if !info.IsDir() {
		return &Entry{Owned: e, Reason: ReasonFileType, Observed: fileTypeOf(info)}
	}
	obs := fmt.Sprintf("%#o", info.Mode().Perm())
	if e.Expected.Mode != "" && obs != e.Expected.Mode {
		return &Entry{Owned: e, Reason: ReasonMode, Observed: obs}
	}
	return nil
}

func inspectPerms(e schema.OwnershipEntry, info os.FileInfo) *Entry {
	obs := fmt.Sprintf("%#o", info.Mode().Perm())
	if e.Expected.Mode != "" && obs != e.Expected.Mode {
		return &Entry{Owned: e, Reason: ReasonMode, Observed: obs}
	}
	return nil
}

func inspectSymlink(root *os.Root, e schema.OwnershipEntry, info os.FileInfo) (*Entry, error) {
	if info.Mode()&os.ModeSymlink == 0 {
		return &Entry{Owned: e, Reason: ReasonFileType, Observed: fileTypeOf(info)}, nil
	}
	target, err := root.Readlink(e.Path)
	if err != nil {
		return nil, err
	}
	if target != e.Expected.Target {
		return &Entry{Owned: e, Reason: ReasonTarget, Observed: target}, nil
	}
	return nil, nil
}

func fileTypeOf(info os.FileInfo) string {
	m := info.Mode()
	switch {
	case m&os.ModeSymlink != 0:
		return "symlink"
	case m.IsDir():
		return "dir"
	default:
		return "regular"
	}
}

package action

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/trevor-vaughan/polypkg/internal/merge"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// Config materializes an operator-mutable file per its replacement policy
// (replace | preserve | preserve_warn | three_way_merge). preserve modes keep
// the operator's live bytes when the path is drifting (PreserveActions) or was
// preserved on a prior apply (sticky invariant on PriorEntry); a queued reset
// (ResetPaths) overrides preserve and force-writes the package's incoming bytes.
func Config(inv Invocation, scope Scope) (Result, error) {
	src, ok := inv.Params["src"].(string)
	if !ok || src == "" {
		return Result{}, fmt.Errorf("config: missing required param 'src'")
	}
	dest, ok := inv.Params["dest"].(string)
	if !ok || dest == "" {
		return Result{}, fmt.Errorf("config: missing required param 'dest'")
	}
	policy, _ := inv.Params["policy"].(string)
	if policy == "" {
		policy = "preserve"
	}
	switch policy {
	case "replace", "preserve", "preserve_warn", "three_way_merge":
	default:
		return Result{}, fmt.Errorf("config: invalid policy %q (want replace|preserve|preserve_warn|three_way_merge)", policy)
	}

	if !scope.AllowsSource(src) {
		return Result{}, fmt.Errorf("config: src %q is outside the package's files", src)
	}
	destRoot, relDest, err := scope.openScope(dest)
	if err != nil {
		return Result{}, fmt.Errorf("config: %w", err)
	}
	defer func() { _ = destRoot.Close() }()

	incoming, err := readPackageFile(scope, src)
	if err != nil {
		return Result{}, fmt.Errorf("config: read src: %w", err)
	}
	incomingHash := blake3Bytes(incoming)

	driftPolicy := "notify_heal"
	if policy != "replace" {
		driftPolicy = "notify_preserve"
	}

	ownPath := filepath.ToSlash(relTo(scope.ActiveRoot, dest))
	reset := inv.ResetPaths[ownPath]
	preserveMode := policy != "replace" && !reset &&
		(inPreserveActions(inv.PreserveActions, ownPath) || stickyPreserve(inv.PriorEntry))

	outBytes, outHash := incoming, incomingHash
	var warnings []ConfigWarning

	if preserveMode && scope.LiveRoot != "" {
		live, lerr := readLive(scope, dest)
		switch {
		case errors.Is(lerr, fs.ErrNotExist):
			// Operator deleted the live file: nothing to preserve; write incoming.
		case lerr != nil:
			return Result{}, fmt.Errorf("config: read live %q: %w", dest, lerr)
		default:
			outBytes, outHash, warnings, err = materializePreserve(policy, scope, destRoot, relDest, dest, live, incoming, inv.PriorEntry)
			if err != nil {
				return Result{}, fmt.Errorf("config: %w", err)
			}
		}
	}

	if err := writeThrough(destRoot, relDest, outBytes, 0o644); err != nil {
		return Result{}, fmt.Errorf("config: write %q: %w", dest, err)
	}
	stat, err := capturedStat(destRoot, relDest)
	if err != nil {
		return Result{}, fmt.Errorf("config: stat dest: %w", err)
	}
	return Result{
		Action:      inv.Action,
		Path:        dest,
		Outcome:     "ok",
		Expected:    schema.Expected{FileType: "regular", ContentHash: outHash, SourceHash: incomingHash},
		Stat:        stat,
		DriftPolicy: driftPolicy,
		SourceBytes: incoming,
		Warnings:    warnings,
	}, nil
}

// materializePreserve returns the bytes to write, their hash, and any warnings
// for a preserve-mode invocation. incoming is still recorded as SourceHash by
// the caller; this function only chooses the on-disk content.
func materializePreserve(policy string, scope Scope, destRoot *os.Root, relDest, dest string, live, incoming []byte, prior *schema.OwnershipEntry) (outBytes []byte, outHash string, warns []ConfigWarning, err error) {
	switch policy {
	case "preserve":
		return live, blake3Bytes(live), nil, nil
	case "preserve_warn":
		if err := writeThrough(destRoot, relDest+".new", incoming, 0o644); err != nil {
			return nil, "", nil, fmt.Errorf("write %s.new: %w", dest, err)
		}
		w := []ConfigWarning{{Kind: "config_preserve_warn", Fields: map[string]any{"path": dest, "new_path": dest + ".new"}}}
		return live, blake3Bytes(live), w, nil
	case "three_way_merge":
		return threeWayMerge(scope, destRoot, relDest, dest, live, incoming, prior)
	default:
		// Unreachable: replace never enters preserve mode; policy validated above.
		return live, blake3Bytes(live), nil, nil
	}
}

func threeWayMerge(scope Scope, destRoot *os.Root, relDest, dest string, live, incoming []byte, prior *schema.OwnershipEntry) (outBytes []byte, outHash string, warns []ConfigWarning, err error) {
	fallback := func(reason string) ([]byte, string, []ConfigWarning, error) {
		if err := writeThrough(destRoot, relDest+".new", incoming, 0o644); err != nil {
			return nil, "", nil, fmt.Errorf("write %s.new: %w", dest, err)
		}
		w := []ConfigWarning{{Kind: "three_way_merge_fallback",
			Fields: map[string]any{"path": dest, "reason": reason, "fallback_action": "preserve_warn"}}}
		return live, blake3Bytes(live), w, nil
	}
	if isBinary(live) {
		return fallback("binary_live")
	}
	base, err := readBase(scope, prior)
	if err != nil {
		return fallback("base_not_in_store")
	}
	if isBinary(incoming) {
		return fallback("binary_incoming")
	}
	if isBinary(base) {
		return fallback("binary_base")
	}
	res, err := merge.Merge(base, live, incoming)
	if err != nil {
		return nil, "", nil, fmt.Errorf("merge %q: %w", dest, err)
	}
	var w []ConfigWarning
	if res.Conflicts > 0 {
		w = []ConfigWarning{{Kind: "three_way_merge_conflicts",
			Fields: map[string]any{"path": dest, "marker_count": res.Conflicts}}}
	}
	return res.Merged, blake3Bytes(res.Merged), w, nil
}

func stickyPreserve(prior *schema.OwnershipEntry) bool {
	return prior != nil &&
		prior.Expected.SourceHash != "" &&
		prior.Expected.ContentHash != prior.Expected.SourceHash
}

func inPreserveActions(m map[string]string, ownPath string) bool {
	_, ok := m[ownPath]
	return ok
}

// relTo returns dest relative to base in OS form. A relativization failure is
// impossible here (dest passed scope confinement) but is reported as the raw
// dest so the ownership key is never silently corrupted.
func relTo(base, dest string) string {
	rel, err := filepath.Rel(base, dest)
	if err != nil {
		return dest
	}
	return rel
}

// readPackageFile reads src from the package's confined files.
func readPackageFile(scope Scope, src string) ([]byte, error) {
	root, rel, err := scope.openPackage(src)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

// readLive reads the live content for dest from the prior generation's active
// tree at LiveRoot/<pkg>/<rel>, confined by an os.Root.
func readLive(scope Scope, dest string) ([]byte, error) {
	rel, ok := relWithin(filepath.Join(scope.ActiveRoot, scope.PackageName), dest)
	if !ok {
		return nil, fmt.Errorf("%q outside scope", dest)
	}
	root, err := os.OpenRoot(scope.LiveRoot)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(filepath.Join(scope.PackageName, rel))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

// readBase reads the three_way_merge base (the package bytes shipped in the
// prior generation) from <PriorGenDir>/config-base/<hash>.
func readBase(scope Scope, prior *schema.OwnershipEntry) ([]byte, error) {
	if prior == nil || prior.Expected.SourceHash == "" || scope.PriorGenDir == "" {
		return nil, fmt.Errorf("no base available")
	}
	root, err := os.OpenRoot(scope.PriorGenDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(schema.ConfigBaseRelPath(prior.Expected.SourceHash))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

// writeThrough creates rel (and parents) within root and writes content with
// the given mode. Idempotent: an existing dest is removed first.
func writeThrough(root *os.Root, rel string, content []byte, mode os.FileMode) (err error) {
	if parent := filepath.Dir(rel); parent != "." {
		if err := root.MkdirAll(parent, 0o700); err != nil {
			return err
		}
	}
	_ = root.Remove(rel)
	f, err := root.OpenFile(rel, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	_, err = f.Write(content)
	return err
}

// isBinary reports whether any of the first 8192 bytes is NUL (git's heuristic).
func isBinary(b []byte) bool {
	head := b
	if len(head) > 8192 {
		head = head[:8192]
	}
	return bytes.IndexByte(head, 0) >= 0
}

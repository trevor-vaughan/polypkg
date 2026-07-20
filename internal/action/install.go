package action

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// Install places a file from src to dest using the specified policy
// ("symlink", "hardlink", or "copy"). The dest must fall within the package's
// scope and src must fall within the package's own extracted files; any path
// outside either boundary returns an error containing "outside". If policy is
// empty it defaults to "symlink".
func Install(inv Invocation, scope Scope) (Result, error) {
	src, ok := inv.Params["src"].(string)
	if !ok || src == "" {
		return Result{}, fmt.Errorf("install: missing required param 'src'")
	}
	dest, ok := inv.Params["dest"].(string)
	if !ok || dest == "" {
		return Result{}, fmt.Errorf("install: missing required param 'dest'")
	}
	policy, _ := inv.Params["policy"].(string)
	if policy == "" {
		policy = "symlink"
	}

	if !scope.AllowsSource(src) {
		return Result{}, fmt.Errorf("install: src %q is outside the package's files", src)
	}

	destRoot, relDest, err := scope.openScope(dest)
	if err != nil {
		return Result{}, fmt.Errorf("install: %w", err)
	}
	defer func() { _ = destRoot.Close() }()

	if parent := filepath.Dir(relDest); parent != "." {
		if err := destRoot.MkdirAll(parent, scope.dirPerm()); err != nil {
			return Result{}, fmt.Errorf("install: create parent dirs for %q: %w", dest, err)
		}
	}
	// Remove any existing dest so the operation is idempotent.
	_ = destRoot.Remove(relDest)

	switch policy {
	case "symlink":
		if err := destRoot.Symlink(src, relDest); err != nil {
			return Result{}, fmt.Errorf("install: symlink %q -> %q: %w", dest, src, err)
		}
	case "copy":
		srcRoot, relSrc, err := scope.openPackage(src)
		if err != nil {
			return Result{}, fmt.Errorf("install: %w", err)
		}
		defer func() { _ = srcRoot.Close() }()
		if err := copyConfined(srcRoot, relSrc, destRoot, relDest); err != nil {
			return Result{}, fmt.Errorf("install: copy %q -> %q: %w", src, dest, err)
		}
	case "hardlink":
		if err := hardlinkConfined(scope, src, relDest); err != nil {
			return Result{}, fmt.Errorf("install: hardlink %q -> %q: %w", dest, src, err)
		}
	default:
		return Result{}, fmt.Errorf("install: unknown policy %q (want symlink|hardlink|copy)", policy)
	}

	fileType := "regular"
	if policy == "symlink" {
		fileType = "symlink"
	}
	// Planner mirrors this hash via HashInstallSource (capture.go) — keep in sync.
	hash, err := hashSource(scope, src)
	if err != nil {
		return Result{}, fmt.Errorf("install: hash source: %w", err)
	}
	stat, err := capturedStat(destRoot, relDest)
	if err != nil {
		return Result{}, fmt.Errorf("install: stat dest: %w", err)
	}
	return Result{
		Action:   inv.Action,
		Path:     dest,
		Outcome:  "ok",
		Expected: schema.Expected{FileType: fileType, ContentHash: hash},
		Stat:     stat,
	}, nil
}

// copyConfined copies relSrc within srcRoot to relDest within dstRoot,
// preserving the source's permission bits. Both ends are confined to their
// roots, so neither the read nor the write can escape via a symlink. The input
// Close error is discarded (read-only fd, content fully consumed); the output
// Close error is captured so a flush failure is not silently lost.
func copyConfined(srcRoot *os.Root, relSrc string, dstRoot *os.Root, relDest string) (err error) {
	in, err := srcRoot.Open(relSrc)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := dstRoot.OpenFile(relDest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	_, err = io.Copy(out, in)
	return err
}

// hardlinkConfined creates a hardlink at relDest (within destRoot) pointing to
// the install source. os.Root.Link cannot span two roots (src lives under the
// package files, dest under the scope), so the link is created via absolute
// paths — but only after both ends are validated through their roots: the
// source is Stat'd through a PackageRoot-confined root (rejecting any escape),
// and the destination's parent directory is created through destRoot, so it is
// a real directory, not a planted symlink.
func hardlinkConfined(scope Scope, src, relDest string) error {
	srcRoot, relSrc, err := scope.openPackage(src)
	if err != nil {
		return err
	}
	defer func() { _ = srcRoot.Close() }()
	if _, err := srcRoot.Stat(relSrc); err != nil {
		return err
	}
	absSrc := filepath.Join(scope.PackageRoot, relSrc)
	absDest := filepath.Join(scope.ActiveRoot, scope.PackageName, relDest)
	return os.Link(absSrc, absDest)
}

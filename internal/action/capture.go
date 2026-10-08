package action

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/trevor-vaughan/polypkg/internal/schema"
	"lukechampine.com/blake3"
)

// HashInstallSource returns the "blake3:<hex>" digest of the install source
// file located at src within pkgRoot, computed identically to the install action
// (hashSource). The planner uses it to project the same content_hash the
// install action records, so a converged system does not report false content
// drift on symlink installs (drift inspection consumes the stored hash).
func HashInstallSource(pkgRoot, src string) (string, error) {
	return hashSource(Scope{PackageRoot: pkgRoot}, src)
}

// hashSource returns the "blake3:<hex>" digest of the install source file,
// opened through a package-confined root so the read cannot escape the package.
func hashSource(scope Scope, src string) (string, error) {
	srcRoot, rel, err := scope.openPackage(src)
	if err != nil {
		return "", err
	}
	defer func() { _ = srcRoot.Close() }()
	return hashConfined(srcRoot, rel)
}

// hashConfined returns the "blake3:<hex>" digest of the regular file at rel,
// read through root so the read cannot escape it. The type is checked before
// the open because opening a FIFO blocks until a writer appears.
func hashConfined(root *os.Root, rel string) (string, error) {
	info, err := root.Stat(rel)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", rel)
	}
	f, err := root.Open(rel)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := blake3.New(32, nil)
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "blake3:" + hex.EncodeToString(h.Sum(nil)), nil
}

// blake3Bytes returns the "blake3:<hex>" digest of in-memory content. Used by
// the config action, which holds incoming/live/merged bytes in memory.
func blake3Bytes(b []byte) string {
	h := blake3.New(32, nil)
	_, _ = h.Write(b)
	return "blake3:" + hex.EncodeToString(h.Sum(nil))
}

// capturedStat lstats rel within root (not following a final symlink) and
// returns its StatInfo via schema.StatInfoFrom.
func capturedStat(root *os.Root, rel string) (schema.StatInfo, error) {
	info, err := root.Lstat(rel)
	if err != nil {
		return schema.StatInfo{}, err
	}
	return schema.StatInfoFrom(info), nil
}

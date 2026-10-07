package drift

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/trevor-vaughan/polypkg/internal/schema"
	"lukechampine.com/blake3"
)

// inspectInstall checks an install entry per apply-semantics §6.1: missing,
// filetype changed, or content hash differs. Incremental hashing (§6.4): if the
// live lstat equals the recorded Stat, the content is assumed unchanged — but
// only for regular files. A symlink install's lstat describes the link, which
// does not change when the extract-cache file it points to is edited, so its
// target is re-hashed on every inspection; a target that no longer exists is
// reported as missing.
func inspectInstall(root *os.Root, e schema.OwnershipEntry, info os.FileInfo) (*Entry, error) {
	obsType := fileTypeOf(info)
	if e.Expected.FileType != "" && obsType != e.Expected.FileType {
		return &Entry{Owned: e, Reason: ReasonFileType, Observed: obsType}, nil
	}
	if obsType != "symlink" && statEquals(schema.StatInfoFrom(info), e.Stat) {
		return nil, nil
	}
	hash, err := HashLiveContent(root, e.Path, obsType)
	if obsType == "symlink" && errors.Is(err, fs.ErrNotExist) {
		return &Entry{Owned: e, Reason: ReasonMissing, Observed: "dangling"}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("hash content: %w", err)
	}
	if hash != e.Expected.ContentHash {
		return &Entry{Owned: e, Reason: ReasonContent, Observed: hash}, nil
	}
	return nil, nil
}

func statEquals(a, b schema.StatInfo) bool {
	return a.Size == b.Size && a.MtimeNs == b.MtimeNs && a.Inode == b.Inode
}

// HashLiveContent returns the blake3:<hex> of the live content at rel. For a
// regular file it reads through the confined root. For a symlink it follows the
// link (the target is polypkg-controlled, e.g. the package extraction dir) and
// reads it directly — necessary because the target lives outside activeRoot and
// os.Root will not follow an escaping symlink. Exported so accept-drift can
// capture the same content hash an install action originally recorded.
func HashLiveContent(root *os.Root, rel, fileType string) (string, error) {
	if fileType == "symlink" {
		target, err := root.Readlink(rel)
		if err != nil {
			return "", err
		}
		f, err := os.Open(filepath.Clean(target))
		if err != nil {
			return "", fmt.Errorf("open symlink target: %w", err)
		}
		defer func() { _ = f.Close() }()
		return hashReader(f)
	}
	f, err := root.Open(rel)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	return hashReader(f)
}

func hashReader(r io.Reader) (string, error) {
	h := blake3.New(32, nil)
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return "blake3:" + hex.EncodeToString(h.Sum(nil)), nil
}

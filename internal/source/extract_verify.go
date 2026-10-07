package source

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// ErrExtractedTreeMismatch reports that a tree ExtractTarZst produced has been
// modified since: it no longer holds exactly what its archive extracts to.
var ErrExtractedTreeMismatch = errors.New("extracted tree does not match its archive")

// archiveEntry is what extraction leaves on disk for one archive member.
type archiveEntry struct {
	typeflag byte
	mode     os.FileMode // permission bits the archive grants (regular files)
	size     int64
	digest   [sha256.Size]byte
	linkname string
}

// VerifyExtractedTarZst checks that dest still holds exactly what
// ExtractTarZst produces from the tar.zst stream r. It returns nil on a match
// and an error wrapping ErrExtractedTreeMismatch naming the first divergence:
// a missing, retyped, or rewritten entry; a regular file carrying a permission
// bit the archive does not grant (extraction can only lose bits, to the umask,
// so a narrower mode matches); a retargeted symlink; an unreadable entry; or a
// path the archive does not produce; or a dest that is not a real directory.
// Directory modes are not compared, because extraction creates implicit
// parents 0o700 regardless of the archive. Any other error means the archive
// could not be read.
// Every dest read goes through an os.Root confined to dest, and the archive is
// held to the same limits as extraction.
func VerifyExtractedTarZst(r io.Reader, dest string) error {
	dec, err := zstd.NewReader(r)
	if err != nil {
		return fmt.Errorf("zstd reader: %w", err)
	}
	defer dec.Close()
	return verifyExtractedTar(dec, dest, defaultExtractLimits())
}

// verifyExtractedTar is VerifyExtractedTarZst on an uncompressed tar stream,
// split out like extractTar so the round trip can be fuzzed on raw tar bytes.
func verifyExtractedTar(r io.Reader, dest string, lim extractLimits) error {
	want, err := archiveEntries(r, lim)
	if err != nil {
		return err
	}
	// dest itself must be a real directory: os.OpenRoot follows a symlink,
	// and a regular file or dangling link would fail it with an error the
	// caller cannot repair. Checking the opened root against the lstat
	// closes the window for a swap between the two.
	destInfo, err := os.Lstat(dest)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrExtractedTreeMismatch, dest, err)
	}
	if !destInfo.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrExtractedTreeMismatch, dest)
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrExtractedTreeMismatch, dest, err)
	}
	defer func() { _ = root.Close() }()
	if rootInfo, err := root.Stat("."); err != nil || !os.SameFile(destInfo, rootInfo) {
		return fmt.Errorf("%w: %s changed while it was being opened", ErrExtractedTreeMismatch, dest)
	}
	for _, name := range slices.Sorted(maps.Keys(want)) {
		if err := verifyEntry(root, name, want[name]); err != nil {
			return err
		}
	}
	return verifyNoExtras(root, want)
}

// archiveEntries reads the tar stream r and returns, per cleaned path, the
// entry extraction materializes there. A later duplicate replaces an earlier
// one, as extraction overwrites it; entry types extraction skips are omitted.
func archiveEntries(r io.Reader, lim extractLimits) (map[string]archiveEntry, error) {
	tr := tar.NewReader(r)
	want := map[string]archiveEntry{}
	var totalBytes int64
	entries := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return want, nil
		}
		if err != nil {
			return nil, fmt.Errorf("tar next: %w", err)
		}
		entries++
		if entries > lim.maxEntries {
			return nil, fmt.Errorf("verification rejected: archive exceeds %d entries", lim.maxEntries)
		}
		name := filepath.Clean(hdr.Name)
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("path traversal rejected: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir, tar.TypeReg, tar.TypeSymlink:
			if p, ok := symlinkOnRoute(want, name); ok {
				return nil, fmt.Errorf("verification rejected: %s passes through or replaces the symlink %s", name, p)
			}
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			want[name] = archiveEntry{typeflag: tar.TypeDir}
		case tar.TypeReg:
			if hdr.Size > lim.maxFileBytes {
				return nil, fmt.Errorf("verification rejected: %s declares %d bytes, exceeds limit %d", hdr.Name, hdr.Size, lim.maxFileBytes)
			}
			if totalBytes+hdr.Size > lim.maxTotalBytes {
				return nil, fmt.Errorf("verification rejected: total size would exceed limit %d", lim.maxTotalBytes)
			}
			h := sha256.New()
			n, err := io.CopyN(h, tr, hdr.Size)
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", hdr.Name, err)
			}
			totalBytes += n
			// Only the permission bits can be on disk: extraction refuses a
			// mode with setuid/setgid/sticky (os.Root's OpenFile fails with
			// "unsupported file mode"), and it always adds owner-read.
			e := archiveEntry{typeflag: tar.TypeReg, mode: os.FileMode(hdr.Mode&0o777) | 0o400, size: n}
			// A duplicate regular entry is rewritten through O_TRUNC, which
			// keeps the existing file's mode: the first entry's mode is the
			// one on disk.
			if prev, ok := want[name]; ok && prev.typeflag == tar.TypeReg {
				e.mode = prev.mode
			}
			copy(e.digest[:], h.Sum(nil))
			want[name] = e
		case tar.TypeSymlink:
			want[name] = archiveEntry{typeflag: tar.TypeSymlink, linkname: hdr.Linkname}
		}
	}
}

// symlinkOnRoute mirrors extraction's refuseSymlinkRoute against the entries
// read so far: it reports the first symlink among name's ancestors or name
// itself.
func symlinkOnRoute(want map[string]archiveEntry, name string) (string, bool) {
	parts := strings.Split(name, string(filepath.Separator))
	for i := range parts {
		p := filepath.Join(parts[:i+1]...)
		if want[p].typeflag == tar.TypeSymlink {
			return p, true
		}
	}
	return "", false
}

// verifyEntry compares one archive entry against its counterpart under root.
func verifyEntry(root *os.Root, name string, e archiveEntry) error {
	info, err := root.Lstat(name)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrExtractedTreeMismatch, name, err)
	}
	switch e.typeflag {
	case tar.TypeDir:
		if !info.IsDir() {
			return fmt.Errorf("%w: %s is no longer a directory", ErrExtractedTreeMismatch, name)
		}
	case tar.TypeSymlink:
		if info.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("%w: %s is no longer a symlink", ErrExtractedTreeMismatch, name)
		}
		target, err := root.Readlink(name)
		if err != nil {
			return fmt.Errorf("%w: %s: %w", ErrExtractedTreeMismatch, name, err)
		}
		if target != e.linkname {
			return fmt.Errorf("%w: %s now points to %q", ErrExtractedTreeMismatch, name, target)
		}
	case tar.TypeReg:
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%w: %s is no longer a regular file", ErrExtractedTreeMismatch, name)
		}
		if extra := info.Mode().Perm() &^ e.mode; extra != 0 {
			return fmt.Errorf("%w: %s gained mode bits %#o", ErrExtractedTreeMismatch, name, extra)
		}
		if info.Size() != e.size {
			return fmt.Errorf("%w: %s changed size", ErrExtractedTreeMismatch, name)
		}
		f, err := root.Open(name)
		if err != nil {
			return fmt.Errorf("%w: %s: %w", ErrExtractedTreeMismatch, name, err)
		}
		defer func() { _ = f.Close() }()
		h := sha256.New()
		if _, err := io.Copy(h, io.LimitReader(f, e.size+1)); err != nil {
			return fmt.Errorf("%w: %s: %w", ErrExtractedTreeMismatch, name, err)
		}
		if !bytes.Equal(h.Sum(nil), e.digest[:]) {
			return fmt.Errorf("%w: %s content changed", ErrExtractedTreeMismatch, name)
		}
	}
	return nil
}

// verifyNoExtras walks root without following symlinks and reports the first
// path extraction would not have produced. A directory that is only an
// ancestor of an archive entry is expected: extraction creates it implicitly.
func verifyNoExtras(root *os.Root, want map[string]archiveEntry) error {
	parents := map[string]bool{}
	for name := range want {
		for d := filepath.Dir(name); d != "."; d = filepath.Dir(d) {
			parents[d] = true
		}
	}
	return fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("%w: %s: %w", ErrExtractedTreeMismatch, p, err)
		}
		if p == "." {
			return nil
		}
		if _, ok := want[p]; ok {
			return nil
		}
		if d.IsDir() && parents[p] {
			return nil
		}
		return fmt.Errorf("%w: unexpected %s", ErrExtractedTreeMismatch, p)
	})
}

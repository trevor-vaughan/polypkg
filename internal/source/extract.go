package source

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// Extraction limits guard against decompression bombs: a small tar.zst that
// expands to fill the disk, or that contains an unbounded number of entries.
const (
	defaultMaxFileBytes  int64 = 1 << 30 // 1 GiB per file
	defaultMaxTotalBytes int64 = 2 << 30 // 2 GiB total across all files
	defaultMaxEntries          = 100_000 // total tar entries (files, dirs, links)
)

// extractLimits bounds resource use during extraction. They are injectable so
// the bomb-rejection paths can be tested without producing gigabyte fixtures.
type extractLimits struct {
	maxFileBytes  int64
	maxTotalBytes int64
	maxEntries    int
}

func defaultExtractLimits() extractLimits {
	return extractLimits{
		maxFileBytes:  defaultMaxFileBytes,
		maxTotalBytes: defaultMaxTotalBytes,
		maxEntries:    defaultMaxEntries,
	}
}

// ExtractTarZst decompresses and extracts a tar.zst stream into dest.
//
// Every filesystem operation is performed through an os.Root confined to dest,
// so no entry can create or modify anything outside dest — not via "../"
// traversal, not via an absolute path, and not by writing through a symlink
// (whether shipped in the archive or already present in dest). The kernel
// (openat2/RESOLVE_BENEATH on Linux) enforces this; the explicit traversal and
// symlink-target rejections below are a hygiene layer with friendlier errors,
// not the sole defense. Total extracted size and entry count are bounded to
// defend against decompression bombs.
func ExtractTarZst(r io.Reader, dest string) error {
	return extractTarZst(r, dest, defaultExtractLimits())
}

func extractTarZst(r io.Reader, dest string, lim extractLimits) error {
	dec, err := zstd.NewReader(r)
	if err != nil {
		return fmt.Errorf("zstd reader: %w", err)
	}
	defer dec.Close()
	return extractTar(dec, dest, lim)
}

// extractTar extracts an uncompressed tar stream into dest with the same
// os.Root confinement and limits as ExtractTarZst. It is split out from the
// zstd layer so the extraction and path-confinement logic can be fuzzed
// directly on raw tar bytes, without paying the decompressor cost per iteration.
func extractTar(r io.Reader, dest string, lim extractLimits) error {
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return fmt.Errorf("mkdir dest: %w", err)
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		return fmt.Errorf("open dest root: %w", err)
	}
	defer func() { _ = root.Close() }()

	tr := tar.NewReader(r)
	var (
		totalBytes int64
		entries    int
	)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("tar next: %w", err)
		}

		entries++
		if entries > lim.maxEntries {
			return fmt.Errorf("extraction rejected: archive exceeds %d entries", lim.maxEntries)
		}

		name := filepath.Clean(hdr.Name)
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return fmt.Errorf("path traversal rejected: %s", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			// Mask to the 12 POSIX mode bits: strips non-permission bits and
			// keeps the int64->FileMode conversion provably in range.
			if err := root.MkdirAll(name, os.FileMode(hdr.Mode&0o7777)); err != nil {
				return fmt.Errorf("mkdir %s: %w", hdr.Name, err)
			}
		case tar.TypeReg:
			if hdr.Size > lim.maxFileBytes {
				return fmt.Errorf("extraction rejected: %s declares %d bytes, exceeds limit %d", hdr.Name, hdr.Size, lim.maxFileBytes)
			}
			if totalBytes+hdr.Size > lim.maxTotalBytes {
				return fmt.Errorf("extraction rejected: total size would exceed limit %d", lim.maxTotalBytes)
			}
			if dir := filepath.Dir(name); dir != "." {
				if err := root.MkdirAll(dir, 0o700); err != nil {
					return fmt.Errorf("mkdir parent of %s: %w", hdr.Name, err)
				}
			}
			f, err := root.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode&0o7777))
			if err != nil {
				return fmt.Errorf("create %s: %w", hdr.Name, err)
			}
			// CopyN bounds the write to the declared size, capping decompression
			// bombs and satisfying the bounded-copy requirement.
			n, err := io.CopyN(f, tr, hdr.Size)
			if err != nil {
				_ = f.Close()
				return fmt.Errorf("copy %s: %w", hdr.Name, err)
			}
			_ = f.Close()
			totalBytes += n
		case tar.TypeSymlink:
			// os.Root confines the link's placement and refuses to traverse it
			// out of dest later. We additionally refuse to even create a link
			// whose target escapes the tree, so a package never ships one.
			if filepath.IsAbs(hdr.Linkname) {
				return fmt.Errorf("path traversal rejected (absolute symlink target): %s -> %s", hdr.Name, hdr.Linkname)
			}
			// G305: resolved is used only to reject escaping links; the link is
			// created through os.Root below, which confines it regardless.
			resolved := filepath.Clean(filepath.Join(filepath.Dir(name), hdr.Linkname)) //nolint:gosec // G305: validation-only; os.Root performs the confined creation
			if resolved == ".." || strings.HasPrefix(resolved, ".."+string(filepath.Separator)) {
				return fmt.Errorf("path traversal rejected (symlink target escapes): %s -> %s", hdr.Name, hdr.Linkname)
			}
			if dir := filepath.Dir(name); dir != "." {
				if err := root.MkdirAll(dir, 0o700); err != nil {
					return fmt.Errorf("mkdir parent of %s: %w", hdr.Name, err)
				}
			}
			if err := root.Symlink(hdr.Linkname, name); err != nil {
				return fmt.Errorf("symlink %s: %w", hdr.Name, err)
			}
		default:
			// Skip unsupported entry types (devices, fifos, hardlinks, etc.)
		}
	}
	return nil
}

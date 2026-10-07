package source

import (
	"fmt"
	"io"
	"os"

	"github.com/klauspost/compress/zstd"
	"github.com/trevor-vaughan/polypkg/internal/archive"
)

// ExtractTarZst decompresses and extracts a tar.zst stream into dest.
//
// Every filesystem operation is performed through an os.Root confined to dest,
// so no entry can create or modify anything outside dest — not via "../"
// traversal, not via an absolute path, and not by writing through a symlink
// (whether shipped in the archive or already present in dest). The kernel
// (openat2/RESOLVE_BENEATH on Linux) enforces this; the explicit traversal and
// symlink-target rejections in archive.ExtractTar are a hygiene layer with
// friendlier errors, not the sole defense. Total extracted size and entry
// count are bounded by archive.DefaultLimits to defend against decompression
// bombs.
func ExtractTarZst(r io.Reader, dest string) error {
	return extractTarZst(r, dest, archive.DefaultLimits())
}

func extractTarZst(r io.Reader, dest string, lim archive.Limits) error {
	dec, err := zstd.NewReader(r)
	if err != nil {
		return fmt.Errorf("zstd reader: %w", err)
	}
	defer dec.Close()
	return extractTar(dec, dest, lim)
}

// extractTar extracts an uncompressed tar stream into dest, creating dest
// 0o700 if needed, under archive.PolicyPackage with implicit parents 0o700.
// It is split out from the zstd layer so the extraction and path-confinement
// logic can be fuzzed directly on raw tar bytes, without paying the
// decompressor cost per iteration.
func extractTar(r io.Reader, dest string, lim archive.Limits) error {
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return fmt.Errorf("mkdir dest: %w", err)
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		return fmt.Errorf("open dest root: %w", err)
	}
	defer func() { _ = root.Close() }()
	_, err = archive.ExtractTar(r, root, archive.Options{
		Policy:  archive.PolicyPackage,
		Limits:  lim,
		DirPerm: 0o700,
	})
	return err
}

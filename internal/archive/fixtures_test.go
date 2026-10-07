package archive_test

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/archive"
)

// Fixture member kinds. Not every kind exists in every container: tar has no
// sockets; zip has no hardlinks, raw type flags or pax global headers.
const (
	fixtureFile     = "file"
	fixtureDir      = "dir"
	fixtureSymlink  = "symlink"
	fixtureHardlink = "hardlink"
	fixtureChar     = "char"
	fixtureBlock    = "block"
	fixtureFIFO     = "fifo"
	fixtureSocket   = "socket"
	fixtureGlobal   = "global"  // pax global header: metadata, never a file
	fixtureRawTar   = "raw-tar" // tar entry carrying the literal typeflag
)

// fixtureMember describes one archive member. Fixtures encode members
// verbatim, without sanitising, so tests can build hostile archives.
type fixtureMember struct {
	name     string
	kind     string
	mode     fs.FileMode // permission plus setuid/setgid/sticky; zero picks a per-kind default
	body     string      // file content (the pax comment for fixtureGlobal)
	target   string      // symlink or hardlink target
	typeflag byte        // fixtureRawTar only
}

// fileMode returns the member's mode, defaulting by kind.
func (m fixtureMember) fileMode() fs.FileMode {
	if m.mode != 0 {
		return m.mode
	}
	switch m.kind {
	case fixtureDir:
		return 0o755
	case fixtureSymlink:
		return 0o777
	default:
		return 0o644
	}
}

// tarMode converts a FileMode to the tar header's POSIX mode bits.
func tarMode(m fs.FileMode) int64 {
	mode := int64(m.Perm())
	if m&fs.ModeSetuid != 0 {
		mode |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		mode |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		mode |= 0o1000
	}
	return mode
}

// fixtureTar encodes members as an uncompressed tar stream.
func fixtureTar(tb testing.TB, members ...fixtureMember) []byte {
	tb.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range members {
		hdr := &tar.Header{Name: m.name, Linkname: m.target, Mode: tarMode(m.fileMode())}
		switch m.kind {
		case fixtureFile:
			hdr.Typeflag, hdr.Size = tar.TypeReg, int64(len(m.body))
		case fixtureDir:
			hdr.Typeflag = tar.TypeDir
		case fixtureSymlink:
			hdr.Typeflag = tar.TypeSymlink
		case fixtureHardlink:
			hdr.Typeflag = tar.TypeLink
		case fixtureChar:
			hdr.Typeflag = tar.TypeChar
		case fixtureBlock:
			hdr.Typeflag = tar.TypeBlock
		case fixtureFIFO:
			hdr.Typeflag = tar.TypeFifo
		case fixtureGlobal:
			hdr = &tar.Header{Name: m.name, Typeflag: tar.TypeXGlobalHeader, PAXRecords: map[string]string{"comment": m.body}}
		case fixtureRawTar:
			hdr.Typeflag = m.typeflag
		default:
			tb.Fatalf("fixtureTar: a %s member cannot be expressed in tar", m.kind)
		}
		if err := tw.WriteHeader(hdr); err != nil {
			tb.Fatalf("tar header %q: %v", m.name, err)
		}
		if m.kind == fixtureFile {
			if _, err := tw.Write([]byte(m.body)); err != nil {
				tb.Fatalf("tar body %q: %v", m.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		tb.Fatalf("tar close: %v", err)
	}
	return buf.Bytes()
}

// fixtureUnexpressible names why members cannot be encoded in format, or
// returns "" when they can.
func fixtureUnexpressible(format archive.Format, members []fixtureMember) string {
	for _, m := range members {
		switch {
		case format == archive.FormatZip && (m.kind == fixtureHardlink || m.kind == fixtureRawTar || m.kind == fixtureGlobal):
			return fmt.Sprintf("a %s member cannot be expressed in zip", m.kind)
		case format != archive.FormatZip && m.kind == fixtureSocket:
			return "a socket member cannot be expressed in tar"
		case format != archive.FormatZip && strings.ContainsRune(m.name, 0):
			return "a NUL in a member name cannot be expressed in tar"
		}
	}
	return ""
}

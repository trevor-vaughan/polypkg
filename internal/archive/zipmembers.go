package archive

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
)

// maxZipLinkTarget bounds a zip symlink's target, which zip stores as the
// member's content. It matches Linux's PATH_MAX.
const maxZipLinkTarget = 4096

// zipMembers walks a zip archive's members in central-directory order.
func zipMembers(zr *zip.Reader) memberWalker {
	return func(visit func(strictMember) error) error {
		for _, f := range zr.File {
			if err := visitZipFile(f, visit); err != nil {
				return err
			}
		}
		return nil
	}
}

// visitZipFile maps one zip member to a strictMember. The member's type comes
// from its external attributes, which is how zip records Unix symlinks,
// devices, FIFOs and sockets.
func visitZipFile(f *zip.File, visit func(strictMember) error) error {
	mode := f.Mode()
	m := strictMember{name: f.Name, exec: mode&0o111 != 0}
	switch {
	case mode.IsRegular():
		m.kind = KindFile
	case mode.IsDir():
		m.kind = KindDir
	case mode&fs.ModeSymlink != 0:
		m.kind = KindSymlink
	case mode&fs.ModeNamedPipe != 0:
		m.refusal = "FIFO"
	case mode&fs.ModeSocket != 0:
		m.refusal = "socket"
	case mode&fs.ModeCharDevice != 0:
		m.refusal = "character device"
	case mode&fs.ModeDevice != 0:
		m.refusal = "block device"
	default:
		m.refusal = fmt.Sprintf("zip entry of unsupported type %v", mode.Type())
	}
	if m.kind != KindFile && m.kind != KindSymlink {
		return visit(m)
	}
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("open zip member %q: %w", f.Name, err)
	}
	defer func() { _ = rc.Close() }()
	if m.kind == KindFile {
		m.body = rc
		return visit(m)
	}
	target, err := io.ReadAll(io.LimitReader(rc, maxZipLinkTarget+1))
	if err != nil {
		return fmt.Errorf("read zip member %q: %w", f.Name, err)
	}
	if len(target) > maxZipLinkTarget {
		return fmt.Errorf("extraction rejected: symlink %q has a target longer than %d bytes", f.Name, maxZipLinkTarget)
	}
	m.linkname = string(target)
	return visit(m)
}

// Package archive extracts archives into a directory confined by an os.Root.
//
// Every filesystem operation goes through the caller's os.Root, so no member
// can create or modify anything outside it — not via "../" traversal, not via
// an absolute path, and not by writing through a symlink (whether shipped in
// the archive or already present under the root). The kernel
// (openat2/RESOLVE_BENEATH on Linux) enforces this; the explicit traversal and
// symlink-route rejections here are a hygiene layer with friendlier errors,
// not the sole defense. Limits bound the bytes written and the number of
// members, to defend against decompression bombs.
package archive

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Limits bounds resource use during one extraction. The byte limits apply to
// the bytes actually written; a member's declared size is checked first only
// so an oversized member fails before anything is written for it.
type Limits struct {
	MaxFileBytes  int64 // largest single regular file
	MaxTotalBytes int64 // all regular files together
	MaxEntries    int   // members of any type, skipped ones included; under PolicyStrict every directory created, implicit parents included, counts too
}

// DefaultLimits returns the limits polypkg extracts with: 1 GiB per file,
// 2 GiB in total, and 100 000 members.
func DefaultLimits() Limits {
	return Limits{MaxFileBytes: 1 << 30, MaxTotalBytes: 2 << 30, MaxEntries: 100_000}
}

// Policy selects which members extraction accepts and the modes it creates
// them with. The zero value is not a policy, so Options that never chose one
// are refused rather than extracted under a default.
type Policy int

const (
	_ Policy = iota

	// PolicyPackage is how polypkg unpacks its own package artifacts.
	// Directories, regular files and symlinks whose target stays inside the
	// root are created; hardlinks, devices, FIFOs and every other member type
	// are skipped without error. A file keeps its archive permission bits plus
	// owner-read, an explicit directory its bits plus owner rwx; a mode that
	// carries setuid, setgid or sticky is refused. A later regular file at the
	// same path rewrites the earlier one's content and keeps its mode.
	PolicyPackage
	// PolicyStrict extracts third-party archives: it refuses every entry type
	// other than regular files, directories and in-root symlinks, refuses
	// duplicate members, normalises file modes to 0o755/0o644, creates
	// directories with Options.DirPerm, ignores ownership and mtimes, and
	// applies Options.StripComponents and Options.Include.
	PolicyStrict
)

// Options configures one extraction.
type Options struct {
	// Format is the archive's container format, normally chosen by Detect.
	// Extract dispatches on it; ExtractTar ignores it, since its input is
	// already an uncompressed tar stream.
	Format Format
	Policy Policy
	Limits Limits
	// StripComponents drops this many leading path segments from every member
	// name, as tar --strip-components does; a member left with none is
	// skipped, but an archive whose every member is left with none is
	// refused. PolicyStrict only.
	StripComponents int
	// Include, when non-empty, extracts only members whose stripped path, or
	// one of its ancestor directories, matches one of these path.Match
	// patterns. A pattern that matches no member is an error. PolicyStrict
	// only.
	Include []string
	// DirPerm is the permission for directories created implicitly as the
	// missing parents of a regular-file or symlink member. The missing
	// ancestors of an explicit directory member take that member's own mode
	// instead. It must be non-zero and hold only the nine permission bits.
	// Under PolicyStrict every directory, explicit or implicit, gets exactly
	// DirPerm, which must also include owner rwx.
	DirPerm fs.FileMode
}

// Placed is one filesystem object an extraction created or wrote.
type Placed struct {
	Path   string      // slash-separated, relative to the root
	Kind   string      // KindFile, KindDir or KindSymlink
	Mode   fs.FileMode // permission requested at creation (under PolicyPackage the umask may clear bits; PolicyStrict sets it exactly); zero for a symlink
	Target string      // a symlink's target, as the archive stores it
}

// Placed.Kind values.
const (
	KindFile    = "file"
	KindDir     = "dir"
	KindSymlink = "symlink"
)

// ExtractTar extracts the uncompressed tar stream r into root under opts and
// returns what it placed, in archive order. Each path is reported once, at
// its first placement: a later member that rewrites a file or names an
// existing directory does not change the record, and a directory that already
// existed under root is not reported at all. A regular file that already
// existed under root is reported when a member rewrites it. On error
// ExtractTar returns a nil slice and root may hold a partial tree, so callers
// extract into a directory they discard on failure.
// With PolicyStrict the stream goes through the strict extractor (see
// PolicyStrict); StripComponents and Include are honoured only there.
func ExtractTar(r io.Reader, root *os.Root, opts Options) ([]Placed, error) {
	if opts.Policy == PolicyStrict {
		return extractStrict(tarMembers(r), root, opts)
	}
	if opts.StripComponents != 0 || len(opts.Include) > 0 {
		return nil, errors.New("archive: StripComponents and Include are only supported with PolicyStrict")
	}
	if err := opts.validate(); err != nil {
		return nil, err
	}
	x := extraction{root: root, opts: opts, seen: map[string]bool{}}
	tr := tar.NewReader(r)
	entries := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return x.placed, nil
		}
		if err != nil {
			return nil, fmt.Errorf("tar next: %w", err)
		}

		entries++
		if entries > opts.Limits.MaxEntries {
			return nil, fmt.Errorf("extraction rejected: archive exceeds %d entries", opts.Limits.MaxEntries)
		}

		name := filepath.Clean(hdr.Name)
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("path traversal rejected: %s", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir, tar.TypeReg, tar.TypeSymlink:
			if err := refuseSymlinkRoute(root, name); err != nil {
				return nil, err
			}
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			err = x.dir(hdr, name)
		case tar.TypeReg:
			err = x.file(hdr, name, tr)
		case tar.TypeSymlink:
			err = x.symlink(hdr, name)
		default:
			// Skip unsupported entry types (devices, fifos, hardlinks, etc.)
		}
		if err != nil {
			return nil, err
		}
	}
}

func (o Options) validate() error {
	if o.Policy != PolicyPackage {
		return fmt.Errorf("unknown extraction policy %d", o.Policy)
	}
	if o.Limits.MaxFileBytes <= 0 || o.Limits.MaxTotalBytes <= 0 || o.Limits.MaxEntries <= 0 {
		return fmt.Errorf("extraction limits must be positive, got %+v", o.Limits)
	}
	if o.DirPerm == 0 || o.DirPerm&fs.ModePerm != o.DirPerm {
		return fmt.Errorf("directory permission %v must be non-zero and hold only permission bits", o.DirPerm)
	}
	return nil
}

// extraction is the state of one ExtractTar call.
type extraction struct {
	root   *os.Root
	opts   Options
	total  int64           // regular-file bytes written so far
	seen   map[string]bool // paths already in placed
	placed []Placed
}

func (x *extraction) dir(hdr *tar.Header, name string) error {
	// Mask to the 12 POSIX mode bits: strips non-permission bits and keeps the
	// int64->FileMode conversion provably in range. The owner always keeps
	// rwx, so the tree stays readable and verifiable. Setuid, setgid and
	// sticky survive the mask as raw 0o7000 bits, not fs.ModeSetuid and
	// friends; os.Root refuses any perm above 0o777 with "unsupported file
	// mode", and that refusal is what rejects them.
	if err := x.mkdirAll(name, os.FileMode(hdr.Mode&0o7777)|0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", hdr.Name, err)
	}
	return nil
}

func (x *extraction) file(hdr *tar.Header, name string, r io.Reader) error {
	lim := x.opts.Limits
	if hdr.Size > lim.MaxFileBytes {
		return fmt.Errorf("extraction rejected: %s declares %d bytes, exceeds limit %d", hdr.Name, hdr.Size, lim.MaxFileBytes)
	}
	if x.total+hdr.Size > lim.MaxTotalBytes {
		return fmt.Errorf("extraction rejected: total size would exceed limit %d", lim.MaxTotalBytes)
	}
	if err := x.mkdirParent(hdr.Name, name); err != nil {
		return err
	}
	// The owner always keeps read, so the file stays verifiable. As in dir,
	// setuid, setgid and sticky survive as raw 0o7000 bits, which os.Root
	// refuses as "unsupported file mode".
	mode := os.FileMode(hdr.Mode&0o7777) | 0o400
	f, err := x.root.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", hdr.Name, err)
	}
	// CopyN bounds the write to the declared size, capping decompression
	// bombs and satisfying the bounded-copy requirement.
	n, err := io.CopyN(f, r, hdr.Size)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("copy %s: %w", hdr.Name, err)
	}
	_ = f.Close()
	x.total += n
	x.record(Placed{Path: filepath.ToSlash(name), Kind: KindFile, Mode: mode})
	return nil
}

func (x *extraction) symlink(hdr *tar.Header, name string) error {
	// os.Root confines the link's placement and refuses to traverse it out of
	// the root later. We additionally refuse to even create a link whose
	// target escapes the tree, so a package never ships one.
	if filepath.IsAbs(hdr.Linkname) {
		return fmt.Errorf("path traversal rejected (absolute symlink target): %s -> %s", hdr.Name, hdr.Linkname)
	}
	// G305: resolved is used only to reject escaping links; the link is
	// created through os.Root below, which confines it regardless.
	resolved := filepath.Clean(filepath.Join(filepath.Dir(name), hdr.Linkname)) //nolint:gosec // G305: validation-only; os.Root performs the confined creation
	if resolved == ".." || strings.HasPrefix(resolved, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path traversal rejected (symlink target escapes): %s -> %s", hdr.Name, hdr.Linkname)
	}
	if err := x.mkdirParent(hdr.Name, name); err != nil {
		return err
	}
	if err := x.root.Symlink(hdr.Linkname, name); err != nil {
		return fmt.Errorf("symlink %s: %w", hdr.Name, err)
	}
	x.record(Placed{Path: filepath.ToSlash(name), Kind: KindSymlink, Target: hdr.Linkname})
	return nil
}

// mkdirParent creates the missing parents of the member at name with
// Options.DirPerm. entry is the member's name as the archive spells it, for
// the error.
func (x *extraction) mkdirParent(entry, name string) error {
	dir := filepath.Dir(name)
	if dir == "." {
		return nil
	}
	if err := x.mkdirAll(dir, x.opts.DirPerm); err != nil {
		return fmt.Errorf("mkdir parent of %s: %w", entry, err)
	}
	return nil
}

// mkdirAll is root.MkdirAll that records each directory it created.
func (x *extraction) mkdirAll(name string, perm fs.FileMode) error {
	missing := x.missingDirs(name)
	if err := x.root.MkdirAll(name, perm); err != nil {
		return err
	}
	for _, d := range missing {
		x.record(Placed{Path: filepath.ToSlash(d), Kind: KindDir, Mode: perm})
	}
	return nil
}

// missingDirs returns name and those of its ancestors that do not yet exist
// under the root, shallowest first; below the first missing one, every
// deeper one is missing too. An Lstat error other than not-exist ends the
// scan with nothing missing: root.MkdirAll then meets and reports it.
func (x *extraction) missingDirs(name string) []string {
	parts := strings.Split(name, string(filepath.Separator))
	for i := range parts {
		_, err := x.root.Lstat(filepath.Join(parts[:i+1]...))
		if err == nil {
			continue
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		missing := make([]string, 0, len(parts)-i)
		for j := i; j < len(parts); j++ {
			missing = append(missing, filepath.Join(parts[:j+1]...))
		}
		return missing
	}
	return nil
}

// record appends p to the result unless its path was already placed.
func (x *extraction) record(p Placed) {
	if x.seen[p.Path] {
		return
	}
	x.seen[p.Path] = true
	x.placed = append(x.placed, p)
}

// refuseSymlinkRoute rejects an entry whose path runs through, or lands on, a
// symlink already under the root. os.Root keeps such a write inside the root,
// but it still lands somewhere other than the entry's own path (a/b written
// through a -> c becomes c/b), so the extracted tree would not be the one the
// archive lists, and no legitimate package needs it. This covers symlinks the
// archive itself created and any that were under the root beforehand.
func refuseSymlinkRoute(root *os.Root, name string) error {
	parts := strings.Split(name, string(filepath.Separator))
	for i := range parts {
		p := filepath.Join(parts[:i+1]...)
		info, err := root.Lstat(p)
		if err != nil {
			// Nothing exists here, so nothing deeper does either; any other
			// error is left for the entry's own operation to report.
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("extraction rejected: %s passes through or replaces the symlink %s", name, p)
		}
	}
	return nil
}

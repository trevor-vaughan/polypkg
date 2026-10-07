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
	MaxEntries    int   // members of any type, skipped ones included, plus every directory created as a member's implicit parent
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
	// Directories, regular files and symlinks are created; hardlinks, devices,
	// FIFOs and every other member type are skipped without error. A symlink
	// target must pass the same check as under PolicyStrict: not absolute, not
	// escaping the root, and no ".." after a named segment. A file keeps its
	// archive permission bits plus owner-read, an explicit directory its bits
	// plus owner rwx; a mode that carries setuid, setgid or sticky is refused.
	// A later regular file at the same path rewrites the earlier one's content
	// and keeps its mode.
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
	x := extraction{root: root, opts: opts, dirs: map[string]bool{".": true}, seen: map[string]bool{}}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return x.placed, nil
		}
		if err != nil {
			return nil, fmt.Errorf("tar next: %w", err)
		}
		if err := x.countEntry(); err != nil {
			return nil, err
		}
		if err := CheckNameBounds(hdr.Name); err != nil {
			return nil, fmt.Errorf("extraction rejected: %w", err)
		}
		name := filepath.Clean(hdr.Name)
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("path traversal rejected: %s", hdr.Name)
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
	root    *os.Root
	opts    Options
	entries int             // members read plus directories created as implicit parents
	total   int64           // regular-file bytes written so far
	dirs    map[string]bool // paths known to be real directories: created by this extraction, or found by one Lstat
	seen    map[string]bool // paths already in placed
	placed  []Placed
}

// countEntry counts one member, or one directory created implicitly as a
// member's parent, against Limits.MaxEntries, so a single deep member cannot
// place more entries than the limit.
func (x *extraction) countEntry() error {
	x.entries++
	if x.entries > x.opts.Limits.MaxEntries {
		return fmt.Errorf("extraction rejected: archive exceeds %d entries", x.opts.Limits.MaxEntries)
	}
	return nil
}

func (x *extraction) dir(hdr *tar.Header, name string) error {
	if err := refuseSpecialBits(hdr); err != nil {
		return err
	}
	// Mask to the nine permission bits, which also keeps the int64->FileMode
	// conversion provably in range. The owner always keeps rwx, so the tree
	// stays readable and verifiable. The member's missing ancestors take its
	// mode too.
	perm := os.FileMode(hdr.Mode&0o777) | 0o700
	if err := x.mkParents(name, perm); err != nil {
		return err
	}
	return x.mkdir(name, name, perm, false)
}

func (x *extraction) file(hdr *tar.Header, name string, r io.Reader) error {
	lim := x.opts.Limits
	if err := refuseSpecialBits(hdr); err != nil {
		return err
	}
	if hdr.Size > lim.MaxFileBytes {
		return fmt.Errorf("extraction rejected: %s declares %d bytes, exceeds limit %d", hdr.Name, hdr.Size, lim.MaxFileBytes)
	}
	if x.total+hdr.Size > lim.MaxTotalBytes {
		return fmt.Errorf("extraction rejected: total size would exceed limit %d", lim.MaxTotalBytes)
	}
	if err := x.mkParents(name, x.opts.DirPerm); err != nil {
		return err
	}
	if err := x.refuseLinkAt(name); err != nil {
		return err
	}
	// The owner always keeps read, so the file stays verifiable.
	mode := os.FileMode(hdr.Mode&0o777) | 0o400
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
	// the root later. A link whose target leaves the tree is refused anyway,
	// under the same rule as PolicyStrict, so a later reader that follows it
	// stays inside too.
	if err := checkLinkTarget(filepath.ToSlash(name), hdr.Linkname); err != nil {
		return err
	}
	if err := x.mkParents(name, x.opts.DirPerm); err != nil {
		return err
	}
	if err := x.refuseLinkAt(name); err != nil {
		return err
	}
	if err := x.root.Symlink(hdr.Linkname, name); err != nil {
		return fmt.Errorf("symlink %s: %w", hdr.Name, err)
	}
	x.record(Placed{Path: filepath.ToSlash(name), Kind: KindSymlink, Target: hdr.Linkname})
	return nil
}

// refuseSpecialBits refuses a member whose mode sets setuid, setgid or
// sticky, naming the bits. polypkg never installs such a file (the dir and
// perms actions refuse the same bits), so a package holding one was built
// wrong. Without this check os.Root would refuse it with an opaque
// "unsupported file mode".
func refuseSpecialBits(hdr *tar.Header) error {
	bits := SpecialBits(hdr.FileInfo().Mode())
	if bits == "" {
		return nil
	}
	return fmt.Errorf("extraction rejected: %q has mode %#o, which is %s; a package cannot carry setuid, setgid or sticky bits, so clear them in the package source and rebuild it",
		hdr.Name, hdr.Mode&0o7777, bits)
}

// SpecialBits names the setuid, setgid and sticky bits set in m, joined with
// " and " ("setuid and setgid"), or returns "" when none is set. Package
// extraction and the package builder both refuse a mode that has any.
func SpecialBits(m fs.FileMode) string {
	var bits []string
	for _, b := range []struct {
		bit  fs.FileMode
		name string
	}{{fs.ModeSetuid, "setuid"}, {fs.ModeSetgid, "setgid"}, {fs.ModeSticky, "sticky"}} {
		if m&b.bit != 0 {
			bits = append(bits, b.name)
		}
	}
	return strings.Join(bits, " and ")
}

// mkParents makes the missing ancestors of the member at name directories
// with perm, each counted as an entry.
func (x *extraction) mkParents(name string, perm fs.FileMode) error {
	for i := range len(name) {
		if name[i] == filepath.Separator {
			if err := x.mkdir(name, name[:i], perm, true); err != nil {
				return err
			}
		}
	}
	return nil
}

// mkdir makes dir, which the member at name needs, a directory with perm
// unless it already is one, and records it when it creates it. implicit
// counts a created dir against MaxEntries; an explicit directory member was
// counted when it was read. A path already known to be a directory costs a
// map lookup, any other one Lstat, so a member costs one filesystem lookup
// per ancestor that is new to this extraction rather than one per prefix.
// A dir that is a symlink is refused: os.Root would keep a write through it
// inside the root, but not at the member's own path, so the extracted tree
// would not be the one the archive lists, and no package needs that. This
// covers symlinks the archive created and any already under the root.
func (x *extraction) mkdir(name, dir string, perm fs.FileMode, implicit bool) error {
	if x.dirs[dir] {
		return nil
	}
	info, err := x.root.Lstat(dir)
	switch {
	case err == nil && info.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("extraction rejected: %q passes through or replaces the symlink %q", name, dir)
	case err == nil && !info.IsDir():
		return fmt.Errorf("mkdir %q: %q exists and is not a directory", name, dir)
	case err == nil:
		x.dirs[dir] = true
		return nil
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("inspect %s: %w", dir, err)
	}
	if implicit {
		if err := x.countEntry(); err != nil {
			return err
		}
	}
	if err := x.root.Mkdir(dir, perm); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	x.dirs[dir] = true
	x.record(Placed{Path: filepath.ToSlash(dir), Kind: KindDir, Mode: perm})
	return nil
}

// refuseLinkAt refuses a file or symlink member whose own path holds a
// symlink, which writing the member would follow or collide with.
func (x *extraction) refuseLinkAt(name string) error {
	if x.dirs[name] {
		return nil
	}
	if info, err := x.root.Lstat(name); err == nil && info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("extraction rejected: %q passes through or replaces the symlink %q", name, name)
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

package archive

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strconv"
	"strings"
)

// Member-name bounds. A name is refused beyond them, which also bounds the
// work of creating its ancestors. maxMemberName matches Linux's PATH_MAX.
// MaxMemberDepth is exported so callers can bound strip_components by it.
const (
	maxMemberName  = 4096
	MaxMemberDepth = 64
)

// strictMember is one archive member as PolicyStrict sees it, independent of
// whether it came from a tar stream or a zip central directory.
type strictMember struct {
	name     string    // the name exactly as stored in the archive
	kind     string    // KindFile, KindDir or KindSymlink; "" when refused or meta
	refusal  string    // what an unsupported member is ("hardlink", "FIFO", ...)
	meta     bool      // archive metadata (a pax global header): counted, never placed
	exec     bool      // the archive grants at least one execute bit
	linkname string    // symlink target
	body     io.Reader // regular-file content
}

// memberWalker calls visit for every member of an archive, in archive order,
// and stops at the first error.
type memberWalker func(visit func(strictMember) error) error

// strictExtractor holds the state of one PolicyStrict extraction.
type strictExtractor struct {
	root    *os.Root
	opts    Options
	entries int
	total   int64
	seen    map[string]bool // stripped member paths already extracted
	dirs    map[string]bool // directories this extraction created
	matched []bool          // matched[i]: opts.Include[i] selected some member
	placed  []Placed
	kept    bool // some member kept a path after StripComponents
	// shallowest is the fewest path segments of any member StripComponents
	// removed entirely; 0 until one is.
	shallowest int
}

// extractStrict extracts every member walk yields into root under
// PolicyStrict. root must be empty: a refusal leaves whatever was written so
// far in place, and the caller discards the whole tree. A member that needs a
// directory this extraction did not create is refused, so a non-empty root is
// never trusted.
func extractStrict(walk memberWalker, root *os.Root, opts Options) ([]Placed, error) {
	if err := checkStrictOptions(opts); err != nil {
		return nil, err
	}
	x := &strictExtractor{
		root:    root,
		opts:    opts,
		seen:    map[string]bool{},
		dirs:    map[string]bool{},
		matched: make([]bool, len(opts.Include)),
	}
	if err := walk(x.place); err != nil {
		return nil, err
	}
	// A strip that leaves no member is a mistake in the request, not an empty
	// archive: report it before include, whose patterns could not have matched.
	if !x.kept && x.shallowest > 0 {
		unit := "segments"
		if x.shallowest == 1 {
			unit = "segment"
		}
		return nil, fmt.Errorf("extraction rejected: strip_components %d removes every archive member (the shallowest has %d path %s); nothing to extract",
			opts.StripComponents, x.shallowest, unit)
	}
	unmatched := make([]string, 0, len(opts.Include))
	for i, ok := range x.matched {
		if !ok {
			unmatched = append(unmatched, strconv.Quote(opts.Include[i]))
		}
	}
	if len(unmatched) > 0 {
		return nil, fmt.Errorf("extraction rejected: include pattern %s matched no archive member", strings.Join(unmatched, ", "))
	}
	return x.placed, nil
}

// checkStrictOptions rejects Options that PolicyStrict cannot honour.
func checkStrictOptions(opts Options) error {
	switch {
	case opts.StripComponents < 0:
		return fmt.Errorf("archive: StripComponents must not be negative, got %d", opts.StripComponents)
	case opts.DirPerm&^fs.ModePerm != 0 || opts.DirPerm&0o700 != 0o700:
		return fmt.Errorf("archive: DirPerm %#o must be permission bits that include owner rwx", uint32(opts.DirPerm))
	case opts.Limits.MaxFileBytes <= 0 || opts.Limits.MaxTotalBytes <= 0 || opts.Limits.MaxEntries <= 0:
		return errors.New("archive: every Limits field must be positive (start from DefaultLimits())")
	}
	for _, p := range opts.Include {
		if _, err := path.Match(p, ""); err != nil {
			return fmt.Errorf("archive: include pattern %q: %w", p, err)
		}
	}
	return nil
}

// place applies PolicyStrict to one member.
func (x *strictExtractor) place(m strictMember) error {
	if m.meta {
		return x.countEntry()
	}
	rel, ok, err := memberPath(m.name, x.opts.StripComponents)
	if err != nil {
		return err
	}
	if ok {
		x.kept = true
	} else if depth := len(memberSegments(m.name)); x.shallowest == 0 || depth < x.shallowest {
		x.shallowest = depth
	}
	selected := ok && x.selected(rel)
	// A selected directory member naming a directory already created as an
	// implicit parent is that same entry, which mkParents counted. It is
	// recorded in seen below, so this applies once per directory.
	if !selected || m.kind != KindDir || !x.dirs[rel] || x.seen[rel] {
		if err := x.countEntry(); err != nil {
			return err
		}
	}
	if !selected {
		return nil
	}
	if m.refusal != "" {
		return fmt.Errorf("extraction rejected: %q is a %s; only regular files, directories and symlinks are extracted", m.name, m.refusal)
	}
	if rel == "." {
		if m.kind == KindDir {
			return nil // "./": the root itself, which already exists
		}
		return fmt.Errorf("extraction rejected: %q names the extraction root itself", m.name)
	}
	if x.seen[rel] {
		return fmt.Errorf("extraction rejected: duplicate archive member %q", rel)
	}
	x.seen[rel] = true
	if err := x.mkParents(rel); err != nil {
		return err
	}
	switch m.kind {
	case KindDir:
		return x.placeDir(rel)
	case KindSymlink:
		return x.placeSymlink(rel, m.linkname)
	default:
		return x.placeFile(rel, m)
	}
}

// countEntry counts one member, or one directory created implicitly as a
// member's parent, against Limits.MaxEntries. Counting implicit parents too
// keeps a single deep member from placing more entries than the limit.
func (x *strictExtractor) countEntry() error {
	x.entries++
	if x.entries > x.opts.Limits.MaxEntries {
		return fmt.Errorf("extraction rejected: archive exceeds %d entries", x.opts.Limits.MaxEntries)
	}
	return nil
}

// memberPath validates an archive member name and returns the slash-separated
// path it extracts to, relative to the root. ok is false when strip removes
// every segment, in which case the member is skipped, as tar
// --strip-components does. Segments are counted before cleaning, so
// "./pkg/bin" has three, matching GNU tar. A ".." segment is refused wherever
// it appears, even in a part that strip would remove. Names are also refused
// when they are too long or deep, hold a NUL byte, or carry a ':' in the
// first segment of the path placed, which Windows reads as a drive
// ("C:evil"); that check runs after strip and cleaning, so neither a
// leading "./" nor a stripped prefix hides it.
func memberPath(name string, strip int) (rel string, ok bool, err error) {
	switch {
	case name == "":
		return "", false, errors.New("extraction rejected: archive member with an empty name")
	case len(name) > maxMemberName:
		return "", false, fmt.Errorf("extraction rejected: member name %q... is longer than %d bytes", name[:64], maxMemberName)
	case strings.ContainsRune(name, 0):
		return "", false, fmt.Errorf("extraction rejected: member name %q contains a NUL byte", name)
	case strings.HasPrefix(name, "/"):
		return "", false, fmt.Errorf("extraction rejected: absolute member name %q", name)
	case strings.Contains(name, `\`):
		return "", false, fmt.Errorf("extraction rejected: member name %q contains a backslash", name)
	}
	segs := memberSegments(name)
	for _, s := range segs {
		if s == ".." {
			return "", false, fmt.Errorf("extraction rejected: member name %q contains a '..' segment", name)
		}
	}
	if len(segs) > MaxMemberDepth {
		return "", false, fmt.Errorf("extraction rejected: member name %q has more than %d path segments", name, MaxMemberDepth)
	}
	if len(segs) <= strip {
		return "", false, nil
	}
	rel = path.Clean(strings.Join(segs[strip:], "/"))
	if first, _, _ := strings.Cut(rel, "/"); strings.Contains(first, ":") {
		return "", false, fmt.Errorf("extraction rejected: member name %q has a ':' in its first segment, which Windows reads as a drive", name)
	}
	return rel, true, nil
}

// memberSegments splits a member name into its non-empty path segments, the
// unit StripComponents counts.
func memberSegments(name string) []string {
	return strings.FieldsFunc(name, func(r rune) bool { return r == '/' })
}

// selected reports whether rel is extracted under opts.Include: with no
// patterns everything is; otherwise some pattern must match rel or one of its
// ancestor directories. Every matching pattern is marked, so a pattern counts
// as unmatched only when it matched no member at all.
func (x *strictExtractor) selected(rel string) bool {
	if len(x.opts.Include) == 0 {
		return true
	}
	hit := false
	for i, pat := range x.opts.Include {
		for p := rel; p != "."; p = path.Dir(p) {
			// checkStrictOptions validated every pattern, so Match cannot fail.
			if ok, _ := path.Match(pat, p); ok {
				x.matched[i] = true
				hit = true
				break
			}
		}
	}
	return hit
}

// mkParents creates the missing ancestors of rel, each counted as an entry.
// An ancestor this extraction already created needs no filesystem lookup, so
// a member costs one Mkdir per new ancestor rather than one Lstat per prefix.
func (x *strictExtractor) mkParents(rel string) error {
	for i, c := range rel {
		if c != '/' || x.dirs[rel[:i]] {
			continue
		}
		if err := x.countEntry(); err != nil {
			return err
		}
		if err := x.mkdir(rel, rel[:i]); err != nil {
			return err
		}
	}
	return nil
}

// mkdir creates dir, needed by the member at rel, with exactly opts.DirPerm,
// and records it. Something already at dir was not created by this
// extraction as a directory (x.dirs says so), so it is refused.
func (x *strictExtractor) mkdir(rel, dir string) error {
	if err := x.root.Mkdir(dir, x.opts.DirPerm); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return x.refuseExisting(rel, dir)
		}
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	// Mkdir is filtered by the umask; Chmod sets the scope's mode exactly.
	if err := x.root.Chmod(dir, x.opts.DirPerm); err != nil {
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	x.dirs[dir] = true
	x.placed = append(x.placed, Placed{Path: dir, Kind: KindDir, Mode: x.opts.DirPerm})
	return nil
}

// refuseExisting explains why the member at rel cannot have the directory
// dir: the archive put a symlink or a file there, or dir was in the root
// before extraction began.
func (x *strictExtractor) refuseExisting(rel, dir string) error {
	info, err := x.root.Lstat(dir)
	switch {
	case err != nil:
		return fmt.Errorf("inspect %s: %w", dir, err)
	case info.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("extraction rejected: %q passes through the symlink %q", rel, dir)
	case info.IsDir():
		return fmt.Errorf("extraction rejected: %q needs the directory %q, which existed before extraction; extract into an empty directory", rel, dir)
	default:
		return fmt.Errorf("extraction rejected: %q needs %q to be a directory, but the archive placed a file there", rel, dir)
	}
}

// placeDir extracts a directory member. A directory already created as the
// parent of an earlier member is left as it is.
func (x *strictExtractor) placeDir(rel string) error {
	if x.dirs[rel] {
		return nil
	}
	return x.mkdir(rel, rel)
}

// placeFile extracts a regular file with its mode normalised: 0o755 when the
// archive grants any execute bit, else 0o644. setuid, setgid, sticky and
// group/other write never survive.
func (x *strictExtractor) placeFile(rel string, m strictMember) error {
	mode := fs.FileMode(0o644)
	if m.exec {
		mode = 0o755
	}
	f, err := x.root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", rel, err)
	}
	err = x.copyLimited(f, m.name, m.body)
	if cerr := f.Close(); err == nil && cerr != nil {
		err = fmt.Errorf("close %s: %w", rel, cerr)
	}
	if err != nil {
		return err
	}
	if err := x.root.Chmod(rel, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", rel, err)
	}
	x.placed = append(x.placed, Placed{Path: rel, Kind: KindFile, Mode: mode})
	return nil
}

// copyLimited copies body into w, counting the bytes the decompressor actually
// produces rather than trusting any size the archive declares, and refuses the
// member once it passes the per-file or the total limit.
func (x *strictExtractor) copyLimited(w io.Writer, name string, body io.Reader) error {
	lim := x.opts.Limits
	totalLeft := lim.MaxTotalBytes - x.total
	n, err := io.Copy(w, io.LimitReader(body, min(lim.MaxFileBytes, totalLeft)))
	x.total += n
	if err != nil {
		return fmt.Errorf("read archive member %q: %w", name, err)
	}
	// One more byte proves the member is over a limit. Reading on to EOF also
	// lets zip verify the member's CRC-32.
	var probe [1]byte
	k, err := io.ReadFull(body, probe[:])
	switch {
	case k > 0 && lim.MaxFileBytes <= totalLeft:
		return fmt.Errorf("extraction rejected: %q exceeds the per-file limit of %d bytes", name, lim.MaxFileBytes)
	case k > 0:
		return fmt.Errorf("extraction rejected: total extracted size exceeds the limit of %d bytes", lim.MaxTotalBytes)
	case errors.Is(err, io.EOF):
		return nil
	default:
		return fmt.Errorf("read archive member %q: %w", name, err)
	}
}

// placeSymlink creates a symlink after checking that its target stays inside
// the root.
func (x *strictExtractor) placeSymlink(rel, target string) error {
	if err := checkLinkTarget(rel, target); err != nil {
		return err
	}
	if err := x.root.Symlink(target, rel); err != nil {
		return fmt.Errorf("symlink %s: %w", rel, err)
	}
	x.placed = append(x.placed, Placed{Path: rel, Kind: KindSymlink, Target: target})
	return nil
}

// checkLinkTarget refuses a symlink target that is absolute, or that resolves
// outside the root from the link's directory. It also refuses a ".." that
// follows a named segment ("sub/.."): the kernel resolves "sub" first, and if
// "sub" is itself a symlink the ".." climbs from wherever that points, which a
// lexical check cannot see. Leading ".." segments are safe to check lexically
// because the link's own ancestors are real directories (mkParents).
func checkLinkTarget(rel, target string) error {
	switch {
	case target == "":
		return fmt.Errorf("extraction rejected: symlink %q has an empty target", rel)
	case strings.HasPrefix(target, "/"):
		return fmt.Errorf("extraction rejected: symlink %q has the absolute target %q", rel, target)
	}
	named := false
	for _, s := range strings.Split(target, "/") {
		switch s {
		case "", ".":
		case "..":
			if named {
				return fmt.Errorf("extraction rejected: symlink %q target %q climbs back out of a directory with '..'", rel, target)
			}
		default:
			named = true
		}
	}
	resolved := path.Join(path.Dir(rel), target)
	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		return fmt.Errorf("extraction rejected: symlink %q target %q escapes the extraction root", rel, target)
	}
	return nil
}

// tarMembers walks an uncompressed tar stream.
func tarMembers(r io.Reader) memberWalker {
	return func(visit func(strictMember) error) error {
		tr := tar.NewReader(r)
		for {
			hdr, err := tr.Next()
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("read tar header: %w", err)
			}
			m := strictMember{name: hdr.Name, exec: hdr.Mode&0o111 != 0}
			switch hdr.Typeflag {
			case tar.TypeReg:
				m.kind, m.body = KindFile, tr
			case tar.TypeDir:
				m.kind = KindDir
			case tar.TypeSymlink:
				m.kind, m.linkname = KindSymlink, hdr.Linkname
			case tar.TypeXGlobalHeader:
				m.meta = true
			case tar.TypeLink:
				m.refusal = "hardlink"
			case tar.TypeChar:
				m.refusal = "character device"
			case tar.TypeBlock:
				m.refusal = "block device"
			case tar.TypeFifo:
				m.refusal = "FIFO"
			default:
				m.refusal = fmt.Sprintf("tar entry of unsupported type %q", hdr.Typeflag)
			}
			if err := visit(m); err != nil {
				return err
			}
		}
	}
}

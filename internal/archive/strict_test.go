package archive_test

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/archive"
)

// testDirPerm includes group write, which a typical 022 umask strips, so the
// tests prove directory modes are set exactly rather than left to the umask.
const testDirPerm fs.FileMode = 0o775

// testLimits are generous for the fixtures but far below the defaults.
var testLimits = archive.Limits{MaxFileBytes: 1 << 20, MaxTotalBytes: 4 << 20, MaxEntries: 1000}

// strictCase is one PolicyStrict scenario, run against every format that can
// express its members.
type strictCase struct {
	name    string
	members []fixtureMember
	strip   int
	include []string
	limits  archive.Limits    // zero value: testLimits
	want    []archive.Placed  // exact result, in archive order
	content map[string]string // expected content of placed files
	wantErr string            // non-empty: extraction must fail with this substring
}

func (c strictCase) options() archive.Options {
	lim := c.limits
	if lim == (archive.Limits{}) {
		lim = testLimits
	}
	return archive.Options{
		Policy:          archive.PolicyStrict,
		Limits:          lim,
		StripComponents: c.strip,
		Include:         c.include,
		DirPerm:         testDirPerm,
	}
}

func wantFile(path string, mode fs.FileMode) archive.Placed {
	return archive.Placed{Path: path, Kind: "file", Mode: mode}
}

func wantDir(path string) archive.Placed {
	return archive.Placed{Path: path, Kind: "dir", Mode: testDirPerm}
}

func wantSymlink(path, target string) archive.Placed {
	return archive.Placed{Path: path, Kind: "symlink", Target: target}
}

// releaseLayout is a typical upstream release archive: one top-level
// directory holding the binary, docs and shell completions.
var releaseLayout = []fixtureMember{
	{name: "rg-14/", kind: fixtureDir},
	{name: "rg-14/rg", kind: fixtureFile, mode: 0o755, body: "binary"},
	{name: "rg-14/doc/", kind: fixtureDir},
	{name: "rg-14/doc/rg.1", kind: fixtureFile, body: "manual"},
	{name: "rg-14/complete/", kind: fixtureDir},
	{name: "rg-14/complete/rg.bash", kind: fixtureFile, body: "bash"},
	{name: "rg-14/complete/_rg", kind: fixtureFile, body: "zsh"},
	{name: "rg-14/LICENSE", kind: fixtureFile, body: "license"},
}

func strictCases() []strictCase {
	return []strictCase{
		{
			name: "nested tree with an executable and a symlink",
			members: []fixtureMember{
				{name: "pkg/", kind: fixtureDir},
				{name: "pkg/bin/hello", kind: fixtureFile, mode: 0o755, body: "#!/bin/sh\necho hello\n"},
				{name: "pkg/README", kind: fixtureFile, body: "readme\n"},
				{name: "pkg/hello", kind: fixtureSymlink, target: "bin/hello"},
				{name: "pkg/share/doc/", kind: fixtureDir},
			},
			want: []archive.Placed{
				wantDir("pkg"), wantDir("pkg/bin"), wantFile("pkg/bin/hello", 0o755), wantFile("pkg/README", 0o644),
				wantSymlink("pkg/hello", "bin/hello"), wantDir("pkg/share"), wantDir("pkg/share/doc"),
			},
			content: map[string]string{"pkg/bin/hello": "#!/bin/sh\necho hello\n", "pkg/README": "readme\n"},
		},
		{
			name: "modes are normalised and directory modes ignored",
			members: []fixtureMember{
				{name: "setuid", kind: fixtureFile, mode: fs.ModeSetuid | 0o777},
				{name: "setgid", kind: fixtureFile, mode: fs.ModeSetgid | 0o755},
				{name: "world-writable", kind: fixtureFile, mode: 0o666},
				{name: "group-exec-only", kind: fixtureFile, mode: 0o610},
				{name: "read-only", kind: fixtureFile, mode: 0o400},
				{name: "sticky/", kind: fixtureDir, mode: fs.ModeSticky | 0o777},
			},
			want: []archive.Placed{
				wantFile("setuid", 0o755), wantFile("setgid", 0o755), wantFile("world-writable", 0o644),
				wantFile("group-exec-only", 0o755), wantFile("read-only", 0o644), wantDir("sticky"),
			},
		},
		{
			name: "a ./ root entry is skipped",
			members: []fixtureMember{
				{name: "./", kind: fixtureDir},
				{name: "./a", kind: fixtureFile, body: "a"},
			},
			want: []archive.Placed{wantFile("a", 0o644)},
		},
		{
			name: "a pax global header is ignored",
			members: []fixtureMember{
				{name: "pax_global_header", kind: fixtureGlobal, body: "commit 0123abcd"},
				{name: "a", kind: fixtureFile, body: "a"},
			},
			want: []archive.Placed{wantFile("a", 0o644)},
		},
		{
			name:    "parent traversal",
			members: []fixtureMember{{name: "../evil", kind: fixtureFile, body: "x"}},
			wantErr: "contains a '..' segment",
		},
		{
			name:    "nested traversal",
			members: []fixtureMember{{name: "a/../../evil", kind: fixtureFile, body: "x"}},
			wantErr: "contains a '..' segment",
		},
		{
			name:    "absolute name",
			members: []fixtureMember{{name: "/etc/evil", kind: fixtureFile, body: "x"}},
			wantErr: "absolute member name",
		},
		{
			name:    "backslash in a name",
			members: []fixtureMember{{name: `a\..\evil`, kind: fixtureFile, body: "x"}},
			wantErr: "contains a backslash",
		},
		{
			name:    "NUL byte in a name",
			members: []fixtureMember{{name: "a\x00b", kind: fixtureFile, body: "x"}},
			wantErr: "contains a NUL byte",
		},
		{
			name:    "escape sequence and newline in a name",
			members: []fixtureMember{{name: "evil\x1b[31mRED\nFAKE line", kind: fixtureFile, body: "x"}},
			wantErr: `member name "evil\x1b[31mRED\nFAKE line" contains the control character U+001B`,
		},
		{
			name:    "tab in a directory segment",
			members: []fixtureMember{{name: "a\tb/c", kind: fixtureFile, body: "x"}},
			wantErr: "contains the control character U+0009",
		},
		{
			name:    "DEL in a name",
			members: []fixtureMember{{name: "a\x7fb", kind: fixtureFile, body: "x"}},
			wantErr: "contains the control character U+007F",
		},
		{
			name:    "C1 control in a name",
			members: []fixtureMember{{name: "a\u009bb", kind: fixtureFile, body: "x"}},
			wantErr: "contains the control character U+009B",
		},
		{
			name:    "invalid UTF-8 in a directory name",
			members: []fixtureMember{{name: "\x80\xffg/", kind: fixtureDir}},
			wantErr: `member name "\x80\xffg/" is not valid UTF-8`,
		},
		{
			name:    "raw C1 byte in a name",
			members: []fixtureMember{{name: "a\x9bb", kind: fixtureFile, body: "x"}},
			wantErr: `member name "a\x9bb" is not valid UTF-8`,
		},
		{
			name:    "invalid UTF-8 in a part strip removes",
			members: []fixtureMember{{name: "top\x80/a", kind: fixtureFile, body: "x"}},
			strip:   1,
			wantErr: "is not valid UTF-8",
		},
		{
			name:    "Unicode format character in a symlink name",
			members: []fixtureMember{{name: "a\u202egnp.exe", kind: fixtureSymlink, target: "b"}},
			wantErr: "contains the format character U+202E",
		},
		{
			name:    "control character in a part strip removes",
			members: []fixtureMember{{name: "top\x1b/a", kind: fixtureFile, body: "x"}},
			strip:   1,
			wantErr: "contains the control character U+001B",
		},
		{
			name:    "drive letter with a slash",
			members: []fixtureMember{{name: "C:/evil", kind: fixtureFile, body: "x"}},
			wantErr: "has a ':' in its first segment",
		},
		{
			name:    "drive letter after a leading ./",
			members: []fixtureMember{{name: "./C:evil", kind: fixtureFile, body: "x"}},
			wantErr: "has a ':' in its first segment",
		},
		{
			name:    "drive letter uncovered by strip_components",
			members: []fixtureMember{{name: "pkg/C:evil", kind: fixtureFile, body: "x"}},
			strip:   1,
			wantErr: "has a ':' in its first segment",
		},
		{
			name:    "a ':' in a segment strip_components removes is allowed",
			members: []fixtureMember{{name: "C:pkg/a", kind: fixtureFile, body: "x"}},
			strip:   1,
			want:    []archive.Placed{wantFile("a", 0o644)},
		},
		{
			name:    "drive-relative name",
			members: []fixtureMember{{name: "C:evil", kind: fixtureFile, body: "x"}},
			wantErr: "has a ':' in its first segment",
		},
		{
			name:    "a ':' below the first segment is allowed",
			members: []fixtureMember{{name: "a/b:c", kind: fixtureFile, body: "x"}},
			want:    []archive.Placed{wantDir("a"), wantFile("a/b:c", 0o644)},
		},
		{
			name:    "empty name",
			members: []fixtureMember{{name: "", kind: fixtureFile, body: "x"}},
			wantErr: "empty name",
		},
		{
			name:    "a file naming the root itself",
			members: []fixtureMember{{name: ".", kind: fixtureFile, body: "x"}},
			wantErr: "names the extraction root itself",
		},
		{
			name:    "symlink with an absolute target",
			members: []fixtureMember{{name: "link", kind: fixtureSymlink, target: "/etc/passwd"}},
			wantErr: "absolute target",
		},
		{
			name:    "symlink escaping through a relative target",
			members: []fixtureMember{{name: "a/link", kind: fixtureSymlink, target: "../../etc/passwd"}},
			wantErr: "escapes the extraction root",
		},
		{
			name: "symlink climbing back out of a directory",
			members: []fixtureMember{
				{name: "up", kind: fixtureSymlink, target: "."},
				{name: "x", kind: fixtureSymlink, target: "up/.."},
			},
			wantErr: "climbs back out of a directory",
		},
		{
			name: "member written through an archive symlink",
			members: []fixtureMember{
				{name: "evil", kind: fixtureSymlink, target: "sub"},
				{name: "sub/", kind: fixtureDir},
				{name: "evil/x", kind: fixtureFile, body: "x"},
			},
			wantErr: `passes through the symlink "evil"`,
		},
		{
			name: "hardlink",
			members: []fixtureMember{
				{name: "a", kind: fixtureFile, body: "a"},
				{name: "h", kind: fixtureHardlink, target: "a"},
			},
			wantErr: `"h" is a hardlink`,
		},
		{
			name:    "character device",
			members: []fixtureMember{{name: "c", kind: fixtureChar}},
			wantErr: `"c" is a character device`,
		},
		{
			name:    "block device",
			members: []fixtureMember{{name: "b", kind: fixtureBlock}},
			wantErr: `"b" is a block device`,
		},
		{
			name:    "FIFO",
			members: []fixtureMember{{name: "f", kind: fixtureFIFO}},
			wantErr: `"f" is a FIFO`,
		},
		{
			name:    "socket",
			members: []fixtureMember{{name: "s", kind: fixtureSocket}},
			wantErr: `"s" is a socket`,
		},
		{
			name:    "unknown tar entry type",
			members: []fixtureMember{{name: "z", kind: fixtureRawTar, typeflag: 'Z'}},
			wantErr: `unsupported type 'Z'`,
		},
		{
			name: "duplicate file",
			members: []fixtureMember{
				{name: "a", kind: fixtureFile, body: "first"},
				{name: "a", kind: fixtureFile, body: "second"},
			},
			wantErr: `duplicate archive member "a"`,
		},
		{
			name: "duplicate directory",
			members: []fixtureMember{
				{name: "d/", kind: fixtureDir},
				{name: "d/", kind: fixtureDir},
			},
			wantErr: `duplicate archive member "d"`,
		},
		{
			name: "a directory member naming an implicit parent is not a duplicate",
			members: []fixtureMember{
				{name: "a/f", kind: fixtureFile, body: "f"},
				{name: "a/", kind: fixtureDir},
			},
			want: []archive.Placed{wantDir("a"), wantFile("a/f", 0o644)},
		},
		{
			name: "file where a directory is needed",
			members: []fixtureMember{
				{name: "a", kind: fixtureFile, body: "a"},
				{name: "a/b", kind: fixtureFile, body: "b"},
			},
			wantErr: `needs "a" to be a directory`,
		},
		{
			name: "file where an earlier member needs a directory",
			members: []fixtureMember{
				{name: "a/b", kind: fixtureFile, body: "b"},
				{name: "a", kind: fixtureFile, body: "a"},
			},
			wantErr: `"a" is a file, but an earlier member needs "a" to be a directory`,
		},
		{
			name: "symlink where an earlier member needs a directory",
			members: []fixtureMember{
				{name: "a/b", kind: fixtureFile, body: "b"},
				{name: "a", kind: fixtureSymlink, target: "b"},
			},
			wantErr: `"a" is a symlink, but an earlier member needs "a" to be a directory`,
		},
		{
			name: "entry limit",
			members: []fixtureMember{
				{name: "a", kind: fixtureFile}, {name: "b", kind: fixtureFile}, {name: "c", kind: fixtureFile},
			},
			limits:  archive.Limits{MaxFileBytes: 100, MaxTotalBytes: 100, MaxEntries: 2},
			wantErr: "exceeds 2 entries",
		},
		{
			name:    "file exactly at the per-file limit",
			members: []fixtureMember{{name: "a", kind: fixtureFile, body: "1234"}},
			limits:  archive.Limits{MaxFileBytes: 4, MaxTotalBytes: 100, MaxEntries: 100},
			want:    []archive.Placed{wantFile("a", 0o644)},
			content: map[string]string{"a": "1234"},
		},
		{
			name:    "file over the per-file limit",
			members: []fixtureMember{{name: "a", kind: fixtureFile, body: "12345"}},
			limits:  archive.Limits{MaxFileBytes: 4, MaxTotalBytes: 100, MaxEntries: 100},
			wantErr: `"a" exceeds the per-file limit of 4 bytes`,
		},
		{
			name: "total over the limit",
			members: []fixtureMember{
				{name: "a", kind: fixtureFile, body: "1234"},
				{name: "b", kind: fixtureFile, body: "567"},
			},
			limits:  archive.Limits{MaxFileBytes: 4, MaxTotalBytes: 6, MaxEntries: 100},
			wantErr: "total extracted size exceeds the limit of 6 bytes",
		},
		{
			name:    "strip_components removes the top-level directory",
			members: releaseLayout,
			strip:   1,
			want: []archive.Placed{
				wantFile("rg", 0o755), wantDir("doc"), wantFile("doc/rg.1", 0o644), wantDir("complete"),
				wantFile("complete/rg.bash", 0o644), wantFile("complete/_rg", 0o644), wantFile("LICENSE", 0o644),
			},
			content: map[string]string{"rg": "binary", "doc/rg.1": "manual"},
		},
		{
			name:    "strip_components counts a leading ./ as a segment, as GNU tar does",
			members: []fixtureMember{{name: "./rg-14/rg", kind: fixtureFile, mode: 0o755, body: "binary"}},
			strip:   1,
			want:    []archive.Placed{wantDir("rg-14"), wantFile("rg-14/rg", 0o755)},
		},
		{
			name: "strip_components skips members with too few segments",
			members: []fixtureMember{
				{name: "LICENSE", kind: fixtureFile, body: "license"},
				{name: "pkg/a", kind: fixtureFile, body: "a"},
			},
			strip: 1,
			want:  []archive.Placed{wantFile("a", 0o644)},
		},
		{
			name: "strip_components that removes every member is refused",
			members: []fixtureMember{
				{name: "pkg/sub/b", kind: fixtureFile, body: "b"},
				{name: "pkg/a", kind: fixtureFile, body: "a"},
			},
			strip:   3,
			wantErr: "strip_components 3 removes every archive member (the shallowest has 2 path segments); nothing to extract",
		},
		{
			name:    "strip_components that removes every member is refused before include is checked",
			members: []fixtureMember{{name: "pkg/a", kind: fixtureFile, body: "a"}},
			strip:   3,
			include: []string{"a"},
			wantErr: "strip_components 3 removes every archive member (the shallowest has 2 path segments)",
		},
		{
			name:    "strip_components does not hide a traversal",
			members: []fixtureMember{{name: "x/../../evil", kind: fixtureFile, body: "x"}},
			strip:   2,
			wantErr: "contains a '..' segment",
		},
		{
			name:    "include an exact file",
			members: releaseLayout,
			strip:   1,
			include: []string{"rg"},
			want:    []archive.Placed{wantFile("rg", 0o755)},
		},
		{
			name:    "include a directory and everything under it",
			members: releaseLayout,
			strip:   1,
			include: []string{"doc"},
			want:    []archive.Placed{wantDir("doc"), wantFile("doc/rg.1", 0o644)},
		},
		{
			name:    "include a glob",
			members: releaseLayout,
			strip:   1,
			include: []string{"complete/*"},
			want:    []archive.Placed{wantDir("complete"), wantFile("complete/rg.bash", 0o644), wantFile("complete/_rg", 0o644)},
		},
		{
			name:    "include patterns matching the same member are each satisfied",
			members: releaseLayout,
			strip:   1,
			include: []string{"rg", "r*"},
			want:    []archive.Placed{wantFile("rg", 0o755)},
		},
		{
			name:    "include is matched after strip_components",
			members: releaseLayout,
			strip:   1,
			include: []string{"rg-14/rg"},
			wantErr: `include pattern "rg-14/rg" matched no archive member`,
		},
		{
			name:    "include pattern that matches nothing",
			members: releaseLayout,
			strip:   1,
			include: []string{"rg", "bin/rg", "man/*"},
			wantErr: `include pattern "bin/rg", "man/*" matched no archive member`,
		},
		{
			name: "include leaves out a member that would be refused",
			members: []fixtureMember{
				{name: "a", kind: fixtureFile, body: "a"},
				{name: "f", kind: fixtureFIFO},
			},
			include: []string{"a"},
			want:    []archive.Placed{wantFile("a", 0o644)},
		},
		{
			name:    "malformed include pattern",
			members: []fixtureMember{{name: "a", kind: fixtureFile}},
			include: []string{"["},
			wantErr: `include pattern "["`,
		},
		{
			name:    "a name of exactly the maximum length",
			members: []fixtureMember{{name: longName(4096), kind: fixtureFile, body: "x"}},
			want:    placedChain(longName(4096)),
		},
		{
			name:    "a name one byte over the maximum length",
			members: []fixtureMember{{name: longName(4097), kind: fixtureFile, body: "x"}},
			wantErr: "is longer than 4096 bytes",
		},
		{
			name:    "a name of exactly the maximum depth",
			members: []fixtureMember{{name: deepName(64), kind: fixtureFile, body: "x"}},
			want:    placedChain(deepName(64)),
		},
		{
			name:    "a name one segment over the maximum depth",
			members: []fixtureMember{{name: deepName(65), kind: fixtureFile, body: "x"}},
			wantErr: "has more than 64 path segments",
		},
		{
			name:    "implicit parent directories count as entries",
			members: []fixtureMember{{name: "a/b/f", kind: fixtureFile, body: "x"}},
			limits:  archive.Limits{MaxFileBytes: 100, MaxTotalBytes: 100, MaxEntries: 2},
			wantErr: "exceeds 2 entries",
		},
		{
			name: "a directory member naming an implicit parent is one entry",
			members: []fixtureMember{
				{name: "a/x", kind: fixtureFile, body: "x"},
				{name: "a/", kind: fixtureDir},
			},
			limits: archive.Limits{MaxFileBytes: 100, MaxTotalBytes: 100, MaxEntries: 2},
			want:   []archive.Placed{wantDir("a"), wantFile("a/x", 0o644)},
		},
		{
			name: "an unselected directory member naming an implicit parent still counts",
			members: []fixtureMember{
				{name: "a/x", kind: fixtureFile, body: "x"},
				{name: "a/", kind: fixtureDir},
				{name: "a/", kind: fixtureDir},
			},
			include: []string{"a/x"},
			limits:  archive.Limits{MaxFileBytes: 100, MaxTotalBytes: 100, MaxEntries: 3},
			wantErr: "exceeds 3 entries",
		},
		{
			name:    "implicit parent directories fit the entry limit exactly",
			members: []fixtureMember{{name: "a/b/f", kind: fixtureFile, body: "x"}},
			limits:  archive.Limits{MaxFileBytes: 100, MaxTotalBytes: 100, MaxEntries: 3},
			want:    []archive.Placed{wantDir("a"), wantDir("a/b"), wantFile("a/b/f", 0o644)},
		},
		{
			name:    "negative strip_components",
			members: []fixtureMember{{name: "a", kind: fixtureFile}},
			strip:   -1,
			wantErr: "StripComponents must not be negative",
		},
	}
}

// deepName returns a member name of segs path segments: segs-1 directories
// and a file.
func deepName(segs int) string {
	return strings.Repeat("d/", segs-1) + "f"
}

// longName returns an n-byte member name whose segments stay well under
// NAME_MAX, so only the whole-name limit can refuse it.
func longName(n int) string {
	seg := strings.Repeat("x", 200)
	var b strings.Builder
	for n-b.Len() > len(seg)+1 {
		b.WriteString(seg + "/")
	}
	b.WriteString(strings.Repeat("y", n-b.Len()))
	return b.String()
}

// placedChain is what extracting the single file member name places: each
// ancestor directory, then the file.
func placedChain(name string) []archive.Placed {
	var want []archive.Placed
	for i, c := range name {
		if c == '/' {
			want = append(want, wantDir(name[:i]))
		}
	}
	return append(want, wantFile(name, 0o644))
}

// newTestRoot creates base/dest and opens an os.Root on dest.
func newTestRoot(t *testing.T) (base string, root *os.Root) {
	t.Helper()
	base = t.TempDir()
	dest := filepath.Join(base, "dest")
	if err := os.Mkdir(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return base, root
}

// assertNothingOutside fails unless base still holds only dest.
func assertNothingOutside(t *testing.T, base string) {
	t.Helper()
	ents, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if e.Name() != "dest" {
			t.Fatalf("extraction wrote %q outside the root", e.Name())
		}
	}
}

// assertPlacedTree fails unless the tree under root is exactly placed: same
// paths, kinds, symlink targets and full modes, so a setuid, setgid or sticky
// bit left on disk fails even when the permission bits match.
func assertPlacedTree(t *testing.T, root *os.Root, placed []archive.Placed) {
	t.Helper()
	want := make(map[string]archive.Placed, len(placed))
	for _, p := range placed {
		want[p.Path] = p
	}
	seen := 0
	err := fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == "." {
			return err
		}
		seen++
		w, ok := want[p]
		if !ok {
			t.Fatalf("%s exists but was not reported as placed", p)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch w.Kind {
		case "file":
			if info.Mode() != w.Mode {
				t.Fatalf("%s: on disk %v, placed as file %v", p, info.Mode(), w.Mode)
			}
		case "dir":
			if info.Mode() != fs.ModeDir|w.Mode {
				t.Fatalf("%s: on disk %v, placed as dir %v", p, info.Mode(), w.Mode)
			}
		case "symlink":
			target, err := root.Readlink(p)
			if err != nil {
				return err
			}
			if target != w.Target {
				t.Fatalf("%s: links to %q, placed with target %q", p, target, w.Target)
			}
		default:
			t.Fatalf("%s: unknown placed kind %q", p, w.Kind)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk extracted tree: %v", err)
	}
	if seen != len(placed) {
		t.Fatalf("%d entries on disk, %d reported placed: %+v", seen, len(placed), placed)
	}
}

// checkStrictCase runs c through extract and checks the outcome.
func checkStrictCase(t *testing.T, c strictCase, extract func(*os.Root, archive.Options) ([]archive.Placed, error)) {
	t.Helper()
	base, root := newTestRoot(t)
	placed, err := extract(root, c.options())
	assertNothingOutside(t, base)
	if c.wantErr != "" {
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Fatalf("error = %v, want one containing %q", err, c.wantErr)
		}
		return
	}
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !slices.Equal(placed, c.want) {
		t.Fatalf("placed:\n got %+v\nwant %+v", placed, c.want)
	}
	assertPlacedTree(t, root, placed)
	for p, want := range c.content {
		got, err := root.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("%s holds %q, want %q", p, got, want)
		}
	}
}

func TestExtractTarStrict(t *testing.T) {
	for _, c := range strictCases() {
		t.Run(c.name, func(t *testing.T) {
			if why := fixtureUnexpressible(archive.FormatTar, c.members); why != "" {
				t.Skip(why)
			}
			data := fixtureTar(t, c.members...)
			checkStrictCase(t, c, func(root *os.Root, opts archive.Options) ([]archive.Placed, error) {
				return archive.ExtractTar(bytes.NewReader(data), root, opts)
			})
		})
	}
}

// TestExtractTarStrictModesIgnoreUmask proves Placed.Mode is the on-disk mode
// under a restrictive umask, which would otherwise strip group and other bits
// from 0o775 directories and 0o755/0o644 files. It changes the process umask,
// so it must not run in parallel with other tests.
func TestExtractTarStrictModesIgnoreUmask(t *testing.T) {
	old := syscall.Umask(0o027)
	t.Cleanup(func() { syscall.Umask(old) })
	c := strictCases()[0]
	data := fixtureTar(t, c.members...)
	checkStrictCase(t, c, func(root *os.Root, opts archive.Options) ([]archive.Placed, error) {
		return archive.ExtractTar(bytes.NewReader(data), root, opts)
	})
}

// TestExtractTarStrictRefusesPreexistingDirectory pins that strict
// extraction trusts only directories it created itself: a directory already
// in the root is refused, whether a member needs it as a parent or names it.
func TestExtractTarStrictRefusesPreexistingDirectory(t *testing.T) {
	cases := map[string]fixtureMember{
		"as a parent":     {name: "a/f", kind: fixtureFile, body: "f"},
		"as a dir member": {name: "a/", kind: fixtureDir},
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			_, root := newTestRoot(t)
			if err := root.Mkdir("a", 0o755); err != nil {
				t.Fatal(err)
			}
			_, err := archive.ExtractTar(bytes.NewReader(fixtureTar(t, m)), root, strictCase{}.options())
			if err == nil || !strings.Contains(err.Error(), `needs the directory "a", which existed before extraction`) {
				t.Fatalf("error = %v, want the pre-existing directory refusal", err)
			}
		})
	}
}

func TestExtractTarStrictRefusesBadOptions(t *testing.T) {
	valid := strictCase{}.options()
	cases := map[string]struct {
		mutate  func(*archive.Options)
		wantErr string
	}{
		"zero DirPerm":           {func(o *archive.Options) { o.DirPerm = 0 }, "DirPerm"},
		"DirPerm with setgid":    {func(o *archive.Options) { o.DirPerm = fs.ModeSetgid | 0o755 }, "DirPerm"},
		"DirPerm without x":      {func(o *archive.Options) { o.DirPerm = 0o644 }, "DirPerm"},
		"zero Limits":            {func(o *archive.Options) { o.Limits = archive.Limits{} }, "Limits"},
		"zero MaxEntries":        {func(o *archive.Options) { o.Limits.MaxEntries = 0 }, "Limits"},
		"negative MaxTotalBytes": {func(o *archive.Options) { o.Limits.MaxTotalBytes = -1 }, "Limits"},
	}
	data := fixtureTar(t, fixtureMember{name: "a", kind: fixtureFile, body: "a"})
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			opts := valid
			c.mutate(&opts)
			_, root := newTestRoot(t)
			_, err := archive.ExtractTar(bytes.NewReader(data), root, opts)
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("error = %v, want one containing %q", err, c.wantErr)
			}
			if _, err := root.Lstat("a"); err == nil {
				t.Fatal("a member was extracted despite invalid options")
			}
		})
	}
}

func TestExtractTarPackagePolicyRefusesStripAndInclude(t *testing.T) {
	data := fixtureTar(t, fixtureMember{name: "a/b", kind: fixtureFile, body: "b"})
	cases := map[string]archive.Options{
		"StripComponents": {Policy: archive.PolicyPackage, Limits: archive.DefaultLimits(), DirPerm: 0o755, StripComponents: 1},
		"Include":         {Policy: archive.PolicyPackage, Limits: archive.DefaultLimits(), DirPerm: 0o755, Include: []string{"a"}},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			_, root := newTestRoot(t)
			_, err := archive.ExtractTar(bytes.NewReader(data), root, opts)
			if err == nil || !strings.Contains(err.Error(), "only supported with PolicyStrict") {
				t.Fatalf("error = %v, want one saying the option needs PolicyStrict", err)
			}
		})
	}
}

package importer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/trevor-vaughan/polypkg/internal/archive"
	"github.com/trevor-vaughan/polypkg/internal/pkglint"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// tarEntry is one member of a test archive: a directory when dir is set, a
// symlink when link is set, else a regular file holding body.
type tarEntry struct {
	name string
	mode int64
	body string
	dir  bool
	link string
}

// tarGz encodes entries as a gzip-compressed tar archive.
func tarGz(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: e.mode, ModTime: time.Unix(0, 0)}
		switch {
		case e.dir:
			hdr.Typeflag = tar.TypeDir
		case e.link != "":
			hdr.Typeflag, hdr.Linkname = tar.TypeSymlink, e.link
		default:
			hdr.Typeflag, hdr.Size = tar.TypeReg, int64(len(e.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// toolArchive is a release archive laid out the common way: everything below
// one top-level directory.
func toolArchive(t *testing.T) []byte {
	t.Helper()
	return tarGz(t,
		tarEntry{name: "tool-1.2.3/", dir: true, mode: 0o755},
		tarEntry{name: "tool-1.2.3/tool", mode: 0o755, body: "#!/bin/sh\necho tool\n"},
		tarEntry{name: "tool-1.2.3/README.md", mode: 0o644, body: "readme\n"},
	)
}

// testExecutableText follows the header of every test executable.
const testExecutableText = "test executable\n"

var (
	elfBinary      = elfExecutable(elf.EM_X86_64)
	elfARM64Binary = elfExecutable(elf.EM_AARCH64)
	machOBinary    = machOExecutable(macho.CpuArm64)
)

// elfExecutable returns a little-endian 64-bit ELF executable for machine.
func elfExecutable(machine elf.Machine) []byte { return elfFile(machine, elf.ET_EXEC) }

// elfFile returns a little-endian 64-bit ELF file of type typ for machine: a
// header with no program or section headers, which debug/elf reads, then
// fixed text.
func elfFile(machine elf.Machine, typ elf.Type) []byte {
	h := make([]byte, 64, 64+len(testExecutableText))
	copy(h, []byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)})
	binary.LittleEndian.PutUint16(h[16:], uint16(typ))
	binary.LittleEndian.PutUint16(h[18:], uint16(machine))
	binary.LittleEndian.PutUint32(h[20:], uint32(elf.EV_CURRENT))
	binary.LittleEndian.PutUint16(h[52:], 64) // e_ehsize
	return append(h, testExecutableText...)
}

// machOExecutable returns a little-endian 64-bit Mach-O executable for cpu.
func machOExecutable(cpu macho.Cpu) []byte { return machOFile(cpu, macho.TypeExec) }

// machOFile returns a little-endian 64-bit Mach-O file of type typ for cpu: a
// header with no load commands, which debug/macho reads, then fixed text.
func machOFile(cpu macho.Cpu, typ macho.Type) []byte {
	h := make([]byte, 32, 32+len(testExecutableText))
	binary.LittleEndian.PutUint32(h[0:], macho.Magic64)
	binary.LittleEndian.PutUint32(h[4:], uint32(cpu))
	binary.LittleEndian.PutUint32(h[12:], uint32(typ))
	return append(h, testExecutableText...)
}

// universalExecutable returns a universal ("fat") Mach-O holding one thin
// executable per cpu.
func universalExecutable(cpus ...macho.Cpu) []byte { return universalFile(macho.TypeExec, cpus...) }

// universalFile returns a universal ("fat") Mach-O holding one thin file of
// type typ per cpu.
func universalFile(typ macho.Type, cpus ...macho.Cpu) []byte {
	thins := make([][]byte, len(cpus))
	for i, cpu := range cpus {
		thins[i] = machOFile(cpu, typ)
	}
	return fatOf(thins...)
}

// fatOf returns a universal ("fat") Mach-O holding the thin files given, each
// listed under the CPU type its own header names.
func fatOf(thins ...[]byte) []byte {
	const fatHeader, fatArch = 8, 20
	var head, body []byte
	head = binary.BigEndian.AppendUint32(head, macho.MagicFat)
	head = binary.BigEndian.AppendUint32(head, uint32(len(thins)))
	offset := fatHeader + fatArch*len(thins)
	for _, thin := range thins {
		cpu := binary.LittleEndian.Uint32(thin[4:])
		for _, v := range []uint32{cpu, 0, uint32(offset + len(body)), uint32(len(thin)), 0} {
			head = binary.BigEndian.AppendUint32(head, v)
		}
		body = append(body, thin...)
	}
	return append(head, body...)
}

// sandboxHome points HOME and every XDG base directory at fresh temporary
// directories, so no test reads or writes the real user's.
func sandboxHome(t *testing.T) {
	t.Helper()
	for _, v := range []string{"HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_BIN_HOME", "XDG_RUNTIME_DIR"} {
		t.Setenv(v, t.TempDir())
	}
}

func TestResolveName(t *testing.T) {
	for _, c := range []struct{ explicit, repo, want string }{
		{"", "RipGrep", "ripgrep"},
		{"rg", "ripgrep", "rg"},
	} {
		if got, err := resolveName(c.explicit, c.repo); err != nil || got != c.want {
			t.Errorf("resolveName(%q, %q) = %q, %v; want %q", c.explicit, c.repo, got, err, c.want)
		}
	}
	for _, c := range []struct {
		explicit, repo, wantName string
		wantFromRepo             bool
	}{
		{"", "tool.js", "tool.js", true},
		{"my tool", "tool", "my tool", false},
	} {
		_, err := resolveName(c.explicit, c.repo)
		var ne *NameError
		if !errors.As(err, &ne) || ne.Name != c.wantName || ne.FromRepo != c.wantFromRepo || ne.Err == nil {
			t.Errorf("resolveName(%q, %q) = %#v, want a *NameError for %q (from repo %t)", c.explicit, c.repo, err, c.wantName, c.wantFromRepo)
		}
		if err != nil && strings.Contains(err.Error(), "pass --") {
			t.Errorf("resolveName error %q carries a hint; the CLI adds it", err)
		}
	}
}

func TestResolveVersion(t *testing.T) {
	for _, c := range []struct{ explicit, tag, want string }{
		{"", "v14.1.1", "14.1.1"},
		{"", "V2.0.0", "2.0.0"},
		{"", "1.2.3-rc.1+build.5", "1.2.3-rc.1+build.5"},
		{"2.0.0", "nightly", "2.0.0"},
	} {
		if got, err := resolveVersion(c.explicit, c.tag); err != nil || got != c.want {
			t.Errorf("resolveVersion(%q, %q) = %q, %v; want %q", c.explicit, c.tag, got, err, c.want)
		}
	}
	for _, c := range []struct {
		explicit, tag, wantVersion string
		wantFromTag                bool
		wantErr                    string
	}{
		{"", "nightly", "nightly", true, `release tag "nightly" is not a semantic version`},
		{"", "v", "v", true, "is not a semantic version"},
		{"", "", "", true, "is not a semantic version"},
		{"latest", "v1.0.0", "latest", false, `version "latest" is not a semantic version`},
		{"../1.0.0", "v1.0.0", "../1.0.0", false, "not a semantic version"},
	} {
		_, err := resolveVersion(c.explicit, c.tag)
		var ve *VersionError
		if !errors.As(err, &ve) || ve.Version != c.wantVersion || ve.FromTag != c.wantFromTag ||
			!strings.Contains(err.Error(), c.wantErr) || strings.Contains(err.Error(), "pass --") {
			t.Errorf("resolveVersion(%q, %q) = %v, want a *VersionError for %q (from tag %t) saying %q and no hint",
				c.explicit, c.tag, err, c.wantVersion, c.wantFromTag, c.wantErr)
		}
	}
}

func TestCheckVersion(t *testing.T) {
	if err := CheckVersion("1.2.3-rc.1"); err != nil {
		t.Fatalf("CheckVersion: %v", err)
	}
	var ve *VersionError
	if err := CheckVersion("latest"); !errors.As(err, &ve) || ve.Version != "latest" || ve.FromTag {
		t.Fatalf("CheckVersion(latest) = %v, want an explicit *VersionError", err)
	}
}

func TestCheckBins(t *testing.T) {
	if err := CheckBins([]string{"rg", "rg-helper", "x_y"}); err != nil {
		t.Fatalf("CheckBins: %v", err)
	}
	for _, c := range []struct {
		bins         []string
		wantBin      string
		wantRepeated bool
		wantErr      string
	}{
		{[]string{"bin/rg"}, "bin/rg", false, `--bin "bin/rg" is not a command name`},
		{[]string{"rg.exe"}, "rg.exe", false, "is not a command name"},
		{[]string{""}, "", false, "is not a command name"},
		{[]string{"rg", "rg"}, "rg", true, `--bin "rg" is given twice`},
	} {
		err := CheckBins(c.bins)
		var be *BinError
		if !errors.As(err, &be) || be.Bin != c.wantBin || be.Repeated != c.wantRepeated || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("CheckBins(%q) = %#v, want a *BinError for %q (repeated %t) saying %q", c.bins, err, c.wantBin, c.wantRepeated, c.wantErr)
		}
	}
}

func TestDetectKind(t *testing.T) {
	universal := universalExecutable(macho.CpuAmd64, macho.CpuArm64)
	for _, c := range []struct {
		name         string
		data         []byte
		goos, goarch string
		wantFormat   archive.Format
		wantBare     bool
		wantErr      string
	}{
		{"a tar.gz archive", toolArchive(t), "linux", "amd64", archive.FormatTarGz, false, ""},
		{"a zip archive", []byte("PK\x03\x04rest"), "darwin", "arm64", archive.FormatZip, false, ""},
		{"an x86-64 ELF executable for linux/amd64", elfBinary, "linux", "amd64", 0, true, ""},
		{"an x86-64 ELF executable for freebsd/amd64", elfBinary, "freebsd", "amd64", 0, true, ""},
		{"an arm64 ELF executable for linux/arm64", elfARM64Binary, "linux", "arm64", 0, true, ""},
		{"a big-endian ppc64 ELF executable for linux/ppc64", bigEndianELF(elf.EM_PPC64), "linux", "ppc64", 0, true, ""},
		{"an arm64 Mach-O executable for darwin/arm64", machOBinary, "darwin", "arm64", 0, true, ""},
		{"a universal Mach-O executable for darwin/arm64", universal, "darwin", "arm64", 0, true, ""},
		{"a universal Mach-O executable for darwin/amd64", universal, "darwin", "amd64", 0, true, ""},
		{"an ELF executable for darwin", elfBinary, "darwin", "amd64", 0, false, "nor a Mach-O executable for darwin"},
		{"a Mach-O executable for linux", machOBinary, "linux", "arm64", 0, false, "nor an ELF executable for linux"},
		{"a shell script", []byte("#!/bin/sh\necho hi\n"), "linux", "amd64", 0, false, "is neither an archive"},
		{"an empty file", nil, "linux", "amd64", 0, false, "is neither an archive"},
		{"an x86-64 ELF executable for linux/arm64", elfBinary, "linux", "arm64", 0, false, "is an ELF executable for amd64, not linux/arm64"},
		{"an arm64 ELF executable for linux/amd64", elfARM64Binary, "linux", "amd64", 0, false, "is an ELF executable for arm64, not linux/amd64"},
		{"an ELF executable for an unknown machine", elfExecutable(elf.EM_MIPS), "linux", "amd64", 0, false, "is an ELF executable for EM_MIPS, not linux/amd64"},
		{"a position-independent ELF executable", elfFile(elf.EM_X86_64, elf.ET_DYN), "linux", "amd64", 0, true, ""},
		{"an ELF relocatable object", elfFile(elf.EM_X86_64, elf.ET_REL), "linux", "amd64", 0, false, "is an ELF ET_REL file, not an executable"},
		{"an ELF core dump", elfFile(elf.EM_X86_64, elf.ET_CORE), "linux", "amd64", 0, false, "is an ELF ET_CORE file, not an executable"},
		{"a Mach-O dynamic library", machOFile(macho.CpuArm64, macho.TypeDylib), "darwin", "arm64", 0, false, "is a Mach-O Dylib file, not an executable"},
		{"a universal Mach-O object", universalFile(macho.TypeObj, macho.CpuAmd64, macho.CpuArm64), "darwin", "arm64", 0, false, "is a universal Mach-O whose arm64 slice is not an executable (type Obj)"},
		{"a universal Mach-O whose slice for the architecture is not an executable",
			fatOf(machOFile(macho.CpuAmd64, macho.TypeExec), machOFile(macho.CpuArm64, macho.TypeDylib)), "darwin", "arm64", 0, false,
			"cannot be read as a Mach-O executable"},
		{"a truncated ELF executable", elfBinary[:20], "linux", "amd64", 0, false, "cannot be read as an ELF executable"},
		{"an arm64 Mach-O executable for darwin/amd64", machOBinary, "darwin", "amd64", 0, false, "is a Mach-O executable for arm64, not darwin/amd64"},
		{"a universal Mach-O executable without the architecture", universalExecutable(macho.CpuAmd64), "darwin", "arm64", 0, false,
			"is a universal Mach-O file for amd64, not darwin/arm64"},
		{"a truncated universal Mach-O executable", universal[:12], "darwin", "arm64", 0, false, "cannot be read as a Mach-O executable"},
	} {
		t.Run(c.name, func(t *testing.T) {
			format, bare, err := detectKind(c.data, c.goos, c.goarch)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("error = %v, want %q", err, c.wantErr)
				}
				return
			}
			if err != nil || format != c.wantFormat || bare != c.wantBare {
				t.Fatalf("detectKind = %v, %v, %v; want %v, %v", format, bare, err, c.wantFormat, c.wantBare)
			}
		})
	}
}

// bigEndianELF returns a big-endian 64-bit ELF executable for machine.
func bigEndianELF(machine elf.Machine) []byte {
	h := make([]byte, 64)
	copy(h, []byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2MSB), byte(elf.EV_CURRENT)})
	binary.BigEndian.PutUint16(h[16:], uint16(elf.ET_EXEC))
	binary.BigEndian.PutUint16(h[18:], uint16(machine))
	binary.BigEndian.PutUint32(h[20:], uint32(elf.EV_CURRENT))
	binary.BigEndian.PutUint16(h[52:], 64) // e_ehsize
	return h
}

func TestChooseStrip(t *testing.T) {
	exe := func(name string) tarEntry { return tarEntry{name: name, mode: 0o755, body: "x"} }
	dir := func(name string) tarEntry { return tarEntry{name: name, dir: true, mode: 0o755} }
	doc := func(name string) tarEntry { return tarEntry{name: name, mode: 0o644, body: "doc"} }
	for _, c := range []struct {
		name      string
		entries   []tarEntry
		wantStrip int
		wantPaths []string
	}{
		{"one top-level directory", []tarEntry{dir("tool-1.2.3/"), exe("tool-1.2.3/tool"), doc("tool-1.2.3/doc/README")}, 1, []string{"tool", "doc", "doc/README"}},
		{"an implicit top-level directory", []tarEntry{exe("tool-1.2.3/bin/tool")}, 1, []string{"bin", "bin/tool"}},
		{"a ./ prefix before the top-level directory", []tarEntry{dir("./"), dir("./tool-1.2.3/"), exe("./tool-1.2.3/tool")}, 2, []string{"tool"}},
		{"members at the top level", []tarEntry{exe("tool"), doc("README")}, 0, []string{"tool", "README"}},
		{"two top-level directories", []tarEntry{exe("a/tool"), exe("b/tool")}, 0, []string{"a", "a/tool", "b", "b/tool"}},
		{"a single top-level file", []tarEntry{exe("tool")}, 0, []string{"tool"}},
		{"an empty top-level directory", []tarEntry{dir("tool-1.2.3/")}, 0, []string{"tool-1.2.3"}},
		{"a strip that would expose a drive-letter name", []tarEntry{exe("pkg/C:tool")}, 0, []string{"pkg", "pkg/C:tool"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			strip, members, err := chooseStrip(tarGz(t, c.entries...), archive.FormatTarGz)
			if err != nil {
				t.Fatalf("chooseStrip: %v", err)
			}
			paths := make([]string, len(members))
			for i, m := range members {
				paths[i] = m.Path
			}
			if strip != c.wantStrip || !reflect.DeepEqual(paths, c.wantPaths) {
				t.Fatalf("chooseStrip = %d %q, want %d %q", strip, paths, c.wantStrip, c.wantPaths)
			}
		})
	}
}

func TestChooseStripRefusesWhatExtractWouldRefuse(t *testing.T) {
	data := tarGz(t, tarEntry{name: "../evil", mode: 0o755, body: "x"})
	if _, _, err := chooseStrip(data, archive.FormatTarGz); err == nil || !strings.Contains(err.Error(), "'..' segment") {
		t.Fatalf("chooseStrip error = %v, want a '..' refusal", err)
	}
}

func TestLocateBin(t *testing.T) {
	exe := func(p string) archive.Member { return archive.Member{Path: p, Kind: archive.KindFile, Mode: 0o755} }
	members := []archive.Member{
		{Path: "bin", Kind: archive.KindDir, Mode: 0o700},
		exe("bin/tool"),
		exe("bin/helper"),
		{Path: "doc", Kind: archive.KindDir, Mode: 0o700},
		{Path: "doc/tool", Kind: archive.KindFile, Mode: 0o644},
		{Path: "tool-link", Kind: archive.KindSymlink},
	}
	if got, err := locateBin(members, "tool"); err != nil || got != "bin/tool" {
		t.Fatalf(`locateBin("tool") = %q, %v; want "bin/tool"`, got, err)
	}
	if got, err := locateBin(members, "helper"); err != nil || got != "bin/helper" {
		t.Fatalf(`locateBin("helper") = %q, %v; want "bin/helper"`, got, err)
	}

	many := make([]archive.Member, 0, 25)
	for i := range 25 {
		many = append(many, exe(fmt.Sprintf("bin/x%02d", i)))
	}
	for _, c := range []struct {
		name    string
		members []archive.Member
		bin     string
		wantErr string
	}{
		{"no executable of that name", members, "missing", `no executable named "missing"; executables found: "bin/tool", "bin/helper" (choose one with --bin)`},
		{"two executables of that name", append(members, exe("libexec/tool")), "tool", `more than one executable named "tool": "bin/tool", "libexec/tool"`},
		{"no executables at all", []archive.Member{{Path: "README", Kind: archive.KindFile, Mode: 0o644}}, "tool", "holds no executable file"},
		{"a '$' in the executable's path", []archive.Member{exe("$ACTIVE/tool")}, "tool", "has a '$' in its archive path"},
		{"a long list of executables is cut short", many, "tool", `"bin/x19" and 5 more`},
		{"an executable path is quoted, never printed raw", []archive.Member{exe("evil\x1b[31mRED\nFAKE line")}, "tool",
			`executables found: "evil\x1b[31mRED\nFAKE line"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := locateBin(c.members, c.bin); err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("error = %v, want %q", err, c.wantErr)
			}
		})
	}
}

func TestArchiveRecipeLayout(t *testing.T) {
	meta := recipeMeta{name: "ripgrep", version: "14.1.1", title: "ripgrep", description: "Fast grep."}
	asset := "ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz"
	got := archiveRecipe(meta, "linux/amd64", asset, 1, []binLocation{{name: "rg", path: "rg"}})
	want := &schema.Package{
		Schema: "polypkg.package/v1", Name: "ripgrep", Version: "14.1.1", Platform: "linux/amd64",
		Title: "ripgrep", Description: "Fast grep.",
		Actions: []schema.PackageAction{
			{Phase: "post-place", Action: "extract", Params: map[string]any{
				"src": "$PKG/content/" + asset, "dest": "$ACTIVE/ripgrep/dist", "strip_components": 1}},
			{Phase: "post-place", Action: "path", Params: map[string]any{"name": "rg", "source": "$ACTIVE/ripgrep/dist/rg"}},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("archiveRecipe:\n got %+v\nwant %+v", got, want)
	}
	flat := archiveRecipe(meta, "linux/amd64", asset, 0, []binLocation{{name: "rg", path: "rg"}})
	if _, ok := flat.Actions[0].Params["strip_components"]; ok {
		t.Fatalf("strip_components 0 must be omitted, got %v", flat.Actions[0].Params)
	}
}

func TestBareRecipeLayout(t *testing.T) {
	meta := recipeMeta{name: "yq", version: "4.44.3", title: "yq"}
	got := bareRecipe(meta, "darwin/arm64", "yq_darwin_arm64", "yq")
	want := &schema.Package{
		Schema: "polypkg.package/v1", Name: "yq", Version: "4.44.3", Platform: "darwin/arm64", Title: "yq",
		Actions: []schema.PackageAction{
			{Phase: "post-place", Action: "install", Params: map[string]any{
				"src": "$PKG/content/yq_darwin_arm64", "dest": "$ACTIVE/yq/bin/yq", "policy": "copy"}},
			{Phase: "post-place", Action: "path", Params: map[string]any{"name": "yq", "source": "$ACTIVE/yq/bin/yq"}},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("bareRecipe:\n got %+v\nwant %+v", got, want)
	}
}

// TestRecipesPassLint proves every recipe shape the importer generates is a
// clean package source and survives a YAML round trip unchanged.
func TestRecipesPassLint(t *testing.T) {
	meta := recipeMeta{name: "tool", version: "1.2.3", title: "tool", description: "A tool: for testing."}
	for _, c := range []struct {
		name   string
		recipe *schema.Package
		asset  string
		data   []byte
		mode   fs.FileMode
	}{
		{"archive with strip", archiveRecipe(meta, "linux/amd64", "tool_1.2.3_linux_amd64.tar.gz", 1,
			[]binLocation{{name: "tool", path: "tool"}}), "tool_1.2.3_linux_amd64.tar.gz", toolArchive(t), 0o644},
		{"archive without strip", archiveRecipe(meta, "freebsd/amd64", "tool.tar.gz", 0,
			[]binLocation{{name: "tool", path: "bin/tool"}, {name: "helper", path: "bin/helper"}}), "tool.tar.gz", toolArchive(t), 0o644},
		{"bare executable", bareRecipe(meta, "darwin/arm64", "tool_1.2.3_darwin_arm64", "tool"),
			"tool_1.2.3_darwin_arm64", machOBinary, 0o755},
	} {
		t.Run(c.name, func(t *testing.T) {
			raw, err := marshalRecipe(c.recipe, "github:acme/tool, version 1.2.3")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(raw, []byte("# Generated by `polypkg pkg import` from github:acme/tool, version 1.2.3.\n")) {
				t.Fatalf("recipe does not start with its origin comment:\n%s", raw)
			}
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, "content"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "polypkg.yaml"), raw, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "content", c.asset), c.data, c.mode); err != nil {
				t.Fatal(err)
			}
			res, err := pkglint.Lint(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Findings) != 0 {
				t.Fatalf("lint findings for\n%s\n%+v", raw, res.Findings)
			}
			parsed, err := schema.ParsePackage(bytes.NewReader(raw), "polypkg.yaml")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(parsed, c.recipe) {
				t.Fatalf("round trip:\n got %+v\nwant %+v", parsed, c.recipe)
			}
		})
	}
}

func TestCleanDescription(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"  A tool\nfor testing.  ", "A tool for testing."},
		{"A\ttool\r\nfor\u0085testing", "A tool for testing"},
		{"red\x1b[31m alert\u009b\x7f!", "red[31m alert!"},
		{"\x00\x07", ""},
		{"", ""},
	} {
		if got := cleanDescription(c.in); got != c.want {
			t.Errorf("cleanDescription(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

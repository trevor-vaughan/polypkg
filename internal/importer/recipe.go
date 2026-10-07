// Package importer turns a GitHub release into publish-ready polypkg package
// sources: one per platform, each holding the upstream asset verbatim under
// content/, a generated polypkg.yaml that installs it, and the asset's
// verified GitHub artifact attestations under attestations/.
package importer

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/Masterminds/semver/v3"
	"gopkg.in/yaml.v3"

	"github.com/trevor-vaughan/polypkg/internal/action"
	"github.com/trevor-vaughan/polypkg/internal/archive"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

const (
	// postPlace is the phase every generated action runs at: right after the
	// package's files are placed.
	postPlace = "post-place"
	// maxListedExecutables bounds how many executables a refusal names.
	maxListedExecutables = 20
	// listDirPerm is the directory mode listings run with. Listings compare
	// paths and kinds; the extract action applies its own directory mode.
	listDirPerm = 0o700
)

var (
	// binName is the path action's command-name grammar, compiled from the
	// action package's own pattern.
	binName = regexp.MustCompile(action.NamePattern)
	// versionPattern keeps a version usable as the <version> directory of the
	// output layout: one path segment that cannot be "." or "..".
	versionPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+-]*$`)

	elfMagic      = []byte{0x7f, 'E', 'L', 'F'}
	machOFatMagic = []byte{0xca, 0xfe, 0xba, 0xbe}
	// machOMagics are the 32- and 64-bit Mach-O magics in both byte orders and
	// the universal ("fat") headers that bundle several architectures.
	machOMagics = [][]byte{
		{0xfe, 0xed, 0xfa, 0xce}, {0xce, 0xfa, 0xed, 0xfe},
		{0xfe, 0xed, 0xfa, 0xcf}, {0xcf, 0xfa, 0xed, 0xfe},
		{0xca, 0xfe, 0xba, 0xbe}, {0xca, 0xfe, 0xba, 0xbf},
	}
	// machOArches maps the Mach-O CPU types darwin runs to their GOARCH.
	machOArches = map[macho.Cpu]string{macho.CpuAmd64: "amd64", macho.CpuArm64: "arm64"}
)

// resolveName returns the package name: explicit when given, else the
// repository name lower-cased. It must be a package-name slug; otherwise the
// error is a *NameError.
func resolveName(explicit, repo string) (string, error) {
	name := explicit
	if name == "" {
		name = strings.ToLower(repo)
	}
	if err := schema.ValidatePackageName(name); err != nil {
		return "", &NameError{Name: name, FromRepo: explicit == "", Err: err}
	}
	return name, nil
}

// resolveVersion returns the package version: explicit when given, else the
// release tag without a leading "v" or "V" before a digit ("v14.1.1" is
// 14.1.1). A version that is not a semantic version is a *VersionError.
func resolveVersion(explicit, tag string) (string, error) {
	if explicit != "" {
		return explicit, CheckVersion(explicit)
	}
	v := tag
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		v = v[1:]
	}
	if !isVersion(v) {
		return "", &VersionError{Version: tag, FromTag: true}
	}
	return v, nil
}

// CheckVersion refuses, as a *VersionError, a --version that is not a
// semantic version usable as a directory name.
func CheckVersion(v string) error {
	if !isVersion(v) {
		return &VersionError{Version: v}
	}
	return nil
}

// isVersion reports whether v is a semantic version, which the resolver
// orders packages by, and a single safe path segment, which the output layout
// uses as a directory name.
func isVersion(v string) bool {
	if !versionPattern.MatchString(v) {
		return false
	}
	_, err := semver.NewVersion(v)
	return err == nil
}

// CheckBins refuses, as a *BinError, a --bin that the path action could not
// expose and a repeated one.
func CheckBins(bins []string) error {
	seen := make(map[string]bool, len(bins))
	for _, b := range bins {
		if !binName.MatchString(b) {
			return &BinError{Bin: b}
		}
		if seen[b] {
			return &BinError{Bin: b, Repeated: true}
		}
		seen[b] = true
	}
	return nil
}

// detectKind classifies an asset by its bytes, never its name: an archive the
// extract action can unpack (format), or a bare executable for goos/goarch
// (bare) — ELF for every OS but darwin, Mach-O (thin or universal) for darwin.
// An executable built for another architecture, or for a machine polypkg
// cannot map to one, is refused, so a misnamed asset or a --platform override
// never ships the wrong architecture. Anything else is refused too.
func detectKind(data []byte, goos, goarch string) (format archive.Format, bare bool, err error) {
	head := data[:min(len(data), archive.DetectHeaderLen)]
	if f, derr := archive.Detect(head); derr == nil {
		return f, false, nil
	}
	if goos == "darwin" {
		if !slices.ContainsFunc(machOMagics, func(m []byte) bool { return bytes.HasPrefix(head, m) }) {
			return 0, false, fmt.Errorf("is neither an archive polypkg can unpack (tar.gz, tar.zst, tar.xz, zip, tar) nor a Mach-O executable for %s", goos)
		}
		if err := checkMachOArch(data, goos, goarch); err != nil {
			return 0, false, err
		}
		return 0, true, nil
	}
	if !bytes.HasPrefix(head, elfMagic) {
		return 0, false, fmt.Errorf("is neither an archive polypkg can unpack (tar.gz, tar.zst, tar.xz, zip, tar) nor an ELF executable for %s", goos)
	}
	if err := checkELFArch(data, goos, goarch); err != nil {
		return 0, false, err
	}
	return 0, true, nil
}

// checkELFArch refuses an ELF file that is not an executable (ET_EXEC, or
// ET_DYN for a position-independent one) or whose machine is not goarch.
func checkELFArch(data []byte, goos, goarch string) error {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("starts like an ELF file but cannot be read as an ELF executable: %w", err)
	}
	if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return fmt.Errorf("is an ELF %s file, not an executable", f.Type)
	}
	got := elfArch(f.FileHeader)
	if got == goarch {
		return nil
	}
	if got == "" {
		got = f.Machine.String()
	}
	return fmt.Errorf("is an ELF executable for %s, not %s/%s", got, goos, goarch)
}

// elfArch returns the GOARCH an ELF header's machine runs as, or "" for a
// machine polypkg does not map. RISC-V and s390 are 64-bit only in Go, and
// 64-bit PowerPC is ppc64le or ppc64 by byte order.
func elfArch(h elf.FileHeader) string {
	switch h.Machine {
	case elf.EM_X86_64:
		return "amd64"
	case elf.EM_AARCH64:
		return "arm64"
	case elf.EM_386:
		return "386"
	case elf.EM_RISCV:
		if h.Class == elf.ELFCLASS64 {
			return "riscv64"
		}
	case elf.EM_PPC64:
		if h.Data == elf.ELFDATA2LSB {
			return "ppc64le"
		}
		return "ppc64"
	case elf.EM_S390:
		if h.Class == elf.ELFCLASS64 {
			return "s390x"
		}
	}
	return ""
}

// checkMachOArch refuses a Mach-O file that does not run as goarch: a thin
// one that is not an executable or was built for another CPU, or a universal
// one with no executable slice for goarch. A slice counts only when its header
// and the image it points at agree on the CPU, since the header picks the
// slice and the image is what runs.
func checkMachOArch(data []byte, goos, goarch string) error {
	r := bytes.NewReader(data)
	if bytes.HasPrefix(data, machOFatMagic) {
		ff, err := macho.NewFatFile(r)
		if err != nil {
			return fmt.Errorf("starts like a universal Mach-O file but cannot be read as a Mach-O executable: %w", err)
		}
		names := make([]string, 0, len(ff.Arches))
		for _, a := range ff.Arches {
			if a.Cpu == a.File.Cpu && machOArch(a.Cpu) == goarch {
				if a.Type != macho.TypeExec {
					return fmt.Errorf("is a universal Mach-O whose %s slice is not an executable (type %s)", goarch, a.Type)
				}
				return nil
			}
			names = append(names, machOArch(a.Cpu))
		}
		return fmt.Errorf("is a universal Mach-O file for %s, not %s/%s", strings.Join(names, ", "), goos, goarch)
	}
	f, err := macho.NewFile(r)
	if err != nil {
		return fmt.Errorf("starts like a Mach-O file but cannot be read as a Mach-O executable: %w", err)
	}
	if f.Type != macho.TypeExec {
		return fmt.Errorf("is a Mach-O %s file, not an executable", f.Type)
	}
	if got := machOArch(f.Cpu); got != goarch {
		return fmt.Errorf("is a Mach-O executable for %s, not %s/%s", got, goos, goarch)
	}
	return nil
}

// machOArch returns the GOARCH a Mach-O CPU type runs as, or the CPU type's
// own name when polypkg does not map it.
func machOArch(c macho.Cpu) string {
	if a, ok := machOArches[c]; ok {
		return a
	}
	return c.String()
}

// listOptions are the options a listing runs with: the strict policy and
// default limits the extract action applies, so a listing refuses exactly
// what apply would.
func listOptions(format archive.Format, strip int) archive.Options {
	return archive.Options{
		Format:          format,
		Policy:          archive.PolicyStrict,
		Limits:          archive.DefaultLimits(),
		StripComponents: strip,
		DirPerm:         listDirPerm,
	}
}

// chooseStrip decides the extract action's strip_components for the archive
// in data and returns the archive's listing at that strip. It is 0 unless
// every member lies below one top-level directory; then it is the smallest
// strip (1, or 2 for names that start with "./") whose listing is exactly the
// strip-0 listing with that directory removed. A candidate strip that extract
// would refuse is not used.
func chooseStrip(data []byte, format archive.Format) (strip int, members []archive.Member, err error) {
	list := func(strip int) ([]archive.Member, error) {
		return archive.List(bytes.NewReader(data), int64(len(data)), listOptions(format, strip))
	}
	all, err := list(0)
	if err != nil {
		return 0, nil, err
	}
	want, ok := belowSoleTopDir(all)
	if !ok {
		return 0, all, nil
	}
	for strip := 1; strip <= 2; strip++ {
		if got, lerr := list(strip); lerr == nil && slices.Equal(got, want) {
			return strip, got, nil
		}
	}
	return 0, all, nil
}

// belowSoleTopDir returns members as they read with their single top-level
// directory removed, when every member lies below one directory and that
// directory holds something; ok is false otherwise.
func belowSoleTopDir(members []archive.Member) (below []archive.Member, ok bool) {
	if len(members) == 0 {
		return nil, false
	}
	top, _, _ := strings.Cut(members[0].Path, "/")
	below = make([]archive.Member, 0, len(members))
	sawTop := false
	for _, m := range members {
		if m.Path == top {
			if m.Kind != archive.KindDir {
				return nil, false
			}
			sawTop = true
			continue
		}
		rest, under := strings.CutPrefix(m.Path, top+"/")
		if !under {
			return nil, false
		}
		m.Path = rest
		below = append(below, m)
	}
	return below, sawTop && len(below) > 0
}

// locateBin finds the executable named bin among an archive listing: a
// regular file with an execute bit whose base name is bin. It refuses when
// there is no such file or more than one, naming the executables it saw.
func locateBin(members []archive.Member, bin string) (string, error) {
	var hits []string
	execs := make([]string, 0, len(members))
	for _, m := range members {
		if m.Kind != archive.KindFile || m.Mode&0o111 == 0 {
			continue
		}
		execs = append(execs, m.Path)
		if path.Base(m.Path) == bin {
			hits = append(hits, m.Path)
		}
	}
	switch {
	case len(hits) == 1:
		if strings.Contains(hits[0], "$") {
			return "", fmt.Errorf("the executable %q has a '$' in its archive path, which apply would read as a path variable", hits[0])
		}
		return hits[0], nil
	case len(hits) > 1:
		return "", fmt.Errorf("the archive holds more than one executable named %q: %s", bin, listPaths(hits))
	case len(execs) == 0:
		return "", fmt.Errorf("the archive holds no executable file, so nothing named %q can go on PATH", bin)
	default:
		return "", fmt.Errorf("the archive holds no executable named %q; executables found: %s (choose one with --bin)", bin, listPaths(execs))
	}
}

// listPaths joins paths for a message, each quoted so a control character in
// an archive member name cannot reach a terminal raw, naming at most
// maxListedExecutables.
func listPaths(paths []string) string {
	shown := paths[:min(len(paths), maxListedExecutables)]
	quoted := make([]string, len(shown))
	for i, p := range shown {
		quoted[i] = strconv.Quote(p)
	}
	if len(paths) <= maxListedExecutables {
		return strings.Join(quoted, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(quoted, ", "), len(paths)-maxListedExecutables)
}

// cleanDescription makes a repository description fit for the recipe's
// one-line description: whitespace runs (newlines included) become single
// spaces, and every other C0 or C1 control character or DEL is removed, so
// an escape sequence cannot reach a terminal that shows the recipe.
func cleanDescription(d string) string {
	d = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && !unicode.IsSpace(r) {
			return -1
		}
		return r
	}, d)
	return strings.Join(strings.Fields(d), " ")
}

// recipeMeta is what every recipe of one import shares.
type recipeMeta struct {
	name, version, title, description string
}

// binLocation is where an archive places one executable to put on PATH; path
// is relative to the extraction destination.
type binLocation struct {
	name, path string
}

// recipe returns the package recipe for plat running actions.
func (m recipeMeta) recipe(plat string, actions []schema.PackageAction) *schema.Package {
	return &schema.Package{
		Schema:      "polypkg.package/v1",
		Name:        m.name,
		Version:     m.version,
		Platform:    plat,
		Title:       m.title,
		Description: m.description,
		Actions:     actions,
	}
}

// archiveRecipe unpacks an archive asset into $ACTIVE/<name>/dist — strictly
// below the package's directory, as extract requires, and created by nothing
// before it — then puts each executable on PATH from where extraction placed
// it.
func archiveRecipe(m recipeMeta, plat, asset string, strip int, bins []binLocation) *schema.Package {
	dist := "$ACTIVE/" + m.name + "/dist"
	extract := map[string]any{"src": "$PKG/content/" + asset, "dest": dist}
	if strip > 0 {
		extract["strip_components"] = strip
	}
	actions := make([]schema.PackageAction, 0, 1+len(bins))
	actions = append(actions, schema.PackageAction{Phase: postPlace, Action: "extract", Params: extract})
	for _, b := range bins {
		actions = append(actions, schema.PackageAction{Phase: postPlace, Action: "path",
			Params: map[string]any{"name": b.name, "source": dist + "/" + b.path}})
	}
	return m.recipe(plat, actions)
}

// bareRecipe copies a single-executable asset to $ACTIVE/<name>/bin/<bin>
// (the content file carries the execute bit, which the copy keeps) and puts
// it on PATH.
func bareRecipe(m recipeMeta, plat, asset, bin string) *schema.Package {
	dest := "$ACTIVE/" + m.name + "/bin/" + bin
	return m.recipe(plat, []schema.PackageAction{
		{Phase: postPlace, Action: "install", Params: map[string]any{"src": "$PKG/content/" + asset, "dest": dest, "policy": "copy"}},
		{Phase: postPlace, Action: "path", Params: map[string]any{"name": bin, "source": dest}},
	})
}

// marshalRecipe renders p as polypkg.yaml under a comment naming its origin.
// origin must be a single line.
func marshalRecipe(p *schema.Package, origin string) ([]byte, error) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# Generated by `polypkg pkg import` from %s.\n", origin)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(p); err != nil {
		return nil, fmt.Errorf("encode polypkg.yaml: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("encode polypkg.yaml: %w", err)
	}
	return buf.Bytes(), nil
}

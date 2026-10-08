package ghrelease

import (
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/trevor-vaughan/polypkg/internal/platform"
)

// Skip is a release asset Match chose for no platform, and why.
type Skip struct {
	Name   string
	Reason string
}

// MatchResult is Match's outcome. Every input asset is either a value in
// Chosen (one asset may serve both darwin platforms) or listed once in
// Skipped, which is sorted by Name.
type MatchResult struct {
	Chosen  map[string]Asset // "os/arch" → asset
	Skipped []Skip
}

// AmbiguityError reports a platform that more than one asset still matches
// after every preference rule. Candidates are those survivors, sorted.
type AmbiguityError struct {
	Platform   string
	Candidates []string
}

func (e *AmbiguityError) Error() string {
	return fmt.Sprintf("%d release assets match %s and no preference rule picks one: %s",
		len(e.Candidates), e.Platform, strings.Join(e.Candidates, ", "))
}

// Skip reasons. They appear in the import summary, so they are written for
// the person running the import.
const (
	reasonUnsafeName      = "file name is not a safe single path segment"
	reasonWindows         = "Windows asset"
	reasonOSPackage       = "OS package"
	reasonMetadata        = "signature, checksum or metadata file"
	reasonARM32           = "32-bit ARM (platform variants are not supported)"
	reasonNoPlatform      = "no OS or architecture token"
	reasonNoArch          = "OS token but no architecture token"
	reasonArchVariant     = "unrecognised architecture variant %q"
	reasonNoOS            = "architecture token but no OS token"
	reasonManyOS          = "names more than one OS"
	reasonManyArch        = "names more than one architecture"
	reasonUniversalUnused = "darwin universal build; both darwin architectures have their own asset"
)

var (
	windowsTokens = []string{"windows", "win32", "win64"}
	osPackageExts = []string{".deb", ".rpm", ".apk", ".msi", ".pkg", ".dmg", ".snap", ".appimage"}
	metadataExts  = []string{
		".sha256", ".sha512", ".sha512sum", ".sha1", ".md5", ".sig", ".asc", ".pem", ".crt", ".cert", ".pub", // DevSkim: ignore DS126858 -- file extensions, not hashing
		".minisig", ".sigstore", ".sbom", ".spdx", ".cdx.xml", ".json", ".jsonl", ".intoto.jsonl", ".txt", ".bundle",
	}
	arm32Tokens = []string{"armv6", "armv7", "armhf", "arm"}

	// osAliases and archAliases map spellings release names use onto Go's
	// GOOS/GOARCH. A bare GOOS or GOARCH is recognised without an entry here.
	osAliases   = map[string][]string{"darwin": {"macos", "apple", "osx", "mac"}}
	archAliases = map[string][]string{
		"amd64": {"x86_64", "x86-64", "x64"},
		"arm64": {"aarch64"},
		"386":   {"i386", "i686"},
	}

	// darwinPlatforms are the platforms a darwin universal build serves.
	darwinPlatforms = []string{"darwin/amd64", "darwin/arm64"}

	// kindOrder ranks archive kinds by file-name extension, most preferred
	// first. A name with none of them ranks next as a bare executable (the
	// content decides after download whether it really is one), unless a
	// "." follows its last platform token: that is an extension polypkg
	// does not know (".tar.bz2", a single-file ".gz"), and ranks last.
	kindOrder = [][]string{{".tar.zst", ".tzst"}, {".tar.xz", ".txz"}, {".tar.gz", ".tgz"}, {".zip"}, {".tar"}}

	knownOS, knownArch = portParts()

	// archStems are the spellings a name segment may start with to be
	// reported as an architecture variant ("armel", "riscv64gc",
	// "universal2") rather than as having no architecture at all. "powerpc"
	// is the long form of Go's "ppc".
	archStems = slices.Concat(
		slices.Sorted(maps.Keys(knownArch)),
		slices.Concat(slices.Collect(maps.Values(archAliases))...),
		[]string{"universal", "powerpc"},
	)
)

// portParts splits platform.Ports into the sets of GOOS and GOARCH names, so
// matching recognises every port this polypkg can publish for.
func portParts() (oses, arches map[string]bool) {
	oses, arches = map[string]bool{}, map[string]bool{}
	for _, p := range platform.Ports() {
		o, a, _ := strings.Cut(p, "/")
		oses[o], arches[a] = true, true
	}
	return oses, arches
}

// reAssetName is a safe file name: letters, digits, '.', '_', '+', '-',
// starting with a letter or digit. That rules out "/", "\", "." and "..",
// NUL and other control bytes, whitespace, a leading "-", and "$" (recipe
// params substitute $PKG and $ACTIVE anywhere in a string).
var reAssetName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

// maxAssetNameLen is the common file-name limit (NAME_MAX), the longest
// asset name Release accepts and ValidateAssetName allows, since an importer
// writes each asset to disk under its name.
const maxAssetNameLen = 255

// ValidateAssetName reports whether name is safe to write to disk as
// content/<name>: a single path segment of at most 255 bytes drawn from
// [A-Za-z0-9._+-], starting with a letter or digit. Match never chooses an
// asset whose name fails this check.
func ValidateAssetName(name string) error {
	if len(name) > maxAssetNameLen {
		return fmt.Errorf("asset name is %d bytes, over the %d-byte file-name limit", len(name), maxAssetNameLen)
	}
	if !reAssetName.MatchString(name) {
		return fmt.Errorf("asset name %q is not a single file name of letters, digits, '.', '_', '+' and '-' starting with a letter or digit", name)
	}
	return nil
}

func isSep(r rune) bool { return r == '-' || r == '_' || r == '.' }

// hasToken reports whether tok occurs in name bounded on each side by the
// start or end of name or a separator. tok may itself contain separators
// ("x86_64"); it is matched as a whole string.
func hasToken(name, tok string) bool {
	return tokenEnd(name, tok) >= 0
}

// tokenEnd returns the offset just past the last occurrence of tok in name
// bounded as hasToken requires, or -1 when there is none.
func tokenEnd(name, tok string) int {
	last := -1
	for from := 0; ; {
		i := strings.Index(name[from:], tok)
		if i < 0 {
			return last
		}
		start, end := from+i, from+i+len(tok)
		if (start == 0 || isSep(rune(name[start-1]))) && (end == len(name) || isSep(rune(name[end]))) {
			last = end
		}
		from = start + 1
	}
}

func hasAnyToken(name string, toks []string) bool {
	return slices.ContainsFunc(toks, func(t string) bool { return hasToken(name, t) })
}

func hasAnySuffix(name string, sufs []string) bool {
	return slices.ContainsFunc(sufs, func(s string) bool { return strings.HasSuffix(name, s) })
}

// hardSkipReason returns why lower-cased name n is outside what an import
// can ship at all, or "". An override cannot choose such an asset.
func hardSkipReason(n string) string {
	switch {
	case strings.HasSuffix(n, ".exe") || hasAnyToken(n, windowsTokens):
		return reasonWindows
	case hasAnySuffix(n, osPackageExts):
		return reasonOSPackage
	case hasAnySuffix(n, metadataExts) || reChecksumsName.MatchString(n):
		return reasonMetadata
	case hasAnyToken(n, arm32Tokens):
		return reasonARM32
	}
	return ""
}

// platformTokens returns the distinct GOOS and GOARCH values lower-cased
// name n names, each sorted.
func platformTokens(n string) (oses, arches []string) {
	osSet, archSet := map[string]bool{}, map[string]bool{}
	for canon, toks := range osAliases {
		if hasAnyToken(n, toks) {
			osSet[canon] = true
		}
	}
	for canon, toks := range archAliases {
		if hasAnyToken(n, toks) {
			archSet[canon] = true
		}
	}
	for _, seg := range strings.FieldsFunc(n, isSep) {
		if knownOS[seg] {
			osSet[seg] = true
		}
		if knownArch[seg] {
			archSet[seg] = true
		}
	}
	return slices.Sorted(maps.Keys(osSet)), slices.Sorted(maps.Keys(archSet))
}

// platformTokenEnd returns the offset just past the last OS or architecture
// token in lower-cased name n, or 0 when it has none.
func platformTokenEnd(n string) int {
	end := 0
	for _, aliases := range []map[string][]string{osAliases, archAliases} {
		for _, toks := range aliases {
			for _, t := range toks {
				end = max(end, tokenEnd(n, t))
			}
		}
	}
	start := 0
	for i := 0; i <= len(n); i++ {
		if i == len(n) || isSep(rune(n[i])) {
			if seg := n[start:i]; knownOS[seg] || knownArch[seg] {
				end = max(end, i)
			}
			start = i + 1
		}
	}
	return end
}

// archVariant returns the last separator-bounded segment of lower-cased
// name n that starts with one of archStems, or "". It is called only for a
// name with no architecture token, so the segment is never a recognised
// architecture itself.
func archVariant(n string) string {
	segs := strings.FieldsFunc(n, isSep)
	for i := len(segs) - 1; i >= 0; i-- {
		if slices.ContainsFunc(archStems, func(s string) bool { return strings.HasPrefix(segs[i], s) }) {
			return segs[i]
		}
	}
	return ""
}

// classification is what an asset's name alone says about it. Exactly one
// of platform, universal and skip is set.
type classification struct {
	platform  string // "os/arch"
	universal bool   // a darwin universal build
	skip      string // why the name matches no platform
	hard      bool   // skip is one an override cannot overrule
}

func classify(name string) classification {
	if ValidateAssetName(name) != nil {
		return classification{skip: reasonUnsafeName, hard: true}
	}
	n := strings.ToLower(name)
	if r := hardSkipReason(n); r != "" {
		return classification{skip: r, hard: true}
	}
	oses, arches := platformTokens(n)
	switch {
	case len(oses) > 1:
		return classification{skip: reasonManyOS}
	case len(arches) > 1:
		return classification{skip: reasonManyArch}
	case len(oses) == 0 && len(arches) == 0:
		return classification{skip: reasonNoPlatform}
	case len(oses) == 0:
		return classification{skip: reasonNoOS}
	case len(arches) == 0:
		if oses[0] == "darwin" && hasAnyToken(n, []string{"universal", "all"}) {
			return classification{universal: true}
		}
		if v := archVariant(n); v != "" {
			return classification{skip: fmt.Sprintf(reasonArchVariant, v)}
		}
		return classification{skip: reasonNoArch}
	}
	p := oses[0] + "/" + arches[0]
	if platform.ValidateProducer(p) != nil {
		return classification{skip: p + " is not a Go port"}
	}
	return classification{platform: p}
}

// Match chooses at most one release asset per platform, by file name only.
//
// Each name is lower-cased and searched for OS and architecture tokens at
// separator boundaries ("-", "_", "." or either end). Windows assets, OS
// packages, signature/checksum/metadata files, 32-bit ARM builds and unsafe
// file names are skipped outright. A name with no OS or no architecture
// token, or with two of either, is skipped too, but an override may still
// choose it; when a segment begins like an architecture without being one
// ("armel", "riscv64gc"), the reason names it as an unrecognised variant. A darwin build named "universal" or "all" serves darwin/amd64
// and darwin/arm64, each only when no asset is specific to that
// architecture.
//
// overrides maps "os/arch" to a path.Match glob over asset names; it must
// match exactly one asset that is not skipped outright, and that asset wins
// the platform outright, which may be one the heuristics found nothing for.
// Any other platform with several candidates keeps those whose name
// contains "musl" over those containing "gnu", then those of the
// best-ranked kind (tar.zst, tar.xz, tar.gz, zip, tar, bare executable,
// then any other extension after the platform tokens). A
// platform still holding several is an *AmbiguityError; with several such
// platforms, the error names the first in sorted order.
func Match(assets []Asset, overrides map[string]string) (*MatchResult, error) {
	byPlatform := map[string][]Asset{}
	var universal []Asset
	eligible := make([]Asset, 0, len(assets))
	softSkip := map[string]string{}
	var skipped []Skip
	for _, a := range assets {
		c := classify(a.Name)
		switch {
		case c.hard:
			skipped = append(skipped, Skip{Name: a.Name, Reason: c.skip})
			continue
		case c.skip != "":
			softSkip[a.Name] = c.skip
		case c.universal:
			universal = append(universal, a)
		default:
			byPlatform[c.platform] = append(byPlatform[c.platform], a)
		}
		eligible = append(eligible, a)
	}
	for _, p := range darwinPlatforms {
		if len(byPlatform[p]) == 0 && len(universal) > 0 {
			byPlatform[p] = slices.Clone(universal)
		}
	}

	chosen := map[string]Asset{}
	for _, p := range slices.Sorted(maps.Keys(overrides)) {
		a, err := overrideAsset(p, overrides[p], eligible)
		if err != nil {
			return nil, err
		}
		chosen[p] = a
	}
	for _, p := range slices.Sorted(maps.Keys(byPlatform)) {
		if _, done := chosen[p]; done {
			continue
		}
		left := prefer(byPlatform[p])
		if len(left) > 1 {
			names := make([]string, 0, len(left))
			for _, a := range left {
				names = append(names, a.Name)
			}
			slices.Sort(names)
			return nil, &AmbiguityError{Platform: p, Candidates: names}
		}
		chosen[p] = left[0]
	}

	reported := map[string]bool{}
	for _, a := range chosen {
		reported[a.Name] = true
	}
	for _, a := range eligible {
		if r, ok := softSkip[a.Name]; ok && !reported[a.Name] {
			skipped = append(skipped, Skip{Name: a.Name, Reason: r})
			reported[a.Name] = true
		}
	}
	for _, p := range slices.Sorted(maps.Keys(byPlatform)) {
		for _, a := range byPlatform[p] {
			if !reported[a.Name] {
				skipped = append(skipped, Skip{Name: a.Name, Reason: fmt.Sprintf("%s preferred for %s", chosen[p].Name, p)})
				reported[a.Name] = true
			}
		}
	}
	for _, a := range universal {
		if !reported[a.Name] {
			skipped = append(skipped, Skip{Name: a.Name, Reason: reasonUniversalUnused})
			reported[a.Name] = true
		}
	}
	slices.SortFunc(skipped, func(x, y Skip) int { return strings.Compare(x.Name, y.Name) })
	return &MatchResult{Chosen: chosen, Skipped: skipped}, nil
}

// overrideAsset returns the one eligible asset glob matches for platform p.
func overrideAsset(p, glob string, eligible []Asset) (Asset, error) {
	if err := platform.ValidateProducer(p); err != nil {
		return Asset{}, fmt.Errorf("platform override %s=%s: %w", p, glob, err)
	}
	if _, err := path.Match(glob, ""); err != nil {
		return Asset{}, fmt.Errorf("platform override %s=%s: %w", p, glob, err)
	}
	var hits []string
	var hit Asset
	for _, a := range eligible {
		// path.Match fails only on a malformed pattern, refused above.
		if ok, _ := path.Match(glob, a.Name); ok {
			hits = append(hits, a.Name)
			hit = a
		}
	}
	switch len(hits) {
	case 0:
		return Asset{}, fmt.Errorf("platform override %s=%s matches no release asset that can be imported", p, glob)
	case 1:
		return hit, nil
	}
	slices.Sort(hits)
	return Asset{}, fmt.Errorf("platform override %s=%s matches %d release assets: %s", p, glob, len(hits), strings.Join(hits, ", "))
}

// prefer narrows one platform's candidates by the preference rules, stopping
// as soon as one is left.
func prefer(cands []Asset) []Asset {
	lower := func(a Asset) string { return strings.ToLower(a.Name) }
	if len(cands) > 1 && slices.ContainsFunc(cands, func(a Asset) bool { return strings.Contains(lower(a), "musl") }) {
		cands = slices.DeleteFunc(slices.Clone(cands), func(a Asset) bool {
			n := lower(a)
			return strings.Contains(n, "gnu") && !strings.Contains(n, "musl")
		})
	}
	if len(cands) > 1 {
		best := slices.MinFunc(cands, func(x, y Asset) int { return kindRank(x.Name) - kindRank(y.Name) })
		rank := kindRank(best.Name)
		cands = slices.DeleteFunc(slices.Clone(cands), func(a Asset) bool { return kindRank(a.Name) != rank })
	}
	return cands
}

// kindRank is name's position in kindOrder; for a name with none of its
// extensions, len(kindOrder) when it is bare and len(kindOrder)+1 when a
// "." follows its last platform token. Dots before that token, as in
// "tool-1.2.3-linux-amd64", are a version, not an extension.
func kindRank(name string) int {
	n := strings.ToLower(name)
	for i, exts := range kindOrder {
		if hasAnySuffix(n, exts) {
			return i
		}
	}
	if strings.Contains(n[platformTokenEnd(n):], ".") {
		return len(kindOrder) + 1
	}
	return len(kindOrder)
}

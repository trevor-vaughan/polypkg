package ghrelease_test

import (
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/ghrelease"
)

// chosenNames flattens MatchResult.Chosen to platform → asset name.
func chosenNames(r *ghrelease.MatchResult) map[string]string {
	out := make(map[string]string, len(r.Chosen))
	for p, a := range r.Chosen {
		out[p] = a.Name
	}
	return out
}

// skippedReasons flattens MatchResult.Skipped to asset name → reason,
// failing the test if a name is listed twice.
func skippedReasons(t *testing.T, r *ghrelease.MatchResult) map[string]string {
	t.Helper()
	out := make(map[string]string, len(r.Skipped))
	for _, s := range r.Skipped {
		if _, dup := out[s.Name]; dup {
			t.Fatalf("%s is skipped twice", s.Name)
		}
		out[s.Name] = s.Reason
	}
	return out
}

func mustMatch(t *testing.T, assets []ghrelease.Asset, overrides map[string]string) *ghrelease.MatchResult {
	t.Helper()
	r, err := ghrelease.Match(assets, overrides)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	return r
}

func TestValidateAssetName(t *testing.T) {
	for _, name := range []string{
		"ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz",
		"gh_2.60.1_macOS_arm64.zip",
		"jq-linux-amd64",
		"a",
		"9tool+extra_1.0",
		strings.Repeat("a", 255),
	} {
		if err := ghrelease.ValidateAssetName(name); err != nil {
			t.Errorf("ValidateAssetName(%q): %v", name, err)
		}
	}
	for _, name := range []string{
		"",
		".",
		"..",
		"../tool-linux-amd64",
		"dir/tool-linux-amd64",
		`dir\tool-linux-amd64`,
		"tool-linux-amd64\x00",
		"tool-linux-amd64\n",
		"tool linux amd64",
		"$ACTIVE-linux-amd64",
		"tool-$PKG-linux-amd64",
		".hidden-linux-amd64",
		"-tool-linux-amd64",
		"tööl-linux-amd64",
		strings.Repeat("a", 256),
	} {
		if err := ghrelease.ValidateAssetName(name); err == nil {
			t.Errorf("ValidateAssetName(%q) accepted an unsafe name", name)
		}
	}
}

// TestMatchSingleName pins how one asset name is classified: the platforms
// it serves, or the reason it is skipped.
func TestMatchSingleName(t *testing.T) {
	cases := []struct {
		name      string
		platforms []string
		skip      string
	}{
		{"tool-linux-x86_64.tar.gz", []string{"linux/amd64"}, ""},
		{"tool-linux-x86-64.tar.gz", []string{"linux/amd64"}, ""},
		{"tool_Linux_x64.zip", []string{"linux/amd64"}, ""},
		{"tool-linux-amd64-x86_64", []string{"linux/amd64"}, ""},
		{"tool-aarch64-apple-darwin.tar.gz", []string{"darwin/arm64"}, ""},
		{"tool-osx-amd64", []string{"darwin/amd64"}, ""},
		{"tool-mac-arm64.tgz", []string{"darwin/arm64"}, ""},
		{"tool_macOS_arm64.zip", []string{"darwin/arm64"}, ""},
		{"tool-freebsd-i386.tar.xz", []string{"freebsd/386"}, ""},
		{"tool-linux-i686", []string{"linux/386"}, ""},
		{"tool-linux-arm64", []string{"linux/arm64"}, ""},
		{"tool-linux-riscv64", []string{"linux/riscv64"}, ""},
		{"tool-linux-ppc64le.tar.gz", []string{"linux/ppc64le"}, ""},
		{"tool_netbsd_amd64.tar.gz", []string{"netbsd/amd64"}, ""},
		{"tool-darwin-universal.tar.gz", []string{"darwin/amd64", "darwin/arm64"}, ""},
		{"tool_Darwin_all.tar.gz", []string{"darwin/amd64", "darwin/arm64"}, ""},

		{"tool-linuxish-amd64", nil, "architecture token but no OS token"},
		{"toolx86_64-linux", nil, "OS token but no architecture token"},
		{"tool-linux-amd64x", nil, `unrecognised architecture variant "amd64x"`},
		{"macintosh-amd64", nil, "architecture token but no OS token"},
		{"tool-linux-universal", nil, `unrecognised architecture variant "universal"`},
		{"tool-linux-armel", nil, `unrecognised architecture variant "armel"`},
		{"tool-linux-armv8", nil, `unrecognised architecture variant "armv8"`},
		{"tool-powerpc64-unknown-linux-gnu.tar.gz", nil, `unrecognised architecture variant "powerpc64"`},
		{"tool-riscv64gc-unknown-linux-gnu.tar.gz", nil, `unrecognised architecture variant "riscv64gc"`},
		{"tool-linux-mips64r6el", nil, `unrecognised architecture variant "mips64r6el"`},
		{"tool-darwin-universal2.tar.gz", nil, `unrecognised architecture variant "universal2"`},
		{"armory-1.0-linux-armel", nil, `unrecognised architecture variant "armel"`},
		{"tool-linux-mipsle-softfloat", []string{"linux/mipsle"}, ""},
		{"tool-linux-1.0", nil, "OS token but no architecture token"},
		{"tool-1.0.tar.gz", nil, "no OS or architecture token"},
		{"tool-linux-darwin-amd64", nil, "names more than one OS"},
		{"tool-x86_64-linux-android.tar.gz", nil, "names more than one OS"},
		{"tool-linux-amd64-arm64", nil, "names more than one architecture"},
		{"tool-darwin-s390x", nil, "darwin/s390x is not a Go port"},

		{"tool-windows-amd64.zip", nil, "Windows asset"},
		{"tool-win64.zip", nil, "Windows asset"},
		{"tool-win32.zip", nil, "Windows asset"},
		{"tool-linux-amd64.exe", nil, "Windows asset"},
		{"tool-x86_64-pc-windows-msvc.zip", nil, "Windows asset"},
		{"tool-linux-amd64.deb", nil, "OS package"},
		{"tool-linux-amd64.rpm", nil, "OS package"},
		{"tool-linux-amd64.apk", nil, "OS package"},
		{"tool-linux-amd64.msi", nil, "OS package"},
		{"tool-darwin-universal.pkg", nil, "OS package"},
		{"tool-darwin-arm64.dmg", nil, "OS package"},
		{"tool-linux-amd64.snap", nil, "OS package"},
		{"tool-x86_64.AppImage", nil, "OS package"},
		{"tool-linux-amd64.tar.gz.sha256", nil, "signature, checksum or metadata file"},
		{"tool-linux-amd64.tar.gz.sha512", nil, "signature, checksum or metadata file"},
		{"tool-linux-amd64.tar.gz.sig", nil, "signature, checksum or metadata file"},
		{"tool-linux-amd64.tar.gz.asc", nil, "signature, checksum or metadata file"},
		{"tool-linux-amd64.tar.gz.pem", nil, "signature, checksum or metadata file"},
		{"tool-linux-amd64.crt", nil, "signature, checksum or metadata file"},
		{"tool-linux-amd64.tar.gz.minisig", nil, "signature, checksum or metadata file"},
		{"tool-linux-amd64.sbom", nil, "signature, checksum or metadata file"},
		{"tool-linux-amd64.spdx", nil, "signature, checksum or metadata file"},
		{"tool-linux-amd64.sbom.json", nil, "signature, checksum or metadata file"},
		{"tool-linux-amd64.jsonl", nil, "signature, checksum or metadata file"},
		{"tool-linux-amd64.intoto.jsonl", nil, "signature, checksum or metadata file"},
		{"tool-linux-amd64.txt", nil, "signature, checksum or metadata file"},
		{"tool-linux-amd64.sigstore.bundle", nil, "signature, checksum or metadata file"},
		{"tool-linux-amd64.md5", nil, "signature, checksum or metadata file"},
		{"tool-linux-amd64.sha1", nil, "signature, checksum or metadata file"},
		{"tool-linux-amd64.sha512sum", nil, "signature, checksum or metadata file"},
		{"tool-linux-amd64.pub", nil, "signature, checksum or metadata file"},
		{"tool-linux-amd64.cert", nil, "signature, checksum or metadata file"},
		{"tool-linux-amd64.sigstore", nil, "signature, checksum or metadata file"},
		{"tool-linux-amd64.cdx.xml", nil, "signature, checksum or metadata file"},
		{"SHA256SUMS", nil, "signature, checksum or metadata file"},
		{"tool_linux_amd64_checksums", nil, "signature, checksum or metadata file"},
		{"tool-linux-armv6.tar.gz", nil, "32-bit ARM (platform variants are not supported)"},
		{"tool-armv7-unknown-linux-gnueabihf.tar.gz", nil, "32-bit ARM (platform variants are not supported)"},
		{"tool-linux-armhf", nil, "32-bit ARM (platform variants are not supported)"},
		{"tool_linux_arm.tar.gz", nil, "32-bit ARM (platform variants are not supported)"},
		{"tool-arm-unknown-linux-musleabihf.tar.gz", nil, "32-bit ARM (platform variants are not supported)"},

		{"../tool-linux-amd64", nil, "file name is not a safe single path segment"},
		{"tool-$ACTIVE-linux-amd64", nil, "file name is not a safe single path segment"},
		{"tool linux amd64", nil, "file name is not a safe single path segment"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := mustMatch(t, []ghrelease.Asset{{Name: c.name}}, nil)
			got := slices.Sorted(maps.Keys(r.Chosen))
			if !slices.Equal(got, c.platforms) {
				t.Fatalf("chosen for platforms %v, want %v", got, c.platforms)
			}
			skips := skippedReasons(t, r)
			if c.skip == "" {
				if len(skips) != 0 {
					t.Fatalf("skipped %v, want none", skips)
				}
				return
			}
			if !maps.Equal(skips, map[string]string{c.name: c.skip}) {
				t.Fatalf("skipped %v, want %q", skips, c.skip)
			}
		})
	}
}

func TestMatchEmpty(t *testing.T) {
	r := mustMatch(t, nil, nil)
	if r.Chosen == nil || len(r.Chosen) != 0 || len(r.Skipped) != 0 {
		t.Fatalf("Match(nil) = %+v, want an empty, non-nil Chosen and nothing skipped", r)
	}
}

func TestMatchDarwinUniversal(t *testing.T) {
	t.Run("serves only the architecture that lacks its own asset", func(t *testing.T) {
		r := mustMatch(t, assetsNamed("t-darwin-amd64.tar.gz", "t-darwin-universal.tar.gz"), nil)
		want := map[string]string{"darwin/amd64": "t-darwin-amd64.tar.gz", "darwin/arm64": "t-darwin-universal.tar.gz"}
		if got := chosenNames(r); !maps.Equal(got, want) {
			t.Fatalf("chosen %v, want %v", got, want)
		}
		if len(r.Skipped) != 0 {
			t.Fatalf("skipped %v, want none", r.Skipped)
		}
	})
	t.Run("is skipped when both architectures have their own asset", func(t *testing.T) {
		r := mustMatch(t, assetsNamed("t_Darwin_x86_64.tar.gz", "t_Darwin_arm64.tar.gz", "t_Darwin_all.tar.gz"), nil)
		want := map[string]string{"darwin/amd64": "t_Darwin_x86_64.tar.gz", "darwin/arm64": "t_Darwin_arm64.tar.gz"}
		if got := chosenNames(r); !maps.Equal(got, want) {
			t.Fatalf("chosen %v, want %v", got, want)
		}
		wantSkip := map[string]string{"t_Darwin_all.tar.gz": "darwin universal build; both darwin architectures have their own asset"}
		if got := skippedReasons(t, r); !maps.Equal(got, wantSkip) {
			t.Fatalf("skipped %v, want %v", got, wantSkip)
		}
	})
}

func TestMatchPreference(t *testing.T) {
	cases := []struct {
		name   string
		assets []string
		want   string
	}{
		{"musl over gnu", []string{"t-x86_64-unknown-linux-gnu.tar.gz", "t-x86_64-unknown-linux-musl.tar.gz"}, "t-x86_64-unknown-linux-musl.tar.gz"},
		{"musl over gnu before kind", []string{"t-linux-amd64-gnu.tar.zst", "t-linux-amd64-musl.tar.gz"}, "t-linux-amd64-musl.tar.gz"},
		{"kind breaks a tie between musl builds", []string{"t-linux-amd64-gnu.tar.zst", "t-linux-amd64-musl.zip", "t-linux-amd64-musl.tar.gz"}, "t-linux-amd64-musl.tar.gz"},
		{"tar.zst over tar.xz", []string{"t-linux-amd64.tar.xz", "t-linux-amd64.tar.zst"}, "t-linux-amd64.tar.zst"},
		{"tar.xz over tar.gz", []string{"t-linux-amd64.tar.gz", "t-linux-amd64.tar.xz"}, "t-linux-amd64.tar.xz"},
		{"tar.gz over zip", []string{"t-linux-amd64.zip", "t-linux-amd64.tar.gz"}, "t-linux-amd64.tar.gz"},
		{"zip over tar", []string{"t-linux-amd64.tar", "t-linux-amd64.zip"}, "t-linux-amd64.zip"},
		{"tar over bare", []string{"t-linux-amd64", "t-linux-amd64.tar"}, "t-linux-amd64.tar"},
		{".tzst ranks as tar.zst", []string{"t-linux-amd64.tar.xz", "t-linux-amd64.tzst"}, "t-linux-amd64.tzst"},
		{".txz ranks as tar.xz", []string{"t-linux-amd64.tar.gz", "t-linux-amd64.txz"}, "t-linux-amd64.txz"},
		{".tgz ranks as tar.gz", []string{"t-linux-amd64.zip", "t-linux-amd64.tgz"}, "t-linux-amd64.tgz"},
		{"bare over an unrecognised extension", []string{"t-linux-amd64.tar.bz2", "t-linux-amd64"}, "t-linux-amd64"},
		{"bare over a single-file .gz", []string{"t-linux-amd64.gz", "t-linux-amd64"}, "t-linux-amd64"},
		{"version dots before the platform stay bare", []string{"t-1.2.3-linux-amd64.gz", "t-1.2.3-linux-amd64"}, "t-1.2.3-linux-amd64"},
		{"tar over an unrecognised extension", []string{"t-linux-amd64.tar.bz2", "t-linux-amd64.tar"}, "t-linux-amd64.tar"},
		{"all kinds", []string{"t-linux-amd64", "t-linux-amd64.tar", "t-linux-amd64.zip", "t-linux-amd64.tar.gz", "t-linux-amd64.tar.xz", "t-linux-amd64.tar.zst"}, "t-linux-amd64.tar.zst"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := mustMatch(t, assetsNamed(c.assets...), nil)
			if got := chosenNames(r); !maps.Equal(got, map[string]string{"linux/amd64": c.want}) {
				t.Fatalf("chosen %v, want linux/amd64=%s", got, c.want)
			}
			skips := skippedReasons(t, r)
			for _, n := range c.assets {
				if n == c.want {
					continue
				}
				if want := c.want + " preferred for linux/amd64"; skips[n] != want {
					t.Fatalf("%s skipped as %q, want %q", n, skips[n], want)
				}
			}
		})
	}
}

// TestMatchSidecars pins that a bare binary published beside a sidecar
// file (a hash, a key, a compressed copy) is chosen rather than reported as
// ambiguous.
func TestMatchSidecars(t *testing.T) {
	for _, ext := range []string{".md5", ".sha512sum", ".pub", ".tar.bz2", ".gz"} {
		t.Run(ext, func(t *testing.T) {
			r := mustMatch(t, assetsNamed("foo-linux-amd64", "foo-linux-amd64"+ext), nil)
			if got := chosenNames(r); !maps.Equal(got, map[string]string{"linux/amd64": "foo-linux-amd64"}) {
				t.Fatalf("chosen %v, want linux/amd64=foo-linux-amd64", got)
			}
			if got := skippedReasons(t, r); len(got) != 1 || got["foo-linux-amd64"+ext] == "" {
				t.Fatalf("skipped %v, want only foo-linux-amd64%s", got, ext)
			}
		})
	}
}

func TestMatchAmbiguity(t *testing.T) {
	cases := []struct {
		name       string
		assets     []string
		platform   string
		candidates []string
	}{
		{"same kind", []string{"b-linux-amd64.tar.gz", "a-linux-amd64.tar.gz"}, "linux/amd64", []string{"a-linux-amd64.tar.gz", "b-linux-amd64.tar.gz"}},
		{"musl does not beat a name with neither", []string{"t-linux-amd64.tar.gz", "t-linux-amd64-musl.tar.gz"}, "linux/amd64", []string{"t-linux-amd64-musl.tar.gz", "t-linux-amd64.tar.gz"}},
		{"only survivors are listed", []string{"t-linux-amd64-gnu.tar.gz", "t-linux-amd64-musl.tar.gz", "u-linux-amd64-musl.tar.gz", "u-linux-amd64-musl"}, "linux/amd64", []string{"t-linux-amd64-musl.tar.gz", "u-linux-amd64-musl.tar.gz"}},
		{"first platform in sorted order", []string{"t-linux-amd64.zip", "u-linux-amd64.zip", "t-darwin-arm64.zip", "u-darwin-arm64.zip"}, "darwin/arm64", []string{"t-darwin-arm64.zip", "u-darwin-arm64.zip"}},
		{"two unrecognised extensions", []string{"t-linux-amd64.tar.bz2", "t-linux-amd64.gz"}, "linux/amd64", []string{"t-linux-amd64.gz", "t-linux-amd64.tar.bz2"}},
		{"two universal builds", []string{"t-darwin-universal.tar.gz", "u_darwin_all.tar.gz"}, "darwin/amd64", []string{"t-darwin-universal.tar.gz", "u_darwin_all.tar.gz"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := ghrelease.Match(assetsNamed(c.assets...), nil)
			var ae *ghrelease.AmbiguityError
			if !errors.As(err, &ae) {
				t.Fatalf("Match = (%v, %v), want an *AmbiguityError", r, err)
			}
			if r != nil {
				t.Fatalf("Match returned a result alongside the error: %+v", r)
			}
			if ae.Platform != c.platform || !slices.Equal(ae.Candidates, c.candidates) {
				t.Fatalf("AmbiguityError = %+v, want %s %v", *ae, c.platform, c.candidates)
			}
			for _, s := range append([]string{c.platform}, c.candidates...) {
				if !strings.Contains(err.Error(), s) {
					t.Fatalf("error %q does not mention %s", err, s)
				}
			}
		})
	}
}

func TestMatchOverrides(t *testing.T) {
	t.Run("resolves an ambiguity", func(t *testing.T) {
		r := mustMatch(t, assetsNamed("a-linux-amd64.tar.gz", "b-linux-amd64.tar.gz"), map[string]string{"linux/amd64": "b-*"})
		if got := chosenNames(r); !maps.Equal(got, map[string]string{"linux/amd64": "b-linux-amd64.tar.gz"}) {
			t.Fatalf("chosen %v", got)
		}
		if got := skippedReasons(t, r); got["a-linux-amd64.tar.gz"] != "b-linux-amd64.tar.gz preferred for linux/amd64" {
			t.Fatalf("skipped %v", got)
		}
	})
	t.Run("beats the musl preference", func(t *testing.T) {
		r := mustMatch(t, assetsNamed("t-linux-amd64-gnu.tar.gz", "t-linux-amd64-musl.tar.gz"), map[string]string{"linux/amd64": "*-gnu.tar.gz"})
		if got := chosenNames(r); got["linux/amd64"] != "t-linux-amd64-gnu.tar.gz" {
			t.Fatalf("chosen %v", got)
		}
	})
	t.Run("adds a platform the heuristics skipped", func(t *testing.T) {
		r := mustMatch(t, assetsNamed("jq-linux-amd64", "jq-linux-ppc64el"), map[string]string{"linux/ppc64le": "jq-linux-ppc64el"})
		want := map[string]string{"linux/amd64": "jq-linux-amd64", "linux/ppc64le": "jq-linux-ppc64el"}
		if got := chosenNames(r); !maps.Equal(got, want) {
			t.Fatalf("chosen %v, want %v", got, want)
		}
		if len(r.Skipped) != 0 {
			t.Fatalf("the overridden asset is still reported skipped: %v", r.Skipped)
		}
	})
	t.Run("may serve one asset to several platforms", func(t *testing.T) {
		r := mustMatch(t, assetsNamed("t-linux-amd64"), map[string]string{"linux/386": "t-linux-amd64"})
		want := map[string]string{"linux/amd64": "t-linux-amd64", "linux/386": "t-linux-amd64"}
		if got := chosenNames(r); !maps.Equal(got, want) {
			t.Fatalf("chosen %v, want %v", got, want)
		}
	})

	refusals := []struct {
		name      string
		assets    []string
		overrides map[string]string
		want      string
	}{
		{"glob matches nothing", []string{"t-linux-amd64"}, map[string]string{"linux/amd64": "nope*"}, "matches no release asset"},
		{"glob matches several", []string{"a-linux-amd64", "b-linux-amd64"}, map[string]string{"linux/amd64": "*-linux-amd64"}, "matches 2 release assets: a-linux-amd64, b-linux-amd64"},
		{"malformed glob", []string{"t-linux-amd64"}, map[string]string{"linux/amd64": "t-["}, "syntax error in pattern"},
		{"malformed glob, no assets", nil, map[string]string{"linux/amd64": "["}, "syntax error in pattern"},
		{"not a Go port", []string{"t-linux-amd64"}, map[string]string{"linux/amd46": "t-*"}, "not a Go port"},
		{"upper-case platform", []string{"t-linux-amd64"}, map[string]string{"Linux/amd64": "t-*"}, "lower-case"},
		{"variant platform", []string{"t-linux-armv7"}, map[string]string{"linux/arm/v7": "t-*"}, "variant"},
		{"cannot choose a Windows asset", []string{"t-windows-amd64.zip"}, map[string]string{"linux/amd64": "t-*"}, "matches no release asset"},
		{"cannot choose a checksum file", []string{"t-linux-amd64.tar.gz.sha256"}, map[string]string{"linux/amd64": "t-*"}, "matches no release asset"},
		{"cannot choose an OS package", []string{"t-linux-amd64.deb"}, map[string]string{"linux/amd64": "t-*"}, "matches no release asset"},
		{"cannot choose a 32-bit ARM build", []string{"t-linux-armv7.tar.gz"}, map[string]string{"linux/arm": "t-*"}, "matches no release asset"},
		{"cannot choose an unsafe name", []string{"t-$PKG-linux-amd64"}, map[string]string{"linux/amd64": "t-*"}, "matches no release asset"},
	}
	for _, c := range refusals {
		t.Run(c.name, func(t *testing.T) {
			r, err := ghrelease.Match(assetsNamed(c.assets...), c.overrides)
			if err == nil {
				t.Fatalf("Match = %+v, want an error", r)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not say %q", err, c.want)
			}
			for p, g := range c.overrides {
				if !strings.Contains(err.Error(), p+"="+g) {
					t.Fatalf("error %q does not name the override %s=%s", err, p, g)
				}
			}
		})
	}
}

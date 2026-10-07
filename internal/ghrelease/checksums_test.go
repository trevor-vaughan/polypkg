package ghrelease_test

import (
	"maps"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/ghrelease"
)

const (
	sumA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	sumB = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
)

func assetsNamed(names ...string) []ghrelease.Asset {
	out := make([]ghrelease.Asset, 0, len(names))
	for _, n := range names {
		out = append(out, ghrelease.Asset{Name: n, URL: "https://example.invalid/" + n})
	}
	return out
}

func TestFindChecksums(t *testing.T) {
	const target = "tool-1.0-linux-amd64.tar.gz"
	cases := []struct {
		name   string
		assets []string
		want   string
	}{
		{"per-asset .sha256", []string{target, target + ".sha256"}, target + ".sha256"},
		{"per-asset .sha256 beats a shared file", []string{"checksums.txt", target, target + ".sha256"}, target + ".sha256"},
		{"checksums.txt", []string{target, "checksums.txt"}, "checksums.txt"},
		{"goreleaser prefix", []string{target, "gh_2.60.1_checksums.txt"}, "gh_2.60.1_checksums.txt"},
		{"SHA256SUMS", []string{target, "SHA256SUMS"}, "SHA256SUMS"},
		{"sha256sum.txt (jq)", []string{target, "sha256sum.txt"}, "sha256sum.txt"},
		{"singular checksum", []string{target, "tool-1.0-checksum.txt"}, "tool-1.0-checksum.txt"},
		{"bare checksums (yq)", []string{target, "checksums"}, "checksums"},
		{"several shared files: longest shared prefix", []string{"tool_checksums.txt", target, "SHA256SUMS", "checksums.txt"}, "tool_checksums.txt"},
		{"several shared files, none sharing a prefix: lowest name", []string{target, "checksums.txt", "SHA256SUMS"}, "SHA256SUMS"},
		{"several shared files, equal prefixes: lowest name", []string{target, "tool-b_checksums.txt", "tool-a_checksums.txt"}, "tool-a_checksums.txt"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := ghrelease.FindChecksums(assetsNamed(c.assets...), target)
			if !ok {
				t.Fatalf("FindChecksums found nothing in %v, want %s", c.assets, c.want)
			}
			if got.Name != c.want {
				t.Fatalf("FindChecksums = %s, want %s", got.Name, c.want)
			}
			if got.URL != "https://example.invalid/"+c.want {
				t.Fatalf("FindChecksums returned URL %s, not the matched asset's", got.URL)
			}
		})
	}
}

// TestFindChecksumsTwoComponents pins that a release shipping two tools,
// each with its own checksums file, verifies each tool against its own file.
func TestFindChecksumsTwoComponents(t *testing.T) {
	assets := assetsNamed(
		"alpha-1.0-linux-amd64.tar.gz", "alpha-1.0-checksums.txt",
		"beta-1.0-linux-amd64.tar.gz", "beta-1.0-checksums.txt",
	)
	for asset, want := range map[string]string{
		"alpha-1.0-linux-amd64.tar.gz": "alpha-1.0-checksums.txt",
		"beta-1.0-linux-amd64.tar.gz":  "beta-1.0-checksums.txt",
	} {
		got, ok := ghrelease.FindChecksums(assets, asset)
		if !ok || got.Name != want {
			t.Fatalf("FindChecksums(%s) = (%s, %v), want %s", asset, got.Name, ok, want)
		}
	}
}

func TestFindChecksumsNone(t *testing.T) {
	const target = "tool-1.0-linux-amd64.tar.gz"
	cases := map[string][]string{
		"no assets":                {},
		"only the asset":           {target},
		"a signature of checksums": {target, "checksums.txt.sig", "checksums.txt.pem"},
		"no separator before name": {target, "mychecksums.txt"},
		"another asset's .sha256":  {target, "tool-1.0-darwin-arm64.tar.gz.sha256"},
		"sha512 sums":              {target, "SHA512SUMS"},
		"checksum as a word":       {target, "checksums-bsd", "checksums_hashes_order"},
	}
	for name, assets := range cases {
		t.Run(name, func(t *testing.T) {
			if got, ok := ghrelease.FindChecksums(assetsNamed(assets...), target); ok {
				t.Fatalf("FindChecksums = %s, want none", got.Name)
			}
		})
	}
}

func TestParseChecksums(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want map[string]string
	}{
		{"text mode", sumA + "  a.tar.gz\n", map[string]string{"a.tar.gz": sumA}},
		{"binary mode", sumA + " *a.tar.gz\n", map[string]string{"a.tar.gz": sumA}},
		{"no trailing newline", sumA + "  a.tar.gz", map[string]string{"a.tar.gz": sumA}},
		{"CRLF and blank lines", "\r\n" + sumA + "  a.tar.gz\r\n\r\n" + sumB + "  b.zip\r\n", map[string]string{"a.tar.gz": sumA, "b.zip": sumB}},
		{"upper-case hex is normalised", strings.ToUpper(sumA) + "  a.tar.gz\n", map[string]string{"a.tar.gz": sumA}},
		{"same entry twice", sumA + "  a.tar.gz\n" + sumA + " *a.tar.gz\n", map[string]string{"a.tar.gz": sumA}},
		{"name with spaces kept verbatim", sumA + "  my tool.tar.gz\n", map[string]string{"my tool.tar.gz": sumA}},
		{"sha256sum ./* output", sumA + "  ./a.tar.gz\n" + sumB + " *./b.zip\n", map[string]string{"a.tar.gz": sumA, "b.zip": sumB}},
		{"only one leading ./ is stripped", sumA + "  ././a.tar.gz\n", map[string]string{"./a.tar.gz": sumA}},
		{"other path components kept verbatim", sumA + "  dist/a.tar.gz\n", map[string]string{"dist/a.tar.gz": sumA}},
		{"leading UTF-8 BOM", "\ufeff" + sumA + "  a.tar.gz\n", map[string]string{"a.tar.gz": sumA}},
		{"name and ./name with the same sum", sumA + "  a.tar.gz\n" + sumA + "  ./a.tar.gz\n", map[string]string{"a.tar.gz": sumA}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ghrelease.ParseChecksums([]byte(c.in))
			if err != nil {
				t.Fatalf("ParseChecksums: %v", err)
			}
			if !maps.Equal(got, c.want) {
				t.Fatalf("ParseChecksums = %v, want %v", got, c.want)
			}
		})
	}
}

func TestParseChecksumsRefusesMalformed(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"empty", "", "no entries"},
		{"only blank lines", "\n\r\n\n", "no entries"},
		{"one space separator", sumA + " a.tar.gz\n", "line 1"},
		{"tab separator", sumA + "\ta.tar.gz\n", "line 1"},
		{"BSD format", "SHA256 (a.tar.gz) = " + sumA + "\n", "line 1"},
		{"hash only", sumA + "\n", "line 1"},
		{"no name", sumA + "  \n", "line 1"},
		{"short hash", sumA[:63] + "  a.tar.gz\n", "line 1"},
		{"non-hex hash", "z" + sumA[1:] + "  a.tar.gz\n", "64 hex digits"},
		{"sha512 line", sumA + sumA + "  a.tar.gz\n", "line 1"},
		{"bad line after a good one", sumA + "  a.tar.gz\ngarbage\n", "line 2"},
		{"conflicting duplicate", sumA + "  a.tar.gz\n" + sumB + "  a.tar.gz\n", "different sha256"},
		{"name and ./name with different sums", sumA + "  a.tar.gz\n" + sumB + "  ./a.tar.gz\n", "different sha256"},
		{"BOM after the start", sumA + "  a.tar.gz\n\ufeff" + sumB + "  b.zip\n", "line 2"},
		{"name is only ./", sumA + "  ./\n", "line 1"},
		{"over the size cap", sumA + "  a.tar.gz\n" + strings.Repeat("\n", ghrelease.MaxChecksumsSize), "limit"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ghrelease.ParseChecksums([]byte(c.in))
			if err == nil {
				t.Fatalf("ParseChecksums = %v, want an error", got)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

// FuzzParseChecksums checks that untrusted checksums content never panics
// and that every accepted entry is a non-empty name with a lower-case
// 64-hex-digit sum.
func FuzzParseChecksums(f *testing.F) {
	f.Add([]byte(sumA + "  a.tar.gz\n"))
	f.Add([]byte(sumA + " *a.tar.gz\r\n" + sumB + "  b.zip"))
	f.Add([]byte("SHA256 (a) = " + sumA))
	f.Fuzz(func(t *testing.T, b []byte) {
		sums, err := ghrelease.ParseChecksums(b)
		if err != nil {
			return
		}
		if len(sums) == 0 {
			t.Fatal("ParseChecksums accepted a file with no entries")
		}
		for name, sum := range sums {
			if name == "" {
				t.Fatal("ParseChecksums accepted an empty name")
			}
			if len(sum) != 64 || strings.Trim(sum, "0123456789abcdef") != "" {
				t.Fatalf("ParseChecksums returned sum %q for %q", sum, name)
			}
		}
	})
}

func TestChecksumsFor(t *testing.T) {
	const target = "tool-1.0-linux-amd64.tar.gz"
	perAsset := ghrelease.Asset{Name: target + ".sha256"}
	shared := ghrelease.Asset{Name: "checksums.txt"}
	cases := []struct {
		name string
		file ghrelease.Asset
		in   string
		want map[string]string
	}{
		{"per-asset bare hash", perAsset, sumA, map[string]string{target: sumA}},
		{"per-asset bare hash, trailing newline", perAsset, sumA + "\n", map[string]string{target: sumA}},
		{"per-asset bare hash, trailing whitespace and CRLF", perAsset, sumA + " \t\r\n", map[string]string{target: sumA}},
		{"per-asset bare hash in upper case", perAsset, strings.ToUpper(sumA) + "\n", map[string]string{target: sumA}},
		{"per-asset sha256sum line", perAsset, sumA + "  " + target + "\n", map[string]string{target: sumA}},
		{"per-asset bare hash, leading whitespace", perAsset, " \t" + sumA + "\n", map[string]string{target: sumA}},
		{"per-asset bare hash after a UTF-8 BOM", perAsset, "\ufeff" + sumA + "\n", map[string]string{target: sumA}},
		{"release-wide file", shared, sumA + "  " + target + "\n" + sumB + "  b.zip\n", map[string]string{target: sumA, "b.zip": sumB}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ghrelease.ChecksumsFor(c.file, target, []byte(c.in))
			if err != nil {
				t.Fatalf("ChecksumsFor: %v", err)
			}
			if !maps.Equal(got, c.want) {
				t.Fatalf("ChecksumsFor = %v, want %v", got, c.want)
			}
		})
	}
}

func TestChecksumsForRefuses(t *testing.T) {
	const target = "tool-1.0-linux-amd64.tar.gz"
	perAsset := ghrelease.Asset{Name: target + ".sha256"}
	cases := []struct {
		name string
		file ghrelease.Asset
		in   string
	}{
		{"bare hash in a release-wide file", ghrelease.Asset{Name: "checksums.txt"}, sumA + "\n"},
		{"bare hash in another asset's .sha256", ghrelease.Asset{Name: "other.tar.gz.sha256"}, sumA + "\n"},
		{"bare hash with trailing garbage", perAsset, sumA + " garbage\n"},
		{"bare hash glued to garbage", perAsset, sumA + "garbage\n"},
		{"bare hash then a garbage line", perAsset, sumA + "\ngarbage\n"},
		{"short bare hash", perAsset, sumA[:63] + "\n"},
		{"non-hex bare hash", perAsset, "z" + sumA[1:] + "\n"},
		{"empty per-asset file", perAsset, ""},
		{"oversized per-asset file", perAsset, sumA + strings.Repeat("\n", ghrelease.MaxChecksumsSize)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, err := ghrelease.ChecksumsFor(c.file, target, []byte(c.in)); err == nil {
				t.Fatalf("ChecksumsFor = %v, want an error", got)
			}
		})
	}
}

// TestChecksumsForMissingEntry pins that a checksums file that does not list
// the asset is refused here, naming both, rather than handed on as a map the
// caller must remember to check.
func TestChecksumsForMissingEntry(t *testing.T) {
	const target = "tool-1.0-linux-amd64.tar.gz"
	cases := []struct {
		name string
		file ghrelease.Asset
		in   string
	}{
		{"per-asset line naming another file", ghrelease.Asset{Name: target + ".sha256"}, sumA + "  other.tar.gz\n"},
		{"release-wide file without the asset", ghrelease.Asset{Name: "checksums.txt"}, sumA + "  other.tar.gz\n" + sumB + "  b.zip\n"},
		{"a dir/ entry does not stand in for the asset", ghrelease.Asset{Name: "checksums.txt"}, sumA + "  dist/" + target + "\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ghrelease.ChecksumsFor(c.file, target, []byte(c.in))
			if err == nil {
				t.Fatalf("ChecksumsFor = %v, want an error", got)
			}
			for _, s := range []string{c.file.Name, target} {
				if !strings.Contains(err.Error(), s) {
					t.Fatalf("error %q does not name %q", err, s)
				}
			}
		})
	}
}

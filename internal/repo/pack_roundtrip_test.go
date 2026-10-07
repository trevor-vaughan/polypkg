package repo

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/source"
)

// sandboxXDG points HOME and every XDG base directory at fresh temporary
// directories, so a test cannot read or write the developer's own.
func sandboxXDG(t *testing.T) {
	t.Helper()
	for _, v := range []string{"HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_BIN_HOME", "XDG_RUNTIME_DIR"} {
		t.Setenv(v, t.TempDir())
	}
}

// TestPackedArtifactsExtractUnderThePackagePolicy proves that extraction
// accepts every shape of artifact PackArtifact builds. Each source is packed,
// extracted the way install extracts it (source.ExtractTarZst, which applies
// archive.PolicyPackage), and the tree is checked with
// source.VerifyExtractedTarZst and against the source files.
func TestPackedArtifactsExtractUnderThePackagePolicy(t *testing.T) {
	sandboxXDG(t)
	// 64 segments ("content/", 62 dirs, "f"), spelled out rather than derived
	// from archive.MaxMemberDepth: a published package may be this deep, so
	// lowering the bound must fail here.
	deepest := strings.Repeat("d/", 62) + "f"
	many := map[string]fs.FileMode{}
	for i := range 40 {
		for j := range 5 {
			many[fmt.Sprintf("dir%02d/sub/file%d", i, j)] = 0o644
		}
	}
	cases := map[string]map[string]fs.FileMode{
		"manifest only": {},
		"executables and nested data": {
			"bin/tool":              0o755,
			"libexec/tool/helper":   0o750,
			"share/doc/tool/README": 0o644,
			"etc/tool/private.conf": 0o600,
		},
		"names extraction must take as they are": {
			"My Documents/a file.txt": 0o644,
			".hidden/.rc":             0o644,
			"ünïcödé/naïve":           0o644,
			"tool/a:b":                0o644,
			"weird/name-with-~#%@":    0o644,
		},
		"the deepest member extraction accepts":   {deepest: 0o644},
		"two hundred files in eighty directories": many,
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			src := t.TempDir()
			manifest := "schema: polypkg.package/v1\nname: shapes\nversion: 1.0.0\nactions: []\n"
			if err := os.WriteFile(filepath.Join(src, "polypkg.yaml"), []byte(manifest), 0o644); err != nil {
				t.Fatal(err)
			}
			for rel, mode := range files {
				p := filepath.Join(src, "content", filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte("body of "+rel), mode); err != nil {
					t.Fatal(err)
				}
				// WriteFile's mode is filtered by the umask; set it exactly.
				if err := os.Chmod(p, mode); err != nil {
					t.Fatal(err)
				}
			}
			artifact, _, err := PackArtifact(src)
			if err != nil {
				t.Fatalf("PackArtifact: %v", err)
			}
			dest := filepath.Join(t.TempDir(), "extract")
			if err := source.ExtractTarZst(bytes.NewReader(artifact), dest); err != nil {
				t.Fatalf("extracting a packed artifact failed: %v", err)
			}
			if err := source.VerifyExtractedTarZst(bytes.NewReader(artifact), dest); err != nil {
				t.Fatalf("the extracted tree does not verify: %v", err)
			}
			for rel, mode := range files {
				p := filepath.Join(dest, "content", filepath.FromSlash(rel))
				got, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != "body of "+rel {
					t.Errorf("%s holds %q", rel, got)
				}
				info, err := os.Stat(p)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm()&0o111 != mode&0o111 {
					t.Errorf("%s has mode %v; the source's execute bits were %v", rel, info.Mode().Perm(), mode&0o111)
				}
			}
		})
	}
}

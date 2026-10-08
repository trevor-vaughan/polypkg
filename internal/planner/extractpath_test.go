package planner_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/extractstore"
	"github.com/trevor-vaughan/polypkg/internal/platform"
	"github.com/trevor-vaughan/polypkg/internal/resolver"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// extractPathIndex is a one-entry, platform-agnostic index whose package key
// and version are the values under test.
func extractPathIndex(name, version string) *schema.Index {
	return &schema.Index{
		Schema:  "polypkg.index/v3",
		Expires: "2099-01-01T00:00:00Z",
		Packages: map[string][]schema.IndexEntry{
			name: {{Version: version, ContentHash: "blake3:" + strings.Repeat("ab", 32), Artifact: "pool/x.tar.zst"}},
		},
	}
}

// TestExtractDirCannotEscapeStore pins the composition Plan relies on: the
// extract dir is built from Resolved.Name (an index key) and Resolved.Version,
// so every name/version BuildCatalog admits must yield a dir that is a direct
// child of the extract store root, and every value that could leave it must be
// refused by BuildCatalog before a path is ever built.
func TestExtractDirCannotEscapeStore(t *testing.T) {
	state := t.TempDir()
	root := extractstore.Root(state)
	hash := "blake3:" + strings.Repeat("ab", 32)

	t.Run("hostile names and versions are refused by the catalog", func(t *testing.T) {
		for _, tc := range []struct{ name, version string }{
			{"../../etc/x", "1.0.0"},
			{"a/b", "1.0.0"},
			{"..", "1.0.0"},
			{".", "1.0.0"},
			{"/etc", "1.0.0"},
			{`a\b`, "1.0.0"},
			{"", "1.0.0"},
			{"hello", "1.0.0/../../x"},
			{"hello", "../1.0.0"},
		} {
			if _, err := resolver.BuildCatalog(extractPathIndex(tc.name, tc.version), "native", platform.Host()); err == nil {
				t.Errorf("BuildCatalog accepted name %q version %q; it must refuse it before an extract path is built", tc.name, tc.version)
			}
		}
	})

	t.Run("admitted names and versions stay one level under the store", func(t *testing.T) {
		for _, tc := range []struct{ name, version string }{
			{"hello", "1.0.0"},
			{"Hello_World-2", "1.0.0-rc.1+build.5"},
		} {
			cat, err := resolver.BuildCatalog(extractPathIndex(tc.name, tc.version), "native", platform.Host())
			if err != nil {
				t.Fatalf("BuildCatalog(%q, %q): %v", tc.name, tc.version, err)
			}
			c, err := cat.Newest(tc.name, "")
			if err != nil {
				t.Fatalf("Newest(%q): %v", tc.name, err)
			}
			dir := extractstore.Dir(state, c.Name, c.Version, hash)
			if filepath.Dir(dir) != root {
				t.Errorf("extract dir %q for %q %q is not a direct child of %q", dir, tc.name, tc.version, root)
			}
			if base := filepath.Base(dir); base != extractstore.DirName(c.Name, c.Version, hash) {
				t.Errorf("extract dir basename %q, want %q", base, extractstore.DirName(c.Name, c.Version, hash))
			}
		}
	})
}

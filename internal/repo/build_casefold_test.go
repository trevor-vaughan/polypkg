package repo

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeNamedPkgSrc writes a package source for name at version under dir,
// declaring plat when it is not "".
func writeNamedPkgSrc(t *testing.T, dir, name, version, plat string) {
	t.Helper()
	manifest := "schema: polypkg.package/v1\nname: " + name + "\nversion: " + version + "\n"
	if plat != "" {
		manifest += "platform: " + plat + "\n"
	}
	manifest += "actions: []\n"
	if err := os.MkdirAll(filepath.Join(dir, "content"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "content", "id"), []byte(name+" "+version+" "+plat), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestBuildRefusesCaseFoldCollisions pins that repo build refuses to publish
// an index in which two names, or two versions of one name, differ only in
// letter case, and publishes nothing when it does.
func TestBuildRefusesCaseFoldCollisions(t *testing.T) {
	for _, tc := range []struct {
		name     string
		packages string // the packages: block of polypkg-repo.yaml
		srcs     [][4]string
		want     string
		wantMsg  []string // what the user-facing Msg must name
		wantHint string
	}{
		{
			name:     "two names",
			packages: "  hello:\n    - source: ./pkgs/a\n  Hello:\n    - source: ./pkgs/b\n",
			srcs:     [][4]string{{"a", "hello", "1.0.0", ""}, {"b", "Hello", "1.0.0", ""}},
			want:     `package names "Hello" and "hello" differ only in letter case`,
			wantMsg:  []string{`"Hello" (packages.Hello: source "./pkgs/b")`, `"hello" (packages.hello: source "./pkgs/a")`},
			wantHint: "rename one package in its polypkg.yaml and under packages: in polypkg-repo.yaml, or remove one of the entries from polypkg-repo.yaml",
		},
		{
			name:     "two versions of one name",
			packages: "  hello:\n    - source: ./pkgs/a\n    - source: ./pkgs/b\n",
			srcs:     [][4]string{{"a", "hello", "1.0.0-rc1", "linux/amd64"}, {"b", "hello", "1.0.0-RC1", "darwin/arm64"}},
			want:     `package "hello" versions "1.0.0-rc1" and "1.0.0-RC1" differ only in letter case`,
			wantMsg:  []string{`package "hello" versions "1.0.0-rc1" (source "./pkgs/a") and "1.0.0-RC1" (source "./pkgs/b")`},
			wantHint: "change the version in one package's polypkg.yaml, or remove one of the entries from polypkg-repo.yaml",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sandboxXDG(t)
			root := t.TempDir()
			keyDir := t.TempDir()
			keyPath := writeDupVersionKey(t, keyDir)
			for _, s := range tc.srcs {
				writeNamedPkgSrc(t, filepath.Join(root, "pkgs", s[0]), s[1], s[2], s[3])
			}
			manifest := "schema: polypkg.repo/v1\nsource: repo\noutput: ./public\n" +
				"key:\n  path: " + keyPath + "\n  kdf: scrypt\npackages:\n" + tc.packages
			mPath := filepath.Join(root, "polypkg-repo.yaml")
			if err := os.WriteFile(mPath, []byte(manifest), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := buildHello(t, mPath, keyDir)
			var pe *PublishError
			if !errors.As(err, &pe) || !strings.Contains(err.Error(), tc.want) || pe.Hint == "" {
				t.Fatalf("Build = %v, want a *PublishError with a hint containing %q", err, tc.want)
			}
			for _, want := range tc.wantMsg {
				if !strings.Contains(pe.Msg, want) {
					t.Errorf("Msg = %q, want it to name %q", pe.Msg, want)
				}
			}
			if pe.Hint != tc.wantHint {
				t.Errorf("Hint = %q, want %q", pe.Hint, tc.wantHint)
			}
			if _, statErr := os.Stat(filepath.Join(root, "public", "index.json")); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("an index was published despite the refusal (stat: %v)", statErr)
			}
		})
	}
}

package repo

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func TestAddAndRemovePackage(t *testing.T) {
	dir := t.TempDir()
	mPath := filepath.Join(dir, "polypkg-repo.yaml")
	base := "schema: polypkg.repo/v1\nsource: example\noutput: ./public\nkey:\n  path: k.key\n  kdf: scrypt\npackages: {}\n"
	if err := os.WriteFile(mPath, []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}
	add, err := PlanAddPackage(mPath, PackageAdd{Name: "hello", Source: "./pkgs/hello"})
	if err != nil {
		t.Fatalf("PlanAddPackage: %v", err)
	}
	if err := add.Commit(); err != nil {
		t.Fatalf("commit add: %v", err)
	}
	m := mustParseManifest(t, mPath)
	if len(m.Packages["hello"]) != 1 || m.Packages["hello"][0].Source != "./pkgs/hello" {
		t.Fatalf("hello not added: %+v", m.Packages)
	}
	rm, err := PlanRemovePackage(mPath, "hello")
	if err != nil {
		t.Fatalf("PlanRemovePackage: %v", err)
	}
	if err := rm.Commit(); err != nil {
		t.Fatalf("commit remove: %v", err)
	}
	m = mustParseManifest(t, mPath)
	if _, ok := m.Packages["hello"]; ok {
		t.Fatal("hello not removed")
	}
}

func TestRemoveUnknownPackageErrors(t *testing.T) {
	dir := t.TempDir()
	mPath := filepath.Join(dir, "polypkg-repo.yaml")
	_ = os.WriteFile(mPath, []byte("schema: polypkg.repo/v1\nsource: e\noutput: ./public\nkey:\n  path: k\n  kdf: scrypt\npackages: {}\n"), 0o644)
	if _, err := PlanRemovePackage(mPath, "ghost"); err == nil {
		t.Fatal("expected error removing unknown package")
	}
}

// TestPlanEditLeavesManifestUntouchedUntilCommit is the unit-level statement of
// the add/remove invariant: planning an edit must not write anything, so a
// caller that fails between planning and committing leaves the file alone.
func TestPlanEditLeavesManifestUntouchedUntilCommit(t *testing.T) {
	dir := t.TempDir()
	mPath := filepath.Join(dir, "polypkg-repo.yaml")
	base := "schema: polypkg.repo/v1\nsource: example\noutput: ./public\nkey:\n  path: k.key\n  kdf: scrypt\npackages:\n  hello:\n    - source: ./pkgs/hello\n"
	if err := os.WriteFile(mPath, []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}

	add, err := PlanAddPackage(mPath, PackageAdd{Name: "goodbye", Source: "./pkgs/goodbye"})
	if err != nil {
		t.Fatal(err)
	}
	rm, err := PlanRemovePackage(mPath, "hello")
	if err != nil {
		t.Fatal(err)
	}
	// The planned manifests carry the edits...
	if _, ok := add.Manifest.Packages["goodbye"]; !ok {
		t.Fatal("planned add does not carry goodbye")
	}
	if _, ok := rm.Manifest.Packages["hello"]; ok {
		t.Fatal("planned remove still carries hello")
	}
	// ...while the file on disk carries neither.
	raw, err := os.ReadFile(mPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != base {
		t.Fatalf("planning rewrote the manifest\nbefore:\n%s\nafter:\n%s", base, raw)
	}

	if err := add.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, ok := mustParseManifest(t, mPath).Packages["goodbye"]; !ok {
		t.Fatal("commit did not persist the add")
	}
}

func TestCommitAddPersistsValidManifest(t *testing.T) {
	dir := t.TempDir()
	mPath := filepath.Join(dir, "polypkg-repo.yaml")
	_ = os.WriteFile(mPath, []byte("schema: polypkg.repo/v1\nsource: e\noutput: ./public\nkey:\n  path: k\n  kdf: scrypt\npackages: {}\n"), 0o644)
	add, err := PlanAddPackage(mPath, PackageAdd{Name: "a", Source: "./a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := add.Commit(); err != nil {
		t.Fatal(err)
	}
	// Re-parsing must still pass schema validation (round-trip stays valid).
	mustParseManifest(t, mPath)
}

// TestPlanAddPackageKeepsOtherVersions pins the whole point of the change: a
// repository serves several versions of one package, so adding a second source
// under the same name must not evict the first.
func TestPlanAddPackageKeepsOtherVersions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "polypkg-repo.yaml")
	writeTestManifest(t, path)

	edit, err := PlanAddPackage(path, PackageAdd{Name: "hello", Source: "./pkgs/hello-1.0.0"})
	if err != nil {
		t.Fatalf("PlanAddPackage 1.0.0: %v", err)
	}
	if err := edit.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	edit, err = PlanAddPackage(path, PackageAdd{Name: "hello", Source: "./pkgs/hello-1.1.0"})
	if err != nil {
		t.Fatalf("PlanAddPackage 1.1.0: %v", err)
	}
	if err := edit.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	got := edit.Manifest.Packages["hello"]
	if len(got) != 2 {
		t.Fatalf("packages[hello] = %d entries, want 2 (%+v)", len(got), got)
	}
	if got[0].Source != "./pkgs/hello-1.0.0" || got[1].Source != "./pkgs/hello-1.1.0" {
		t.Fatalf("entries not in add order: %+v", got)
	}
}

// TestPlanAddPackageReplacesSameSource keeps re-adding idempotent: the same
// source path is an update in place, not a duplicate entry.
func TestPlanAddPackageReplacesSameSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "polypkg-repo.yaml")
	writeTestManifest(t, path)

	for range 2 {
		edit, err := PlanAddPackage(path, PackageAdd{Name: "hello", Source: "./pkgs/hello"})
		if err != nil {
			t.Fatalf("PlanAddPackage: %v", err)
		}
		if err := edit.Commit(); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}

	m, err := loadManifestForEdit(path)
	if err != nil {
		t.Fatalf("loadManifestForEdit: %v", err)
	}
	if got := len(m.Packages["hello"]); got != 1 {
		t.Fatalf("re-adding the same source produced %d entries, want 1", got)
	}
}

// writeTestManifest writes a minimal valid manifest with no packages.
func writeTestManifest(t *testing.T, path string) {
	t.Helper()
	body := "schema: polypkg.repo/v1\nsource: demo\noutput: ./public\n" +
		"key:\n  path: /tmp/demo.key\n  kdf: scrypt\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

func mustParseManifest(t *testing.T, path string) *schema.RepoManifest {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m, err := schema.ParseRepoManifest(f)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestPlanRemovePackageSourceDropsOneEntry covers withdrawing a single version
// while the package's other versions stay published.
func TestPlanRemovePackageSourceDropsOneEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "polypkg-repo.yaml")
	writeTestManifest(t, path)

	for _, src := range []string{"./pkgs/hello-1.0.0", "./pkgs/hello-1.1.0"} {
		edit, err := PlanAddPackage(path, PackageAdd{Name: "hello", Source: src})
		if err != nil {
			t.Fatalf("PlanAddPackage %s: %v", src, err)
		}
		if err := edit.Commit(); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}

	edit, err := PlanRemovePackageSource(path, "hello", "./pkgs/hello-1.0.0")
	if err != nil {
		t.Fatalf("PlanRemovePackageSource: %v", err)
	}
	got := edit.Manifest.Packages["hello"]
	if len(got) != 1 || got[0].Source != "./pkgs/hello-1.1.0" {
		t.Fatalf("packages[hello] = %+v, want only ./pkgs/hello-1.1.0", got)
	}
}

// TestPlanRemovePackageSourceDropsEmptyKey keeps the manifest schema-valid:
// packages entries have minItems 1, so removing the last version must delete
// the name rather than leave `hello: []`.
func TestPlanRemovePackageSourceDropsEmptyKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "polypkg-repo.yaml")
	writeTestManifest(t, path)

	edit, err := PlanAddPackage(path, PackageAdd{Name: "hello", Source: "./pkgs/hello"})
	if err != nil {
		t.Fatalf("PlanAddPackage: %v", err)
	}
	if err := edit.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	edit, err = PlanRemovePackageSource(path, "hello", "./pkgs/hello")
	if err != nil {
		t.Fatalf("PlanRemovePackageSource: %v", err)
	}
	if _, present := edit.Manifest.Packages["hello"]; present {
		t.Fatal("removing the last version left the name behind with an empty list")
	}
}

// TestPlanRemovePackageSourceMatchesPrebuiltArtifact covers the other entry
// kind: a prebuilt entry has no Source, so removal must match on its artifact
// path instead. PlanAddPackage only ever writes Source entries, so this
// manifest is hand-authored the way an operator publishing a prebuilt would
// write it.
func TestPlanRemovePackageSourceMatchesPrebuiltArtifact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "polypkg-repo.yaml")
	body := "schema: polypkg.repo/v1\nsource: demo\noutput: ./public\n" +
		"key:\n  path: /tmp/demo.key\n  kdf: scrypt\n" +
		"packages:\n  hello:\n" +
		"    - prebuilt:\n        artifact: ./staging/hello-1.0.0.tar.zst\n        attestations: ./staging/hello-1.0.0-atts\n" +
		"    - prebuilt:\n        artifact: ./staging/hello-1.1.0.tar.zst\n        attestations: ./staging/hello-1.1.0-atts\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	edit, err := PlanRemovePackageSource(path, "hello", "./staging/hello-1.0.0.tar.zst")
	if err != nil {
		t.Fatalf("PlanRemovePackageSource: %v", err)
	}
	got := edit.Manifest.Packages["hello"]
	if len(got) != 1 || got[0].Prebuilt == nil || got[0].Prebuilt.Artifact != "./staging/hello-1.1.0.tar.zst" {
		t.Fatalf("packages[hello] = %+v, want only the 1.1.0 prebuilt entry", got)
	}
}

// TestPlanRemovePackageSourceNoMatchErrors covers the resolution failure: no
// entry in the package has the given source/artifact identifier.
func TestPlanRemovePackageSourceNoMatchErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "polypkg-repo.yaml")
	writeTestManifest(t, path)

	edit, err := PlanAddPackage(path, PackageAdd{Name: "hello", Source: "./pkgs/hello"})
	if err != nil {
		t.Fatalf("PlanAddPackage: %v", err)
	}
	if err := edit.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	if _, err := PlanRemovePackageSource(path, "hello", "./pkgs/does-not-exist"); err == nil {
		t.Fatal("expected an error for a source with no matching entry")
	}
}

// writeThreeEntryManifest writes a hand-authored manifest whose package hello
// has three source entries, ./pkgs/a, ./pkgs/b and ./pkgs/c, in that order.
func writeThreeEntryManifest(t *testing.T, path string) {
	t.Helper()
	body := "schema: polypkg.repo/v1\nsource: demo\noutput: ./public\n" +
		"key:\n  path: /tmp/demo.key\n  kdf: scrypt\n" +
		"packages:\n  hello:\n" +
		"    - source: ./pkgs/a\n    - source: ./pkgs/b\n    - source: ./pkgs/c\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

// TestPlanRemovePackageSourceDropsEveryNamedEntry covers withdrawing a version
// published as several entries (one per platform): every named entry goes,
// the rest stay in order.
func TestPlanRemovePackageSourceDropsEveryNamedEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "polypkg-repo.yaml")
	writeThreeEntryManifest(t, path)

	edit, err := PlanRemovePackageSource(path, "hello", "./pkgs/a", "./pkgs/c")
	if err != nil {
		t.Fatalf("PlanRemovePackageSource: %v", err)
	}
	got := edit.Manifest.Packages["hello"]
	if len(got) != 1 || got[0].Source != "./pkgs/b" {
		t.Fatalf("packages[hello] = %+v, want only ./pkgs/b", got)
	}
}

// TestPlanRemovePackageSourceRefusesWhenAnyIdentifierIsMissing pins that a
// partial match plans nothing: removing some but not all of a version's
// entries would leave the version half-withdrawn.
func TestPlanRemovePackageSourceRefusesWhenAnyIdentifierIsMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "polypkg-repo.yaml")
	writeThreeEntryManifest(t, path)

	_, err := PlanRemovePackageSource(path, "hello", "./pkgs/a", "./pkgs/nope")
	if err == nil {
		t.Fatal("PlanRemovePackageSource accepted an identifier with no entry")
	}
	if !strings.Contains(err.Error(), "./pkgs/nope") {
		t.Fatalf("error %q does not name the unmatched identifier", err)
	}
}

// TestPlanEditKeepsSigstoreRoots pins that the machine-managed rewrite `repo
// add` and `repo remove` perform carries the operator's sigstore_roots through
// unchanged: dropping them would silently stop publishing the sigstore trust
// roots on the next build.
func TestPlanEditKeepsSigstoreRoots(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "polypkg-repo.yaml")
	body := "schema: polypkg.repo/v1\nsource: demo\noutput: ./public\n" +
		"key:\n  path: /tmp/demo.key\n  kdf: scrypt\n" +
		"sigstore_roots:\n  - ./imports/sigstore-trusted-root.json\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	want := []string{"./imports/sigstore-trusted-root.json"}

	add, err := PlanAddPackage(path, PackageAdd{Name: "hello", Source: "./pkgs/hello"})
	if err != nil {
		t.Fatalf("PlanAddPackage: %v", err)
	}
	if !slices.Equal(add.Manifest.SigstoreRoots, want) {
		t.Fatalf("planned add SigstoreRoots = %q, want %q", add.Manifest.SigstoreRoots, want)
	}
	if err := add.Commit(); err != nil {
		t.Fatalf("commit add: %v", err)
	}
	if got := mustParseManifest(t, path).SigstoreRoots; !slices.Equal(got, want) {
		t.Fatalf("committed add SigstoreRoots = %q, want %q", got, want)
	}

	rm, err := PlanRemovePackage(path, "hello")
	if err != nil {
		t.Fatalf("PlanRemovePackage: %v", err)
	}
	if !slices.Equal(rm.Manifest.SigstoreRoots, want) {
		t.Fatalf("planned remove SigstoreRoots = %q, want %q", rm.Manifest.SigstoreRoots, want)
	}
}

// TestPlanAddPackageRegistersSeveralSourcesInOneEdit covers the batch `repo
// add` relies on: several builds of one package and another package land in a
// single planned edit, in argument order, and nothing reaches disk until
// Commit.
func TestPlanAddPackageRegistersSeveralSourcesInOneEdit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "polypkg-repo.yaml")
	writeTestManifest(t, path)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	edit, err := PlanAddPackage(path,
		PackageAdd{Name: "hello", Source: "./pkgs/hello-linux-amd64"},
		PackageAdd{Name: "world", Source: "./pkgs/world"},
		PackageAdd{Name: "hello", Source: "./pkgs/hello-darwin-arm64"},
	)
	if err != nil {
		t.Fatalf("PlanAddPackage: %v", err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatalf("planning wrote the manifest:\n%s", after)
	}
	hello := edit.Manifest.Packages["hello"]
	if len(hello) != 2 || hello[0].Source != "./pkgs/hello-linux-amd64" || hello[1].Source != "./pkgs/hello-darwin-arm64" {
		t.Fatalf("packages[hello] = %+v, want both platform sources in argument order", hello)
	}
	if w := edit.Manifest.Packages["world"]; len(w) != 1 || w[0].Source != "./pkgs/world" {
		t.Fatalf("packages[world] = %+v", w)
	}
}

package planner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/planner"
	"github.com/trevor-vaughan/polypkg/internal/repo"
	"github.com/trevor-vaughan/polypkg/internal/resolver"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// buildRecommendingRepo builds a signed local repo with two packages:
//   - "app" 1.0.0 — a hard-installed package that recommends "extras"
//   - "extras" 1.0.0 — the weak dependency recommended by "app"
//
// It returns the output directory (used as the source URL) and the path to
// trust_root.pub.
func buildRecommendingRepo(t *testing.T, sourceName string) (outputDir, trustRoot string) {
	t.Helper()
	root := t.TempDir()
	keyDir := t.TempDir() // outside the output dir (guardKeyNotInOutput)

	// "app" package recommends "extras".
	appDir := filepath.Join(root, "pkgs", "app")
	if err := os.MkdirAll(filepath.Join(appDir, "content", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "polypkg.yaml"),
		[]byte("schema: polypkg.package/v1\nname: app\nversion: 1.0.0\nactions: []\n"+
			"recommends:\n  - name: extras\n    version: \">=1.0\"\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "content", "bin", "app"),
		[]byte("#!/bin/sh\necho app\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// "extras" package (weak dep).
	extrasDir := filepath.Join(root, "pkgs", "extras")
	if err := os.MkdirAll(filepath.Join(extrasDir, "content", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(extrasDir, "polypkg.yaml"),
		[]byte("schema: polypkg.package/v1\nname: extras\nversion: 1.0.0\nactions: []\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(extrasDir, "content", "bin", "extras"),
		[]byte("#!/bin/sh\necho extras\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	kp, err := repo.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDir, "repo.key")
	if err := repo.SaveKey(keyPath, kp, "pw", repo.KDFScrypt); err != nil {
		t.Fatal(err)
	}

	manifest := "schema: polypkg.repo/v1\nsource: " + sourceName + "\noutput: ./public\n" +
		"key:\n  path: " + keyPath + "\n  kdf: scrypt\n" +
		"packages:\n  app:\n    source: ./pkgs/app\n  extras:\n    source: ./pkgs/extras\n"
	mPath := filepath.Join(root, "polypkg-repo.yaml")
	if err := os.WriteFile(mPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	b, err := repo.NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	if _, err := b.Build(repo.BuildOptions{}); err != nil {
		t.Fatalf("Build: %v", err)
	}

	outputDir = filepath.Join(root, "public")
	trustRoot = filepath.Join(outputDir, "trust_root.pub")
	return outputDir, trustRoot
}

// TestPlanWeakDepsProvenance verifies that when WeakPolicy is WeakOn:
//   - both the hard ("app") and weak ("extras") packages appear in Manifest.Entries
//   - the "extras" entry carries Weak==true and RecommendedBy==["app"]
//   - the "app" entry carries Weak==false
//   - Manifest.WeakDepsPolicy is "on"
func TestPlanWeakDepsProvenance(t *testing.T) {
	outDir, trustRoot := buildRecommendingRepo(t, "repo")

	p := &schema.Profile{
		Schema: "polypkg.spec/v1",
		Name:   "t",
		Scopes: map[string]schema.ScopeSpec{"user": {Substrate: "store"}},
		Sources: schema.SourcesSpec{
			Order: []string{"repo"},
			Sources: map[string]schema.SourceBackend{
				"repo": {Type: "polypkg-native", URL: outDir, TrustRoot: trustRoot},
			},
		},
		Packages: map[string]map[string]schema.PackageRef{
			"user": {"app": {Version: ">=1.0.0"}},
		},
	}

	res, err := planner.Plan(context.Background(), p, planner.Options{
		Scope:      "user",
		DataHome:   t.TempDir(),
		StateHome:  t.TempDir(),
		WeakPolicy: resolver.WeakOn,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	// Index entries by name for easy lookup.
	byName := make(map[string]schema.ManifestEntry)
	for _, e := range res.Manifest.Entries {
		byName[e.Name] = e
	}

	// Both packages must be present.
	if _, ok := byName["app"]; !ok {
		t.Fatal("manifest missing hard package 'app'")
	}
	if _, ok := byName["extras"]; !ok {
		t.Fatal("manifest missing weak package 'extras'")
	}

	// "app" must not be marked weak.
	if byName["app"].Weak {
		t.Error("'app' should have Weak==false")
	}

	// "extras" must be marked weak and attributed to "app".
	extrasEntry := byName["extras"]
	if !extrasEntry.Weak {
		t.Error("'extras' should have Weak==true")
	}
	if len(extrasEntry.RecommendedBy) != 1 || extrasEntry.RecommendedBy[0] != "app" {
		t.Errorf("'extras' RecommendedBy = %v, want [app]", extrasEntry.RecommendedBy)
	}

	// Policy must be recorded on the manifest.
	if res.Manifest.WeakDepsPolicy != "on" {
		t.Errorf("WeakDepsPolicy = %q, want %q", res.Manifest.WeakDepsPolicy, "on")
	}

	// extras is satisfiable, so nothing should be skipped or suggested.
	if len(res.Skipped) != 0 {
		t.Errorf("Skipped = %v, want empty", res.Skipped)
	}
	if len(res.Suggests) != 0 {
		t.Errorf("Suggests = %v, want empty", res.Suggests)
	}
}

// TestPlanWeakDepsOffSkipsRecommends verifies that when WeakPolicy is WeakOff:
//   - only the hard ("app") package appears in Manifest.Entries
//   - "extras" is NOT installed
//   - Manifest.WeakDepsPolicy is "" (absent under omitempty)
//   - res.Skipped is empty (recommends are not attempted under off)
func TestPlanWeakDepsOffSkipsRecommends(t *testing.T) {
	outDir, trustRoot := buildRecommendingRepo(t, "repo")

	p := &schema.Profile{
		Schema: "polypkg.spec/v1",
		Name:   "t",
		Scopes: map[string]schema.ScopeSpec{"user": {Substrate: "store"}},
		Sources: schema.SourcesSpec{
			Order: []string{"repo"},
			Sources: map[string]schema.SourceBackend{
				"repo": {Type: "polypkg-native", URL: outDir, TrustRoot: trustRoot},
			},
		},
		Packages: map[string]map[string]schema.PackageRef{
			"user": {"app": {Version: ">=1.0.0"}},
		},
	}

	res, err := planner.Plan(context.Background(), p, planner.Options{
		Scope:      "user",
		DataHome:   t.TempDir(),
		StateHome:  t.TempDir(),
		WeakPolicy: resolver.WeakOff,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	// Index entries by name for easy lookup.
	byName := make(map[string]schema.ManifestEntry)
	for _, e := range res.Manifest.Entries {
		byName[e.Name] = e
	}

	// Only the hard package should be present.
	if _, ok := byName["app"]; !ok {
		t.Fatal("manifest missing hard package 'app'")
	}
	if _, ok := byName["extras"]; ok {
		t.Error("manifest should NOT contain weak package 'extras' when WeakOff")
	}

	// Policy field must be absent (empty string → omitempty omits it from JSON).
	if res.Manifest.WeakDepsPolicy != "" {
		t.Errorf("WeakDepsPolicy = %q, want %q (absent)", res.Manifest.WeakDepsPolicy, "")
	}

	// Recommends are not attempted under WeakOff — nothing should be skipped.
	if len(res.Skipped) != 0 {
		t.Errorf("Skipped = %v, want empty", res.Skipped)
	}
}

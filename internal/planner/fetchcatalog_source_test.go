package planner_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/planner"
	"github.com/trevor-vaughan/polypkg/internal/repo"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

// buildSignedLocalRepo builds a real signed polypkg repo containing one package
// (hello 1.0.0, serial 1) served from a local directory, honoring opts (e.g.
// SkipAttestations for the unattested-publish scenarios). It returns the output
// directory (used as the source URL) and the path to its trust_root.pub.
// testing.TB so both plain tests and Ginkgo specs (via GinkgoTB()) can call it.
func buildSignedLocalRepo(t testing.TB, sourceName string, opts repo.BuildOptions) (outputDir, trustRoot string) {
	t.Helper()
	return buildSignedLocalRepoDecorated(t, sourceName, opts, nil)
}

// buildSignedLocalRepoDecorated is buildSignedLocalRepo with an optional hook to
// mutate the package source dir (pkgs/hello) after layout but before the build —
// used to add carried attestations for carriage tests.
func buildSignedLocalRepoDecorated(t testing.TB, sourceName string, opts repo.BuildOptions, decorate func(t testing.TB, pkgDir string)) (outputDir, trustRoot string) {
	t.Helper()
	root := t.TempDir()
	keyDir := t.TempDir() // outside the output dir (guardKeyNotInOutput)

	pkgDir := filepath.Join(root, "pkgs", "hello")
	if err := os.MkdirAll(filepath.Join(pkgDir, "content", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "polypkg.yaml"),
		[]byte("schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nactions: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "content", "bin", "hello"),
		[]byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
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
		"packages:\n  hello:\n    source: ./pkgs/hello\n"
	mPath := filepath.Join(root, "polypkg-repo.yaml")
	if err := os.WriteFile(mPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	b, err := repo.NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	if decorate != nil {
		decorate(t, pkgDir)
	}
	if _, err := b.Build(opts); err != nil {
		t.Fatalf("Build: %v", err)
	}

	outputDir = filepath.Join(root, "public")
	trustRoot = filepath.Join(outputDir, "trust_root.pub")
	return outputDir, trustRoot
}

// profileForLocalSource returns a minimal profile whose single source points at
// a local repo and requests the hello package in the user scope.
func profileForLocalSource(name, url, trustRoot string) *schema.Profile {
	return &schema.Profile{
		Schema: "polypkg.spec/v1",
		Name:   "t",
		Scopes: map[string]schema.ScopeSpec{"user": {Substrate: "store"}},
		Sources: schema.SourcesSpec{
			Order: []string{name},
			Sources: map[string]schema.SourceBackend{
				name: {Type: "polypkg-native", URL: url, TrustRoot: trustRoot},
			},
		},
		Packages: map[string]map[string]schema.PackageRef{
			"user": {"hello": {Version: ">=1.0.0"}},
		},
	}
}

func TestFetchCatalogVerifiesSignedLocalSource(t *testing.T) {
	out, tr := buildSignedLocalRepo(t, "repo", repo.BuildOptions{})
	p := profileForLocalSource("repo", out, tr)
	stateHome := t.TempDir()

	res, err := planner.FetchCatalog(context.Background(), p, planner.Options{Scope: "user", StateHome: stateHome})
	if err != nil {
		t.Fatalf("FetchCatalog on a valid signed source: %v", err)
	}
	if res.Catalog == nil {
		t.Fatal("expected a non-nil catalog")
	}
	if res.Keyrings["repo"] == nil {
		t.Fatal("expected a verified keyring for source repo")
	}

	// The trust and index serial high-water marks must advance to the published
	// serial (1) on success.
	seen, err := trust.LoadSeen(stateHome, "repo")
	if err != nil {
		t.Fatal(err)
	}
	if seen.TrustSerial != 1 || seen.IndexSerial != 1 {
		t.Fatalf("seen serials = trust %d index %d, want 1/1", seen.TrustSerial, seen.IndexSerial)
	}
}

func TestFetchCatalogRejectsTrustRollback(t *testing.T) {
	out, tr := buildSignedLocalRepo(t, "repo", repo.BuildOptions{})
	p := profileForLocalSource("repo", out, tr)
	stateHome := t.TempDir()

	// Pre-seed a trust serial higher than the repo publishes (1): a mirror
	// replaying this older trust document must be rejected.
	if err := trust.StoreSeen(stateHome, "repo", trust.Seen{TrustSerial: 5, IndexSerial: 5}); err != nil {
		t.Fatal(err)
	}
	_, err := planner.FetchCatalog(context.Background(), p, planner.Options{Scope: "user", StateHome: stateHome})
	if err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("want trust rollback rejection, got %v", err)
	}
}

func TestFetchCatalogRejectsIndexRollback(t *testing.T) {
	out, tr := buildSignedLocalRepo(t, "repo", repo.BuildOptions{})
	p := profileForLocalSource("repo", out, tr)
	stateHome := t.TempDir()

	// Trust serial within bounds, but a higher last-seen index serial than the
	// repo publishes (1): the stale index must be rejected even though its
	// trust document verifies.
	if err := trust.StoreSeen(stateHome, "repo", trust.Seen{TrustSerial: 0, IndexSerial: 5}); err != nil {
		t.Fatal(err)
	}
	_, err := planner.FetchCatalog(context.Background(), p, planner.Options{Scope: "user", StateHome: stateHome})
	if err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("want index rollback rejection, got %v", err)
	}
}

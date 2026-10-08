package repo

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

// readBundle returns the tar's regular-file entries as a name->bytes map.
func readBundle(t *testing.T, path string) map[string][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open bundle: %v", err)
	}
	defer f.Close()
	out := map[string][]byte{}
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read entry %q: %v", hdr.Name, err)
		}
		out[hdr.Name] = b
	}
	return out
}

func bundleNames(m map[string][]byte) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// buildTestRepoForExport builds newTestRepo and returns (manifest path, keyDir,
// published outputDir).
func buildTestRepoForExport(t *testing.T) (string, string, string) {
	t.Helper()
	mPath, keyDir := newTestRepo(t)
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	if _, err := b.Build(BuildOptions{}); err != nil {
		t.Fatalf("Build: %v", err)
	}
	return mPath, keyDir, filepath.Join(filepath.Dir(mPath), "public")
}

func TestExportBundleWholeRepoCarriesReachableBlobsAndSignedManifest(t *testing.T) {
	mPath, keyDir, pub := buildTestRepoForExport(t)
	bundle := filepath.Join(t.TempDir(), "bundle.tar")

	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	res, err := b.ExportBundle(nil, bundle)
	if err != nil {
		t.Fatalf("ExportBundle: %v", err)
	}

	files := readBundle(t, bundle)

	for _, want := range []string{"index.json", "index.json.minisig", "trust.json", "trust.json.minisig", "trust_root.pub", "pool-manifest.json", "pool-manifest.json.minisig"} {
		if _, ok := files[want]; !ok {
			t.Fatalf("bundle missing %q (have %v)", want, bundleNames(files))
		}
	}

	idx := readIndex(t, pub)
	art := idx.Packages["hello"][0].Artifact
	if _, ok := files[art]; !ok {
		t.Fatalf("bundle missing artifact %q", art)
	}
	if _, ok := files[art+".minisig"]; !ok {
		t.Fatalf("bundle missing artifact sig %q", art+".minisig")
	}

	foundAtt := false
	for n := range files {
		if strings.HasPrefix(n, "pool/") && strings.HasSuffix(n, ".att.json") {
			foundAtt = true
			if _, ok := files[n+".minisig"]; !ok {
				t.Fatalf("attestation %q present but its sig is missing", n)
			}
		}
	}
	if !foundAtt {
		t.Fatal("expected at least one attestation blob in the bundle")
	}

	rootPub, err := os.ReadFile(filepath.Join(pub, "trust_root.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.Verify(string(rootPub), files["pool-manifest.json"], string(files["pool-manifest.json.minisig"])); err != nil {
		t.Fatalf("manifest signature invalid: %v", err)
	}
	m, err := schema.ParsePoolManifest(bytes.NewReader(files["pool-manifest.json"]))
	if err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	listed := map[string]struct{}{}
	for _, e := range m.Entries {
		listed[e.Path] = struct{}{}
		if e.ContentHash != ContentHash(files[e.Path]) {
			t.Fatalf("manifest hash for %q does not match bundled bytes", e.Path)
		}
	}
	for n := range files {
		if n == "pool-manifest.json" || n == "pool-manifest.json.minisig" {
			continue
		}
		if _, ok := listed[n]; !ok {
			t.Fatalf("bundled file %q is not listed in the manifest", n)
		}
	}
	if res.Entries != len(m.Entries) || res.Source == "" {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestExportBundleSubsetSelectsOnlyRequestedPackage(t *testing.T) {
	mPath, keyDir, pub := buildTestRepoForExport(t)
	idx := readIndex(t, pub)
	ver := idx.Packages["hello"][0].Version
	bundle := filepath.Join(t.TempDir(), "subset.tar")

	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.ExportBundle([]string{"hello@" + ver}, bundle); err != nil {
		t.Fatalf("ExportBundle subset: %v", err)
	}
	files := readBundle(t, bundle)
	if _, ok := files[idx.Packages["hello"][0].Artifact]; !ok {
		t.Fatal("subset bundle missing the requested artifact")
	}

	b2, _ := NewBuilder(mPath, keyDir, "pw")
	if _, err := b2.ExportBundle([]string{"nope"}, filepath.Join(t.TempDir(), "x.tar")); err == nil {
		t.Fatal("expected error selecting a package not in the index")
	}
}

func TestExportBundleIsDeterministic(t *testing.T) {
	mPath, keyDir, _ := buildTestRepoForExport(t)
	b1, _ := NewBuilder(mPath, keyDir, "pw")
	p1 := filepath.Join(t.TempDir(), "a.tar")
	if _, err := b1.ExportBundle(nil, p1); err != nil {
		t.Fatal(err)
	}
	b2, _ := NewBuilder(mPath, keyDir, "pw")
	p2 := filepath.Join(t.TempDir(), "b.tar")
	if _, err := b2.ExportBundle(nil, p2); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(p1)
	c, _ := os.ReadFile(p2)
	if !bytes.Equal(a, c) {
		t.Fatal("export is not byte-for-byte deterministic across runs")
	}
}

// buildTwoPlatformRepoForExport builds a repo publishing hello 1.0.0 for
// linux/amd64 and darwin/arm64 and returns (manifest path, keyDir, published
// outputDir), like buildTestRepoForExport.
func buildTwoPlatformRepoForExport(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	keyDir := t.TempDir()
	for _, p := range []struct{ dir, platform string }{
		{"hello-linux", "linux/amd64"},
		{"hello-darwin", "darwin/arm64"},
	} {
		dir := filepath.Join(root, "pkgs", p.dir)
		if err := os.MkdirAll(filepath.Join(dir, "content", "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		pm := "schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nplatform: " + p.platform + "\nactions: []\n"
		if err := os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte(pm), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "content", "bin", "hello"), []byte("#!/bin/sh\necho "+p.dir+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDir, "example.key")
	if err := SaveKey(keyPath, kp, "pw", KDFScrypt); err != nil {
		t.Fatal(err)
	}
	manifest := "schema: polypkg.repo/v1\nsource: example\noutput: ./public\n" +
		"key:\n  path: " + keyPath + "\n  kdf: scrypt\n" +
		"packages:\n  hello:\n    - source: ./pkgs/hello-linux\n    - source: ./pkgs/hello-darwin\n"
	mPath := filepath.Join(root, "polypkg-repo.yaml")
	if err := os.WriteFile(mPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	if _, err := b.Build(BuildOptions{}); err != nil {
		t.Fatalf("Build: %v", err)
	}
	return mPath, keyDir, filepath.Join(root, "public")
}

// TestExportBundleCarriesEveryPlatformBuild proves that every selection form
// that names hello 1.0.0 (the whole repo, the bare name, the exact version)
// exports both platform builds' artifacts and signatures, each listed in the
// signed pool manifest.
func TestExportBundleCarriesEveryPlatformBuild(t *testing.T) {
	mPath, keyDir, pub := buildTwoPlatformRepoForExport(t)
	entries := readIndex(t, pub).Packages["hello"]
	if len(entries) != 2 || entries[0].Platform == entries[1].Platform || entries[0].Artifact == entries[1].Artifact {
		t.Fatalf("fixture: want two hello builds on distinct platforms and pool blobs, got %+v", entries)
	}
	for _, selectors := range [][]string{nil, {"hello"}, {"hello@1.0.0"}} {
		b, err := NewBuilder(mPath, keyDir, "pw")
		if err != nil {
			t.Fatal(err)
		}
		bundle := filepath.Join(t.TempDir(), "bundle.tar")
		if _, err := b.ExportBundle(selectors, bundle); err != nil {
			t.Fatalf("selectors %v: ExportBundle: %v", selectors, err)
		}
		files := readBundle(t, bundle)
		m, err := schema.ParsePoolManifest(bytes.NewReader(files["pool-manifest.json"]))
		if err != nil {
			t.Fatalf("selectors %v: parse pool manifest: %v", selectors, err)
		}
		listed := map[string]bool{}
		for _, e := range m.Entries {
			listed[e.Path] = true
		}
		for _, e := range entries {
			for _, want := range []string{e.Artifact, e.Artifact + ".minisig"} {
				if _, ok := files[want]; !ok {
					t.Errorf("selectors %v: bundle is missing the %s build's %q", selectors, e.Platform, want)
				}
				if !listed[want] {
					t.Errorf("selectors %v: pool manifest does not list the %s build's %q", selectors, e.Platform, want)
				}
			}
		}
	}
}

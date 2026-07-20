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

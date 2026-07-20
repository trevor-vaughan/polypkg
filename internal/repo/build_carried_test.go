package repo

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func writeCarriedRepo(t *testing.T, bind bool) (mPath, keyDir string) {
	t.Helper()
	mPath, keyDir = newTestRepo(t)
	// newTestRepo lays out package "hello" at pkgs/hello with content/bin/hello.
	srcDir := filepath.Join(filepath.Dir(mPath), "pkgs", "hello")
	contentFile := filepath.Join(srcDir, "content", "bin", "hello")
	body, err := os.ReadFile(contentFile)
	if err != nil {
		t.Fatalf("read fixture content (adjust path to newTestRepo layout): %v", err)
	}
	digest := sha256Bare(body)
	subjectName := "bin/hello" // advisory
	if !bind {
		digest = sha256Bare([]byte("mismatch"))
	}
	attDir := filepath.Join(srcDir, "attestations")
	if err := os.MkdirAll(attDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attDir, "slsa.json"), dsseSLSA(t, subjectName, digest), 0o644); err != nil {
		t.Fatal(err)
	}
	return mPath, keyDir
}

func TestBuildCarriesAndBindsExternalProvenance(t *testing.T) {
	mPath, keyDir := writeCarriedRepo(t, true)
	pub := filepath.Join(filepath.Dir(mPath), "public")
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(BuildOptions{}); err != nil {
		t.Fatalf("build with carried provenance: %v", err)
	}
	e := readIndex(t, pub).Packages["hello"][0]

	for _, r := range e.Attestations {
		if _, statErr := os.Stat(filepath.Join(pub, r.Artifact)); statErr != nil {
			t.Fatalf("attestation blob %s missing: %v", r.Artifact, statErr)
		}
	}
	var carried, link int
	for _, r := range e.Attestations {
		switch {
		case r.Kind == schema.KindCarriedOpaque:
			carried++
			if r.Format != schema.FormatSLSAProvenance {
				t.Fatalf("carried format = %q", r.Format)
			}
			if r.SubjectScope != "content:bin/hello" {
				t.Fatalf("carried subject_scope = %q", r.SubjectScope)
			}
		case r.Format == schema.FormatPolypkgLink:
			link++
		}
	}
	if carried != 1 || link != 1 {
		t.Fatalf("carried=%d link=%d, want 1/1; refs=%+v", carried, link, e.Attestations)
	}
	if !sort.SliceIsSorted(e.Attestations, func(i, j int) bool { return attRefLess(e.Attestations[i], e.Attestations[j]) }) {
		t.Fatal("attestation refs are not stably sorted")
	}
}

func TestBuildRefusesUnboundCarriedProvenance(t *testing.T) {
	mPath, keyDir := writeCarriedRepo(t, false)
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(BuildOptions{}); err == nil {
		t.Fatal("expected build to refuse carried provenance that binds nothing")
	}
}

package repo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gowebpki/jcs"
	"github.com/trevor-vaughan/polypkg/internal/attest"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// writeCanonicalSarifStatement writes a JCS-canonical in-toto SARIF statement
// binding artName+blakeHex and returns the file path.
func writeCanonicalSarifStatement(t *testing.T, dir, artName, blakeHex string) string {
	t.Helper()
	st := attest.AssembleStatement(artName, blakeHex, json.RawMessage(`{"runs":[]}`))
	b, err := st.CanonicalJSON()
	if err != nil {
		t.Fatalf("canon: %v", err)
	}
	p := filepath.Join(dir, "native.att.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestNativeAttestationRefValid(t *testing.T) {
	dir := t.TempDir()
	ch := "blake3:" + strings.Repeat("ab", 32)
	hex := strings.TrimPrefix(ch, "blake3:")
	p := writeCanonicalSarifStatement(t, dir, "acme-1.0.0.tar.zst", hex)

	b := &Builder{}
	ref, blob, err := b.nativeAttestationRef(p, "acme", "1.0.0", ch)
	if err != nil {
		t.Fatalf("valid preview rejected: %v", err)
	}
	if ref.Kind != schema.KindNativeJCS {
		t.Fatalf("ref.Kind = %q, want %q", ref.Kind, schema.KindNativeJCS)
	}
	if ref.PredicateType != attest.PredicateTypeSARIF {
		t.Fatalf("ref.PredicateType = %q, want %q", ref.PredicateType, attest.PredicateTypeSARIF)
	}
	if ref.Format != schema.FormatPolypkgSARIF {
		t.Fatalf("ref.Format = %q, want %q", ref.Format, schema.FormatPolypkgSARIF)
	}
	if ref.ContentHash == "" {
		t.Fatal("ref.ContentHash is empty")
	}
	if blob.name != ref.Artifact {
		t.Fatalf("blob.name = %q, want ref.Artifact %q", blob.name, ref.Artifact)
	}
}

func TestNativeAttestationRefRejectsWrongDigest(t *testing.T) {
	dir := t.TempDir()
	ch := "blake3:" + strings.Repeat("ab", 32)
	// Preview binds a DIFFERENT hex than the artifact content-hash.
	p := writeCanonicalSarifStatement(t, dir, "acme-1.0.0.tar.zst", strings.Repeat("cd", 32))

	b := &Builder{}
	if _, _, err := b.nativeAttestationRef(p, "acme", "1.0.0", ch); err == nil {
		t.Fatal("expected rejection: preview binds a different digest")
	}
}

func TestNativeAttestationRefRejectsWrongSubjectName(t *testing.T) {
	dir := t.TempDir()
	ch := "blake3:" + strings.Repeat("ab", 32)
	hex := strings.TrimPrefix(ch, "blake3:")
	// Correct digest, wrong subject name.
	p := writeCanonicalSarifStatement(t, dir, "other-1.0.0.tar.zst", hex)

	b := &Builder{}
	if _, _, err := b.nativeAttestationRef(p, "acme", "1.0.0", ch); err == nil {
		t.Fatal("expected rejection: preview binds a different subject name")
	}
}

func TestNativeAttestationRefRejectsNonSARIFPredicate(t *testing.T) {
	dir := t.TempDir()
	ch := "blake3:" + strings.Repeat("ab", 32)
	hex := strings.TrimPrefix(ch, "blake3:")

	st := attest.AssembleStatement("acme-1.0.0.tar.zst", hex, json.RawMessage(`{"runs":[]}`))
	b0, err := st.CanonicalJSON()
	if err != nil {
		t.Fatalf("canon: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b0, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	m["predicateType"] = "https://example.com/other/v1"
	remarshalled, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	canon, err := jcs.Transform(remarshalled)
	if err != nil {
		t.Fatalf("jcs: %v", err)
	}
	p := filepath.Join(dir, "native.att.json")
	if err := os.WriteFile(p, canon, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	b := &Builder{}
	if _, _, err := b.nativeAttestationRef(p, "acme", "1.0.0", ch); err == nil {
		t.Fatal("expected rejection: predicateType is not the polypkg SARIF predicate")
	}
}

func TestNativeAttestationRefRejectsNonCanonical(t *testing.T) {
	dir := t.TempDir()
	ch := "blake3:" + strings.Repeat("ab", 32)
	hex := strings.TrimPrefix(ch, "blake3:")

	st := attest.AssembleStatement("acme-1.0.0.tar.zst", hex, json.RawMessage(`{"runs":[]}`))
	b0, err := st.CanonicalJSON()
	if err != nil {
		t.Fatalf("canon: %v", err)
	}
	// Append a trailing space so the bytes are valid JSON but not JCS-canonical.
	p := filepath.Join(dir, "native.att.json")
	if err := os.WriteFile(p, append(b0, ' '), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	b := &Builder{}
	if _, _, err := b.nativeAttestationRef(p, "acme", "1.0.0", ch); err == nil {
		t.Fatal("expected rejection: bytes are not JCS-canonical")
	}
}

func TestNativeAttestationRefRejectsMalformed(t *testing.T) {
	dir := t.TempDir()
	ch := "blake3:" + strings.Repeat("ab", 32)
	p := filepath.Join(dir, "native.att.json")
	if err := os.WriteFile(p, []byte("{"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	b := &Builder{}
	if _, _, err := b.nativeAttestationRef(p, "acme", "1.0.0", ch); err == nil {
		t.Fatal("expected rejection: malformed JSON")
	}
}

func TestBuildIngestsNativeAttestation(t *testing.T) {
	root := t.TempDir()
	sp := stageOnePrebuilt(t, root, "hello", nil)

	// Bind the native SARIF preview to the STAGED artifact's content-hash.
	artifact, err := os.ReadFile(sp.artPath)
	if err != nil {
		t.Fatal(err)
	}
	hex := strings.TrimPrefix(ContentHash(artifact), "blake3:")
	st := attest.AssembleStatement("hello-1.0.0.tar.zst", hex, json.RawMessage(`{"runs":[]}`))
	canon, err := st.CanonicalJSON()
	if err != nil {
		t.Fatalf("canon: %v", err)
	}
	sp.nativePath = filepath.Join(filepath.Dir(sp.artPath), "native.att.json")
	if err := os.WriteFile(sp.nativePath, canon, 0o644); err != nil {
		t.Fatal(err)
	}

	mPath, keyDir := writePrebuiltManifest(t, root, sp)
	pub := filepath.Join(root, "public")
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(BuildOptions{}); err != nil {
		t.Fatalf("build prebuilt with native attestation: %v", err)
	}

	e := readIndex(t, pub).Packages["hello"][0]
	var nativeRef schema.AttestationRef
	found := false
	for _, r := range e.Attestations {
		if r.Kind == schema.KindNativeJCS && r.PredicateType == attest.PredicateTypeSARIF {
			found = true
			nativeRef = r
		}
	}
	if !found {
		t.Fatalf("signed index has no native-jcs SARIF attestation ref; refs=%+v", e.Attestations)
	}
	if _, statErr := os.Stat(filepath.Join(pub, nativeRef.Artifact)); statErr != nil {
		t.Fatalf("native attestation blob %s missing: %v", nativeRef.Artifact, statErr)
	}
	if _, statErr := os.Stat(filepath.Join(pub, nativeRef.Artifact+".minisig")); statErr != nil {
		t.Fatalf("native attestation was not signed (%s.minisig missing): %v", nativeRef.Artifact, statErr)
	}
}

func TestNativeAttestationRefRejectsMissingFile(t *testing.T) {
	dir := t.TempDir()
	ch := "blake3:" + strings.Repeat("ab", 32)
	p := filepath.Join(dir, "does-not-exist.att.json")

	b := &Builder{}
	if _, _, err := b.nativeAttestationRef(p, "acme", "1.0.0", ch); err == nil {
		t.Fatal("expected rejection: file does not exist")
	}
}

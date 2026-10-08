package repo

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func sha256Bare(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// writeCarriedFixture creates a package source dir with content/bin/hello and
// returns the dir plus that file's bytes.
func writeCarriedFixture(t *testing.T) (dir string, helloBytes []byte) {
	t.Helper()
	dir = t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "content", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	helloBytes = []byte("#!/bin/sh\necho hello\n")
	if err := os.WriteFile(filepath.Join(dir, "content", "bin", "hello"), helloBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, helloBytes
}

// dsseSLSA wraps an in-toto SLSA statement (subject = one file digest) in DSSE.
func dsseSLSA(t *testing.T, subjectName, sha256hex string) []byte {
	t.Helper()
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []map[string]any{{"name": subjectName, "digest": map[string]string{"sha256": sha256hex}}},
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate":     map[string]any{},
	}
	stB, _ := json.Marshal(st)
	env := map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": base64.StdEncoding.EncodeToString(stB), "signatures": []map[string]string{{"keyid": "k", "sig": "AA=="}}}
	b, _ := json.Marshal(env)
	return b
}

func TestBindCarriedBindsContentFileByDigest(t *testing.T) {
	dir, hello := writeCarriedFixture(t)
	carried := dsseSLSA(t, "bin/hello", sha256Bare(hello))
	got, err := bindCarried(dir, []byte("the-artifact-bytes"), carried)
	if err != nil {
		t.Fatalf("bindCarried: %v", err)
	}
	if got.PredicateType != "https://slsa.dev/provenance/v1" {
		t.Fatalf("predicate = %q", got.PredicateType)
	}
	if got.Format != "slsa-provenance" {
		t.Fatalf("format = %q", got.Format)
	}
	if got.SubjectScope != "content:bin/hello" {
		t.Fatalf("scope = %q", got.SubjectScope)
	}
	if len(got.Materials) != 1 || got.Materials[0].Name != "content:bin/hello" {
		t.Fatalf("materials = %+v", got.Materials)
	}
}

func TestBindCarriedBindsArtifact(t *testing.T) {
	dir, _ := writeCarriedFixture(t)
	artifact := []byte("the-artifact-bytes")
	carried := dsseSLSA(t, "hello.tar.zst", sha256Bare(artifact))
	got, err := bindCarried(dir, artifact, carried)
	if err != nil {
		t.Fatalf("bindCarried: %v", err)
	}
	if got.SubjectScope != "artifact" {
		t.Fatalf("scope = %q", got.SubjectScope)
	}
}

func TestBindCarriedRejectsUnboundProvenance(t *testing.T) {
	dir, _ := writeCarriedFixture(t)
	carried := dsseSLSA(t, "bin/hello", sha256Bare([]byte("totally different bytes")))
	_, err := bindCarried(dir, []byte("the-artifact-bytes"), carried)
	if err == nil {
		t.Fatal("expected bind failure for provenance that describes nothing packed")
	}
}

func TestBindCarriedRejectsUnparseableEnvelope(t *testing.T) {
	dir, _ := writeCarriedFixture(t)
	_, err := bindCarried(dir, []byte("x"), []byte(`{"random":"json"}`))
	if err == nil {
		t.Fatal("expected error for unrecognized envelope")
	}
}

// TestBindCarriedSkipsSymlinkInContent pins that the content walk never reads a
// symlink as a binding target: a symlink (lexically before the real file) whose
// resolved bytes match the subject must NOT be selected — only the regular file
// is. If the walk followed the symlink, first-match (lexical order) would bind
// the subject to "content:link" instead of "content:real".
func TestBindCarriedSkipsSymlinkInContent(t *testing.T) {
	dir := t.TempDir()
	cdir := filepath.Join(dir, "content")
	if err := os.MkdirAll(cdir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte("payload bytes\n")
	if err := os.WriteFile(filepath.Join(cdir, "real"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(cdir, "link")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	carried := dsseSLSA(t, "real", sha256Bare(body))
	got, err := bindCarried(dir, []byte("artifact"), carried)
	if err != nil {
		t.Fatalf("bindCarried: %v", err)
	}
	if got.SubjectScope != "content:real" {
		t.Fatalf("scope = %q, want content:real (symlink must be skipped, not followed)", got.SubjectScope)
	}
}

// TestBindCarriedWeakOnlySubjectDoesNotBind pins that a subject offering only a
// forbidden weak digest (sha1) cannot bind — MatchSubjectDigests rejects it, so
// the target is skipped and the attestation binds nothing (fail closed).
func TestBindCarriedWeakOnlySubjectDoesNotBind(t *testing.T) {
	dir, hello := writeCarriedFixture(t)
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []map[string]any{{"name": "bin/hello", "digest": map[string]string{"sha1": sha256Bare(hello)}}},
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate":     map[string]any{},
	}
	stB, _ := json.Marshal(st)
	if _, err := bindCarried(dir, []byte("artifact"), stB); err == nil {
		t.Fatal("expected a sha1-only subject to fail binding (weak digest forbidden)")
	}
}

func rawSPDXFixture(fileName, sha256hex string) []byte {
	doc := map[string]any{
		"spdxVersion": "SPDX-2.3",
		"SPDXID":      "SPDXRef-DOCUMENT",
		"name":        "hello-sbom",
		"files": []map[string]any{{
			"fileName":  fileName,
			"SPDXID":    "SPDXRef-File-hello",
			"checksums": []map[string]any{{"algorithm": "SHA256", "checksumValue": sha256hex}},
		}},
	}
	b, _ := json.Marshal(doc)
	return b
}

func rawCycloneDXFixture(name, sha256hex string) []byte {
	doc := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"metadata": map[string]any{
			"component": map[string]any{
				"type":   "application",
				"name":   name,
				"hashes": []map[string]any{{"alg": "SHA-256", "content": sha256hex}},
			},
		},
	}
	b, _ := json.Marshal(doc)
	return b
}

func TestBindCarriedBindsRawSPDXByChecksum(t *testing.T) {
	dir, hello := writeCarriedFixture(t)
	got, err := bindCarried(dir, []byte("the-artifact-bytes"), rawSPDXFixture("bin/hello", sha256Bare(hello)))
	if err != nil {
		t.Fatalf("bindCarried raw SPDX: %v", err)
	}
	if got.Format != "spdx" {
		t.Fatalf("format = %q, want spdx", got.Format)
	}
	if got.PredicateType != "https://spdx.dev/Document" {
		t.Fatalf("predicate = %q, want canonical SPDX URI", got.PredicateType)
	}
	if got.SubjectScope != "content:bin/hello" {
		t.Fatalf("scope = %q, want content:bin/hello", got.SubjectScope)
	}
}

func TestBindCarriedBindsRawCycloneDXAgainstArtifact(t *testing.T) {
	dir, _ := writeCarriedFixture(t)
	artifact := []byte("the-artifact-bytes")
	got, err := bindCarried(dir, artifact, rawCycloneDXFixture("hello", sha256Bare(artifact)))
	if err != nil {
		t.Fatalf("bindCarried raw CycloneDX: %v", err)
	}
	if got.Format != "cyclonedx" {
		t.Fatalf("format = %q, want cyclonedx", got.Format)
	}
	if got.SubjectScope != "artifact" {
		t.Fatalf("scope = %q, want artifact", got.SubjectScope)
	}
}

func TestBindCarriedRefusesRawSBOMThatBindsNothing(t *testing.T) {
	dir, _ := writeCarriedFixture(t)
	// A raw SPDX whose only checksum matches neither the artifact nor any content file.
	unrelated := rawSPDXFixture("bin/hello", sha256Bare([]byte("something-else-entirely")))
	if _, err := bindCarried(dir, []byte("the-artifact-bytes"), unrelated); err == nil {
		t.Fatal("expected bindCarried to refuse a raw SBOM that binds nothing packed")
	}
}

// TestBindCarriedBindsGitHubSigstoreBundle confirms the carry-in binding takes
// the bundle GitHub artifact attestations publish (a
// dev.sigstore.bundle.v0.3+json over an in-toto v1 statement) when the
// attested asset is a content file, which is how an imported release lays
// out its package source.
func TestBindCarriedBindsGitHubSigstoreBundle(t *testing.T) {
	read := func(name string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("..", "attest", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	asset, bundle := read("github-asset.bin"), read("github-bundle.json")
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "content"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "content", "tool-linux-amd64"), asset, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := bindCarried(dir, []byte("the-artifact-bytes"), bundle)
	if err != nil {
		t.Fatalf("bindCarried: %v", err)
	}
	if got.Format != schema.FormatSigstoreBundle {
		t.Fatalf("format = %q, want %q", got.Format, schema.FormatSigstoreBundle)
	}
	if got.SubjectScope != "content:tool-linux-amd64" {
		t.Fatalf("scope = %q", got.SubjectScope)
	}
	if got.SubjectDigests["sha256"] != sha256Bare(asset) {
		t.Fatalf("digest = %q, want %q", got.SubjectDigests["sha256"], sha256Bare(asset))
	}
}

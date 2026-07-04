package repo

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func TestBuildCacheFingerprintDetectsChange(t *testing.T) {
	dir := t.TempDir()
	writePkgSrc(t, dir) // defined in pack_test.go

	fp1, err := SourceFingerprint(dir)
	if err != nil {
		t.Fatal(err)
	}
	fp2, err := SourceFingerprint(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fp1 != fp2 {
		t.Fatal("fingerprint not stable for unchanged source")
	}
	target := filepath.Join(dir, "content", "bin", "hello")
	if err := os.WriteFile(target, []byte("changed contents are longer"), 0o755); err != nil {
		t.Fatal(err)
	}
	future := time.Unix(1<<31, 0)
	_ = os.Chtimes(target, future, future)
	fp3, err := SourceFingerprint(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fp3 == fp1 {
		t.Fatal("fingerprint did not change after edit")
	}
}

func TestBuildCacheSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.json")
	c := NewBuildCache()
	c.Serial = 7
	c.Put("./pkgs/hello", CacheEntry{
		Fingerprint: "fp", ContentHash: "blake3:x", Artifact: "hello-1.0.0.tar.zst", Version: "1.0.0",
		Attestations: []schema.AttestationRef{{
			PredicateType: "https://polypkg.dev/attestation/sarif/v1",
			Artifact:      "pool/bb.att.json", ContentHash: "blake3:bb",
		}},
	})
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("cache file mode = %v (err %v)", fi.Mode().Perm(), err)
	}
	got, err := LoadBuildCache(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Serial != 7 {
		t.Fatalf("serial = %d", got.Serial)
	}
	e, ok := got.Get("./pkgs/hello")
	if !ok || e.ContentHash != "blake3:x" {
		t.Fatalf("entry = %+v ok=%v", e, ok)
	}
	if len(e.Attestations) != 1 || e.Attestations[0].ContentHash != "blake3:bb" {
		t.Fatalf("attestations = %+v", e.Attestations)
	}
}

func TestLoadBuildCacheMissingIsEmpty(t *testing.T) {
	got, err := LoadBuildCache(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("missing cache should be empty, got err %v", err)
	}
	if len(got.Entries) != 0 || got.Serial != 0 {
		t.Fatal("missing cache should be zero-valued")
	}
}

func TestStaleV1CacheIsCold(t *testing.T) {
	// A cache file with schema polypkg.repo-cache/v1 must be treated as cold:
	// its entries carry flat artifact names that would leak into a v2 pool
	// index via the stat-check cache-hit path (D-C8).
	c := NewBuildCache()
	if c.Schema != "polypkg.repo-cache/v3" {
		t.Fatalf("new cache schema = %q", c.Schema)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	if err := os.WriteFile(p, []byte(`{"schema":"polypkg.repo-cache/v1","serial":7,"entries":{"x":{"fingerprint":"f","content_hash":"blake3:aa","artifact":"x-1.tar.zst","version":"1"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadBuildCache(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 0 || got.Serial != 0 {
		t.Fatalf("v1 cache not treated as cold: %+v", got)
	}
}

func TestStaleV2CacheIsCold(t *testing.T) {
	// A v2 cache carries single-attestation fields (att_predicate_type/…) that
	// v3 no longer understands; it must cold-reset rather than silently drop the
	// attestation shape on rebuild.
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	body := `{"schema":"polypkg.repo-cache/v2","serial":4,"entries":{"x":{"fingerprint":"f","content_hash":"blake3:aa","artifact":"pool/aa.tar.zst","version":"1","att_predicate_type":"t","att_artifact":"pool/bb.att.json","att_content_hash":"blake3:bb"}}}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadBuildCache(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 0 || got.Serial != 0 {
		t.Fatalf("v2 cache not treated as cold: %+v", got)
	}
}

// TestLoadBuildCacheSchemaLessIsCold pins the zero-struct-unmarshal case: a
// file that is valid JSON but carries no schema key must load as cold, not as
// a live cache with serial/entries taken at face value.
func TestLoadBuildCacheSchemaLessIsCold(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(path, []byte(`{"serial":7,"entries":{"x":{"fingerprint":"f","content_hash":"blake3:aa","artifact":"pool/aa.tar.zst","version":"1"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadBuildCache(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 0 || got.Serial != 0 {
		t.Fatalf("schema-less cache not treated as cold: %+v", got)
	}
}

func TestLoadBuildCacheCorruptIsCold(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadBuildCache(path)
	if err != nil {
		t.Fatalf("corrupt cache should be treated as cold, got err %v", err)
	}
	if len(got.Entries) != 0 {
		t.Fatal("corrupt cache should yield empty entries")
	}
}

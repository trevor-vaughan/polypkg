package schema

import (
	"strings"
	"testing"
)

func TestParsePoolManifestRoundTrips(t *testing.T) {
	const j = `{
	  "schema": "polypkg.pool-manifest/v1",
	  "source": "example",
	  "serial": 3,
	  "issued_at": "1970-01-01T00:00:00Z",
	  "expires": "2099-01-01T00:00:00Z",
	  "entries": [
	    {"path": "index.json", "content_hash": "blake3:aa", "kind": "index"},
	    {"path": "pool/bb.tar.zst", "content_hash": "blake3:bb", "kind": "artifact"}
	  ]
	}`
	m, err := ParsePoolManifest(strings.NewReader(j))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.Source != "example" || m.Serial != 3 || m.Expires != "2099-01-01T00:00:00Z" {
		t.Fatalf("unexpected header: %+v", m)
	}
	if len(m.Entries) != 2 || m.Entries[1].Kind != "artifact" || m.Entries[1].Path != "pool/bb.tar.zst" {
		t.Fatalf("unexpected entries: %+v", m.Entries)
	}
}

func TestParsePoolManifestRejectsUnknownKind(t *testing.T) {
	const j = `{"schema":"polypkg.pool-manifest/v1","source":"e","serial":1,"expires":"2099-01-01T00:00:00Z","entries":[{"path":"x","content_hash":"blake3:aa","kind":"bogus"}]}`
	if _, err := ParsePoolManifest(strings.NewReader(j)); err == nil {
		t.Fatal("expected rejection of an unknown kind")
	}
}

func TestParsePoolManifestRejectsBadContentHash(t *testing.T) {
	const j = `{"schema":"polypkg.pool-manifest/v1","source":"e","serial":1,"expires":"2099-01-01T00:00:00Z","entries":[{"path":"x","content_hash":"sha256:aa","kind":"artifact"}]}`
	if _, err := ParsePoolManifest(strings.NewReader(j)); err == nil {
		t.Fatal("expected rejection of a non-blake3 content_hash")
	}
}

func TestParsePoolManifestRejectsDuplicatePath(t *testing.T) {
	const j = `{"schema":"polypkg.pool-manifest/v1","source":"e","serial":1,"expires":"2099-01-01T00:00:00Z","entries":[{"path":"x","content_hash":"blake3:aa","kind":"artifact"},{"path":"x","content_hash":"blake3:bb","kind":"artifact-sig"}]}`
	if _, err := ParsePoolManifest(strings.NewReader(j)); err == nil {
		t.Fatal("expected rejection of a duplicate entry path")
	}
}

func TestParsePoolManifestRejectsUnknownField(t *testing.T) {
	const j = `{"schema":"polypkg.pool-manifest/v1","source":"e","serial":1,"expires":"2099-01-01T00:00:00Z","entries":[],"bogus":true}`
	if _, err := ParsePoolManifest(strings.NewReader(j)); err == nil {
		t.Fatal("expected rejection of an unknown top-level field")
	}
}

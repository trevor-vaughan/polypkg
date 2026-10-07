package schema

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// Patterns the embedded index-v3 JSON Schema imposes, copied from
// jsonschema/index-v3.json so the fuzzer can check that the struct the decoder
// hands to callers obeys what the validator checked on the raw bytes.
var (
	fuzzPackageNameRE = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	fuzzPlatformRE    = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9]+(/[a-z0-9]+)?$`)
	fuzzContentHashRE = regexp.MustCompile(`^blake3:[0-9a-f]+$`)
)

// FuzzParseIndex checks that ParseIndex never panics and that an index it
// accepts is one callers can rely on: it declares the v3 schema, every package
// name, version, artifact, platform and content hash in the decoded struct has
// the shape the schema requires, and re-encoding it yields an index ParseIndex
// accepts and that encodes to the same bytes.
func FuzzParseIndex(f *testing.F) {
	f.Add(`{"schema":"polypkg.index/v3","expires":"2099-01-01T00:00:00Z","packages":{}}`)
	f.Add(`{"schema":"polypkg.index/v3","expires":"2099-01-01T00:00:00Z","packages":{"a":[{"version":"1.0.0","content_hash":"blake3:aa","artifact":"a.tar.zst"}]}}`)
	f.Add(`{"schema":"polypkg.index/v3","expires":"2099-01-01T00:00:00Z","packages":{"a":[{"version":"1.0.0","platform":"linux/amd64","content_hash":"blake3:aa","artifact":"a.tar.zst"}]}}`)
	f.Add(`{"schema":"polypkg.index/v3","expires":"2099-01-01T00:00:00Z","packages":{"a":[{"version":"1.0.0","content_hash":"blake3:aa","artifact":"a.tar.zst","revision":2,"attestations":[],"depends":[{"name":"b","version":">=1"}]}]}}`)
	f.Add(`{"schema":"polypkg.index/v2","expires":"2099-01-01T00:00:00Z","packages":{}}`)
	f.Add(`{"schema":"polypkg.index/v1","packages":{}}`)
	f.Add(`{"schema":"polypkg.index/v3","packages":{}}`)
	f.Add(`not json`)
	f.Fuzz(func(t *testing.T, s string) {
		idx, err := ParseIndex(strings.NewReader(s))
		if err != nil {
			return
		}
		if idx.Schema != IndexSchemaID {
			t.Fatalf("accepted index declaring schema %q", idx.Schema)
		}
		for name, entries := range idx.Packages {
			if !fuzzPackageNameRE.MatchString(name) {
				t.Fatalf("accepted package name %q", name)
			}
			for _, e := range entries {
				if e.Version == "" || e.Artifact == "" {
					t.Fatalf("accepted %s entry with empty version or artifact: %+v", name, e)
				}
				if e.Platform != "" && !fuzzPlatformRE.MatchString(e.Platform) {
					t.Fatalf("accepted %s entry with platform %q", name, e.Platform)
				}
				if !fuzzContentHashRE.MatchString(e.ContentHash) {
					t.Fatalf("accepted %s entry with content hash %q", name, e.ContentHash)
				}
			}
		}

		first, err := json.Marshal(idx)
		if err != nil {
			t.Fatalf("marshal accepted index: %v", err)
		}
		again, err := ParseIndex(bytes.NewReader(first))
		if err != nil {
			t.Fatalf("re-encoded index is rejected: %v\ninput: %q\nre-encoded: %s", err, s, first)
		}
		second, err := json.Marshal(again)
		if err != nil {
			t.Fatalf("marshal re-parsed index: %v", err)
		}
		if !bytes.Equal(first, second) {
			t.Fatalf("index changed across a round trip:\nfirst:  %s\nsecond: %s", first, second)
		}
	})
}

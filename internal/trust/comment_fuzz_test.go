package trust

import (
	"maps"
	"slices"
	"strings"
	"testing"
)

// FuzzParseTrustedComment checks the properties a verifier relies on when it
// reads claims out of a signed trusted comment. A rejected comment yields no
// fields. An accepted one yields exactly one field per whitespace-separated
// token, split at the token's first '=', with a non-empty key, so no token is
// dropped or merged into another. And the fields, written back out as
// "key=value" tokens, parse to the same fields.
func FuzzParseTrustedComment(f *testing.F) {
	f.Add("name=hello version=1.0.0 hash=blake3:abc")
	f.Add("serial=42 ts=2026-01-01T00:00:00Z")
	f.Add("")
	f.Add("=")
	f.Add("a=b a=c")
	f.Add("k==v\tempty=")
	f.Fuzz(func(t *testing.T, comment string) {
		fields, err := parseComment(comment)
		if err != nil {
			if fields != nil {
				t.Fatalf("parseComment(%q) returned fields %v alongside error %v", comment, fields, err)
			}
			return
		}
		if fields == nil {
			t.Fatalf("parseComment(%q) returned nil fields without an error", comment)
		}
		tokens := strings.Fields(comment)
		if len(fields) != len(tokens) {
			t.Fatalf("parseComment(%q) returned %d fields for %d tokens", comment, len(fields), len(tokens))
		}
		for _, tok := range tokens {
			k, v, _ := strings.Cut(tok, "=")
			if k == "" {
				t.Fatalf("parseComment(%q) accepted token %q with an empty key", comment, tok)
			}
			if got, ok := fields[k]; !ok || got != v {
				t.Fatalf("parseComment(%q): token %q is not represented as %q=%q", comment, tok, k, v)
			}
		}

		canonical := make([]string, 0, len(fields))
		for _, k := range slices.Sorted(maps.Keys(fields)) {
			canonical = append(canonical, k+"="+fields[k])
		}
		again, err := parseComment(strings.Join(canonical, " "))
		if err != nil {
			t.Fatalf("re-serialised fields of %q do not parse: %v", comment, err)
		}
		if !maps.Equal(fields, again) {
			t.Fatalf("round trip of %q changed the fields: %v != %v", comment, fields, again)
		}
	})
}

package trust

import "testing"

func FuzzParseTrustedComment(f *testing.F) {
	f.Add("name=hello version=1.0.0 hash=blake3:abc")
	f.Add("serial=42 ts=2026-01-01T00:00:00Z")
	f.Add("")
	f.Add("=")
	f.Add("a=b a=c")
	f.Fuzz(func(t *testing.T, comment string) {
		// Must never panic.
		_, _ = parseComment(comment)
	})
}

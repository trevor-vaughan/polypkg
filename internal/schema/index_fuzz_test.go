package schema

import (
	"strings"
	"testing"
)

func FuzzParseIndex(f *testing.F) {
	f.Add(`{"schema":"polypkg.index/v2","expires":"2099-01-01T00:00:00Z","packages":{}}`)
	f.Add(`{"schema":"polypkg.index/v2","expires":"2099-01-01T00:00:00Z","packages":{"a":[{"version":"1.0.0","content_hash":"blake3:aa","artifact":"a.tar.zst"}]}}`)
	f.Add(`{"schema":"polypkg.index/v1","packages":{}}`)
	f.Add(`{"schema":"polypkg.index/v2","packages":{}}`)
	f.Add(`not json`)
	f.Fuzz(func(t *testing.T, s string) {
		// Must never panic; errors are fine.
		_, _ = ParseIndex(strings.NewReader(s))
	})
}

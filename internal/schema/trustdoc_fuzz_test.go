package schema

import (
	"strings"
	"testing"
)

func FuzzParseTrustDoc(f *testing.F) {
	f.Add(validTrustDoc)
	f.Add(`{"schema":"polypkg.trust/v2","source":"native","serial":1,"expires":"2099-01-01T00:00:00Z","keys":[]}`)
	f.Add(`{}`)
	f.Add(``)
	f.Fuzz(func(t *testing.T, doc string) {
		// Must never panic; a returned doc must have passed schema validation.
		td, err := ParseTrustDoc(strings.NewReader(doc))
		if err == nil && td.Schema != "polypkg.trust/v2" {
			t.Fatalf("accepted doc with schema %q", td.Schema)
		}
	})
}

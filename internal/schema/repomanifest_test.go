package schema

import (
	"strings"
	"testing"
)

func TestParseRepoManifest_Valid(t *testing.T) {
	const in = `schema: polypkg.repo/v1
source: example
output: ./public
key:
  path: keys/example.key
  kdf: scrypt
packages:
  hello:
    source: ./pkgs/hello
`
	m, err := ParseRepoManifest(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ParseRepoManifest: %v", err)
	}
	if m.Source != "example" || m.Output != "./public" {
		t.Fatalf("unexpected manifest: %+v", m)
	}
	if m.Key.KDF != "scrypt" || m.Key.Path != "keys/example.key" {
		t.Fatalf("unexpected key: %+v", m.Key)
	}
	if got := m.Packages["hello"].Source; got != "./pkgs/hello" {
		t.Fatalf("hello source = %q", got)
	}
	if m.Schema != "polypkg.repo/v1" {
		t.Fatalf("schema = %q", m.Schema)
	}
}

func FuzzParseRepoManifest(f *testing.F) {
	f.Add(`schema: polypkg.repo/v1
source: example
output: ./public
key:
  path: keys/example.key
  kdf: scrypt
packages:
  hello:
    source: ./pkgs/hello
`)
	f.Add(`schema: polypkg.repo/v1
source: s
output: ./out
key: {path: k, kdf: scrypt}
`)
	f.Add(`{}`)
	f.Add(``)
	f.Fuzz(func(t *testing.T, s string) {
		// Must never panic; errors are fine.
		_, _ = ParseRepoManifest(strings.NewReader(s))
	})
}

func TestParseRepoManifest_RejectsUnknownField(t *testing.T) {
	const in = `schema: polypkg.repo/v1
source: example
output: ./public
key: {path: k, kdf: scrypt}
bogus: true
`
	if _, err := ParseRepoManifest(strings.NewReader(in)); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestParseRepoManifest_RejectsBadKDF(t *testing.T) {
	const in = `schema: polypkg.repo/v1
source: example
output: ./public
key: {path: k, kdf: argon2}
packages: {}
`
	if _, err := ParseRepoManifest(strings.NewReader(in)); err == nil {
		t.Fatal("expected error for invalid kdf")
	}
}

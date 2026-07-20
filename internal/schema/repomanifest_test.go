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

const prebuiltManifest = `schema: polypkg.repo/v1
source: example
output: ./public
key:
  path: /keys/example.key
  kdf: scrypt
packages:
  hello:
    prebuilt:
      artifact: ./staging/hello.tar.zst
      attestations: ./staging/hello-atts
      trust_bundle: ./staging/trust-bundle.json
`

func TestParseRepoManifestAcceptsPrebuilt(t *testing.T) {
	m, err := ParseRepoManifest(strings.NewReader(prebuiltManifest))
	if err != nil {
		t.Fatalf("parse prebuilt manifest: %v", err)
	}
	p := m.Packages["hello"]
	if p.Source != "" {
		t.Fatalf("prebuilt entry set source = %q, want empty", p.Source)
	}
	if p.Prebuilt == nil {
		t.Fatal("prebuilt entry parsed with nil Prebuilt")
	}
	if p.Prebuilt.Artifact != "./staging/hello.tar.zst" ||
		p.Prebuilt.Attestations != "./staging/hello-atts" ||
		p.Prebuilt.TrustBundle != "./staging/trust-bundle.json" {
		t.Fatalf("prebuilt fields = %+v", *p.Prebuilt)
	}
}

func TestParseRepoManifestAcceptsSourceOnly(t *testing.T) {
	src := `schema: polypkg.repo/v1
source: example
output: ./public
key: {path: /k, kdf: scrypt}
packages:
  hello: {source: ./pkgs/hello}
`
	m, err := ParseRepoManifest(strings.NewReader(src))
	if err != nil {
		t.Fatalf("parse source manifest: %v", err)
	}
	if m.Packages["hello"].Prebuilt != nil {
		t.Fatal("source entry parsed a non-nil Prebuilt")
	}
}

func TestParseRepoManifestRejectsSourceAndPrebuilt(t *testing.T) {
	bad := `schema: polypkg.repo/v1
source: example
output: ./public
key: {path: /k, kdf: scrypt}
packages:
  hello:
    source: ./pkgs/hello
    prebuilt: {artifact: ./a.tar.zst, attestations: ./atts}
`
	if _, err := ParseRepoManifest(strings.NewReader(bad)); err == nil {
		t.Fatal("expected rejection: entry declares both source and prebuilt")
	}
}

func TestParseRepoManifestRejectsNeitherSourceNorPrebuilt(t *testing.T) {
	bad := `schema: polypkg.repo/v1
source: example
output: ./public
key: {path: /k, kdf: scrypt}
packages:
  hello: {}
`
	if _, err := ParseRepoManifest(strings.NewReader(bad)); err == nil {
		t.Fatal("expected rejection: entry declares neither source nor prebuilt")
	}
}

func TestParseRepoManifestRejectsPrebuiltMissingArtifact(t *testing.T) {
	bad := `schema: polypkg.repo/v1
source: example
output: ./public
key: {path: /k, kdf: scrypt}
packages:
  hello:
    prebuilt: {attestations: ./atts}
`
	if _, err := ParseRepoManifest(strings.NewReader(bad)); err == nil {
		t.Fatal("expected rejection: prebuilt missing required artifact")
	}
}

func TestParseRepoManifestRejectsPrebuiltMissingAttestations(t *testing.T) {
	bad := `schema: polypkg.repo/v1
source: example
output: ./public
key: {path: /k, kdf: scrypt}
packages:
  hello:
    prebuilt: {artifact: ./a.tar.zst}
`
	if _, err := ParseRepoManifest(strings.NewReader(bad)); err == nil {
		t.Fatal("expected rejection: prebuilt missing required attestations")
	}
}

func TestParseRepoManifestRejectsUnknownPrebuiltField(t *testing.T) {
	bad := `schema: polypkg.repo/v1
source: example
output: ./public
key: {path: /k, kdf: scrypt}
packages:
  hello:
    prebuilt: {artifact: ./a.tar.zst, attestations: ./atts, bogus: x}
`
	if _, err := ParseRepoManifest(strings.NewReader(bad)); err == nil {
		t.Fatal("expected rejection: unknown prebuilt sub-field")
	}
}

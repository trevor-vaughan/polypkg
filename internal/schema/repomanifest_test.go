package schema

import (
	"slices"
	"strconv"
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
    - source: ./pkgs/hello
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
	if got := m.Packages["hello"][0].Source; got != "./pkgs/hello" {
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
    - source: ./pkgs/hello
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
    - prebuilt:
        artifact: ./staging/hello.tar.zst
        attestations: ./staging/hello-atts
        trust_bundle: ./staging/trust-bundle.json
`

func TestParseRepoManifestAcceptsPrebuilt(t *testing.T) {
	m, err := ParseRepoManifest(strings.NewReader(prebuiltManifest))
	if err != nil {
		t.Fatalf("parse prebuilt manifest: %v", err)
	}
	p := m.Packages["hello"][0]
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

func TestParseRepoManifestAcceptsPrebuiltNativeAttestation(t *testing.T) {
	const in = `schema: polypkg.repo/v1
source: example
output: ./public
key:
  path: /keys/example.key
  kdf: scrypt
packages:
  hello:
    - prebuilt:
        artifact: ./staging/hello.tar.zst
        attestations: ./staging/hello-atts
        native_attestation: some/path.att.json
`
	m, err := ParseRepoManifest(strings.NewReader(in))
	if err != nil {
		t.Fatalf("parse native_attestation manifest: %v", err)
	}
	p := m.Packages["hello"][0]
	if p.Prebuilt == nil {
		t.Fatal("prebuilt entry parsed with nil Prebuilt")
	}
	if p.Prebuilt.NativeAttestation != "some/path.att.json" {
		t.Fatalf("native_attestation = %q, want %q", p.Prebuilt.NativeAttestation, "some/path.att.json")
	}
}

func TestParseRepoManifestAcceptsSourceOnly(t *testing.T) {
	src := `schema: polypkg.repo/v1
source: example
output: ./public
key: {path: /k, kdf: scrypt}
packages:
  hello:
    - {source: ./pkgs/hello}
`
	m, err := ParseRepoManifest(strings.NewReader(src))
	if err != nil {
		t.Fatalf("parse source manifest: %v", err)
	}
	if m.Packages["hello"][0].Prebuilt != nil {
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
    - source: ./pkgs/hello
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
  hello:
    - {}
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
    - prebuilt: {attestations: ./atts}
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
    - prebuilt: {artifact: ./a.tar.zst}
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
    - prebuilt: {artifact: ./a.tar.zst, attestations: ./atts, bogus: x}
`
	if _, err := ParseRepoManifest(strings.NewReader(bad)); err == nil {
		t.Fatal("expected rejection: unknown prebuilt sub-field")
	}
}

// nonSlugSourceNames are repo source names that must never reach a filesystem
// path. `repo build` interpolates the manifest's top-level `source` into the
// build-cache path under --key-dir, so a separator or a `..` segment relocates
// operator secrets outside the directory the operator chose.
var nonSlugSourceNames = []string{
	"../../evilsrc",
	"../r/public/leaked",
	"a/b",
	`a\b`,
	"..",
	".",
	"",
	"https://mymirror.local/repo",
}

func TestParseRepoManifestRejectsNonSlugSource(t *testing.T) {
	for _, src := range nonSlugSourceNames {
		t.Run(src, func(t *testing.T) {
			in := "schema: polypkg.repo/v1\nsource: " + strconv.Quote(src) +
				"\noutput: ./public\nkey: {path: /k, kdf: scrypt}\n"
			_, err := ParseRepoManifest(strings.NewReader(in))
			if err == nil {
				t.Fatalf("expected rejection for source %q", src)
			}
			if !strings.Contains(err.Error(), "is not a valid slug") {
				t.Fatalf("source %q: want a slug error, got %v", src, err)
			}
		})
	}
}

func TestParseRepoManifestAcceptsSlugSourceNames(t *testing.T) {
	for _, src := range []string{"native", "mymirror", "edge", "my-mirror", "my_mirror", "Repo1", "s"} {
		t.Run(src, func(t *testing.T) {
			in := "schema: polypkg.repo/v1\nsource: " + src +
				"\noutput: ./public\nkey: {path: /k, kdf: scrypt}\n"
			m, err := ParseRepoManifest(strings.NewReader(in))
			if err != nil {
				t.Fatalf("source %q must parse: %v", src, err)
			}
			if m.Source != src {
				t.Fatalf("source = %q, want %q", m.Source, src)
			}
		})
	}
}

func TestParseRepoManifestAcceptsSigstoreRoots(t *testing.T) {
	const in = `schema: polypkg.repo/v1
source: example
output: ./public
key: {path: /k, kdf: scrypt}
sigstore_roots:
  - ./imports/sigstore-trusted-root.json
  - /etc/polypkg/staging-trusted-root.json
`
	m, err := ParseRepoManifest(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ParseRepoManifest: %v", err)
	}
	want := []string{"./imports/sigstore-trusted-root.json", "/etc/polypkg/staging-trusted-root.json"}
	if !slices.Equal(m.SigstoreRoots, want) {
		t.Fatalf("SigstoreRoots = %q, want %q", m.SigstoreRoots, want)
	}
}

func TestParseRepoManifestRejectsBadSigstoreRoots(t *testing.T) {
	for name, roots := range map[string]string{
		"empty entry":     "sigstore_roots: ['']\n",
		"duplicate entry": "sigstore_roots: [./a.json, ./a.json]\n",
		"not a list":      "sigstore_roots: ./a.json\n",
		"non-string item": "sigstore_roots: [{path: ./a.json}]\n",
	} {
		t.Run(name, func(t *testing.T) {
			in := "schema: polypkg.repo/v1\nsource: example\noutput: ./public\nkey: {path: /k, kdf: scrypt}\n" + roots
			if _, err := ParseRepoManifest(strings.NewReader(in)); err == nil {
				t.Fatalf("expected rejection for %s", name)
			}
		})
	}
}

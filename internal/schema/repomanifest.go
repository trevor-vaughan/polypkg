package schema

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

//go:embed jsonschema/repo-v1.json
var repoSchemaV1 []byte

// RepoKey describes where the publisher's encrypted signing key lives and how
// it is wrapped.
type RepoKey struct {
	Path string `yaml:"path" json:"path"`
	KDF  string `yaml:"kdf"  json:"kdf"`
}

// RepoPrebuilt describes a pre-built package ingested verbatim: a fetched
// artifact tarball, a directory of its carried attestation blobs, and an
// optional upstream trust bundle to carry forward. Mutually exclusive with
// RepoPackage.Source (repo-v1.json enforces the oneOf).
type RepoPrebuilt struct {
	Artifact     string `yaml:"artifact"                json:"artifact"`
	Attestations string `yaml:"attestations"            json:"attestations"`
	TrustBundle  string `yaml:"trust_bundle,omitempty"  json:"trust_bundle,omitempty"`
	// NativeAttestation is an optional path to a JCS-canonical in-toto SARIF
	// statement (the `pkg build` <name>-<version>.att.json preview) to sign and
	// publish as this prebuilt package's native attestation. Its subject digest
	// must bind the artifact. Absent ⇒ carried attestations only.
	// The build cache keys on the artifact content-hash, so changing only this
	// path without changing the artifact may require a cache-busting rebuild.
	NativeAttestation string `yaml:"native_attestation,omitempty" json:"native_attestation,omitempty"`
}

// RepoPackage is one package registered in a repo manifest: either a local
// source tree (Source) or a pre-built ingest (Prebuilt), never both.
type RepoPackage struct {
	Source   string        `yaml:"source,omitempty"   json:"source,omitempty"`
	Prebuilt *RepoPrebuilt `yaml:"prebuilt,omitempty" json:"prebuilt,omitempty"`
}

// RepoManifest is the declarative description of a polypkg repository
// (polypkg.repo/v1). It is the single source of truth a `repo build` reconciles
// the output directory against.
type RepoManifest struct {
	Schema   string                 `yaml:"schema"             json:"schema"`
	Source   string                 `yaml:"source"             json:"source"`
	Output   string                 `yaml:"output"             json:"output"`
	Key      RepoKey                `yaml:"key"                json:"key"`
	Packages map[string]RepoPackage `yaml:"packages,omitempty" json:"packages,omitempty"`
}

// ParseRepoManifest reads a YAML repo manifest, rejects unknown fields, and
// validates it against the embedded polypkg.repo/v1 JSON Schema.
//
// polypkg-repo.yaml is a checked-in, hand-editable, shared file, so parse time
// is the one place every consumer of it passes through. The top-level `source`
// is checked against SourceNamePattern here — ahead of the schema pass, which
// enforces the same pattern but reports it in JSON Schema terms — because the
// producers interpolate that name straight into the signing-key and
// build-cache paths.
func ParseRepoManifest(r io.Reader) (*RepoManifest, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read repo manifest: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var m RepoManifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("decode repo manifest: %w", err)
	}
	if err := ValidateSourceName(m.Source); err != nil {
		return nil, fmt.Errorf("repo manifest: %w", err)
	}
	jsonBytes, err := json.Marshal(&m)
	if err != nil {
		return nil, fmt.Errorf("marshal for validation: %w", err)
	}
	if err := validateAgainstSchema(jsonBytes, repoSchemaV1, "repo-v1.json"); err != nil {
		return nil, err
	}
	return &m, nil
}

package repo

import (
	"os"
	"path/filepath"

	"github.com/trevor-vaughan/polypkg/internal/schema"
	"gopkg.in/yaml.v3"
)

// InitOptions parameterizes repo scaffolding.
type InitOptions struct {
	Dir      string
	KeyDir   string
	Source   string
	Password string
	KDF      KDF
}

// InitResult reports paths created by InitRepo.
type InitResult struct {
	ManifestPath  string
	KeyPath       string
	TrustRootPath string
}

// InitRepo scaffolds a new repository: creates Dir, generates and encrypts a
// signing key under KeyDir (which must be outside Dir/public), writes
// polypkg-repo.yaml, and exports the public trust root. Refuses to overwrite
// an existing manifest.
func InitRepo(o InitOptions) (InitResult, error) {
	manifestPath := filepath.Join(o.Dir, "polypkg-repo.yaml")
	if _, err := os.Stat(manifestPath); err == nil {
		return InitResult{}, &PublishError{
			Msg:  "a repo manifest already exists here",
			Hint: "edit polypkg-repo.yaml or pick a new directory",
		}
	}

	outputDir := filepath.Join(o.Dir, "public")
	// filepath.Base on the source name keeps a stray separator from relocating
	// the encrypted signing key out of the KeyDir the operator chose. Callers
	// reaching InitRepo through the CLI have already had the name rejected by
	// schema.ValidateSourceName; this is the guard at the interpolation site.
	//
	// Absolute because this path is recorded in the manifest, and manifest
	// paths resolve against the manifest directory while KeyDir is relative to
	// the process working directory. Recording KeyDir verbatim made
	// `repo init ./myrepo --key-dir ./keys` write ./keys/<source>.key and every
	// later command look for ./myrepo/keys/<source>.key. An absolute KeyDir
	// already behaved this way; this makes both forms agree.
	keyPath, kerr := filepath.Abs(filepath.Join(o.KeyDir, filepath.Base(o.Source)+".key"))
	if kerr != nil {
		return InitResult{}, kerr
	}
	if err := guardKeyNotInOutput(outputDir, keyPath, o.KeyDir); err != nil {
		return InitResult{}, err
	}

	if err := os.MkdirAll(o.Dir, 0o755); err != nil { //nolint:gosec // G301: repo root is publicly accessible; 0755 is intentional
		return InitResult{}, err
	}
	if err := os.MkdirAll(o.KeyDir, 0o700); err != nil {
		return InitResult{}, err
	}

	kp, err := GenerateKeypair()
	if err != nil {
		return InitResult{}, err
	}
	if err := SaveKey(keyPath, kp, o.Password, o.KDF); err != nil {
		return InitResult{}, err
	}

	m := &schema.RepoManifest{
		Schema:   "polypkg.repo/v1",
		Source:   o.Source,
		Output:   "./public",
		Key:      schema.RepoKey{Path: keyPath, KDF: string(o.KDF)},
		Packages: map[string]schema.RepoPackage{},
	}
	raw, err := yaml.Marshal(m)
	if err != nil {
		return InitResult{}, err
	}
	if err := writeAtomic(manifestPath, raw); err != nil {
		return InitResult{}, err
	}

	absOut, _ := filepath.Abs(outputDir)
	if err := os.MkdirAll(absOut, 0o755); err != nil { //nolint:gosec // G301: output dir is served over HTTP; 0755 is intentional
		return InitResult{}, err
	}
	trustRootPub := kp.PublicKeyFile("polypkg " + o.Source + " trust root")
	trustRootPath := filepath.Join(absOut, "trust_root.pub")
	if err := os.WriteFile(trustRootPath, []byte(trustRootPub), 0o644); err != nil { //nolint:gosec // G306: trust_root.pub is a public key distributed to clients; 0644 is correct
		return InitResult{}, err
	}

	return InitResult{ManifestPath: manifestPath, KeyPath: keyPath, TrustRootPath: trustRootPath}, nil
}

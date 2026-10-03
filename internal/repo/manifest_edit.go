package repo

import (
	"bytes"
	"os"

	"github.com/trevor-vaughan/polypkg/internal/schema"
	"gopkg.in/yaml.v3"
)

// ManifestEdit is a change to the repo manifest that has been computed but not
// yet written: Manifest is the edited manifest to work against, and Commit
// persists it.
//
// The split exists so a caller can do the work the edit implies BEFORE the edit
// reaches disk. `repo add` and `repo remove` build against Manifest and Commit
// only once that build has succeeded, which is what makes a command that exits
// non-zero leave polypkg-repo.yaml byte-identical (see the invariant note at
// the top of internal/cli/repoaddremove.go).
type ManifestEdit struct {
	// Manifest is the parsed form of the bytes Commit will write, so what a
	// caller builds against is exactly what gets persisted.
	Manifest *schema.RepoManifest

	path string
	body []byte
}

// Commit atomically overwrites the manifest with the edit. Any user-authored
// YAML comments are not preserved because the manifest is machine-managed.
func (e *ManifestEdit) Commit() error { return writeAtomic(e.path, e.body) }

// PlanAddPackage computes the manifest at path with packages.<name>.source
// registered (or updated), writing nothing.
func PlanAddPackage(path, name, source string) (*ManifestEdit, error) {
	m, err := loadManifestForEdit(path)
	if err != nil {
		return nil, err
	}
	if m.Packages == nil {
		m.Packages = map[string]schema.RepoPackage{}
	}
	m.Packages[name] = schema.RepoPackage{Source: source}
	return planEdit(path, m)
}

// PlanRemovePackage computes the manifest at path with packages.<name> dropped,
// writing nothing. It errors if the package is not registered.
func PlanRemovePackage(path, name string) (*ManifestEdit, error) {
	m, err := loadManifestForEdit(path)
	if err != nil {
		return nil, err
	}
	if _, ok := m.Packages[name]; !ok {
		return nil, &PublishError{
			Msg:  "package " + name + " is not in the repo manifest",
			Hint: "run `polypkg repo status` to list registered packages",
		}
	}
	delete(m.Packages, name)
	return planEdit(path, m)
}

// planEdit renders the edited manifest to the bytes Commit will write and
// re-parses those bytes. Round-tripping rather than keeping the in-memory value
// buys two things: the manifest a caller builds against is the one that will be
// persisted, not a pre-serialization copy of it; and an edit that would produce
// a manifest the schema rejects fails here, before any work is done on it.
func planEdit(path string, m *schema.RepoManifest) (*ManifestEdit, error) {
	body, err := yaml.Marshal(m)
	if err != nil {
		return nil, err
	}
	parsed, err := schema.ParseRepoManifest(bytes.NewReader(body))
	if err != nil {
		return nil, &PublishError{
			Msg:  "the edited repo manifest is not valid",
			Hint: "check polypkg-repo.yaml against the polypkg.repo/v1 schema",
			Err:  err,
		}
	}
	return &ManifestEdit{Manifest: parsed, path: path, body: body}, nil
}

func loadManifestForEdit(path string) (*schema.RepoManifest, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is user-supplied manifest location
	if err != nil {
		return nil, &PublishError{
			Msg:  "cannot open repo manifest",
			Hint: "run `polypkg repo init <dir>` first",
			Err:  err,
		}
	}
	defer func() { _ = f.Close() }()
	return schema.ParseRepoManifest(f)
}

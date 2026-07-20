package repo

import (
	"os"

	"github.com/trevor-vaughan/polypkg/internal/schema"
	"gopkg.in/yaml.v3"
)

// AddPackage registers (or updates) a package source in the manifest at path.
func AddPackage(path, name, source string) error {
	m, err := loadManifestForEdit(path)
	if err != nil {
		return err
	}
	if m.Packages == nil {
		m.Packages = map[string]schema.RepoPackage{}
	}
	m.Packages[name] = schema.RepoPackage{Source: source}
	return saveManifest(path, m)
}

// RemovePackage drops a package from the manifest, erroring if it is absent.
func RemovePackage(path, name string) error {
	m, err := loadManifestForEdit(path)
	if err != nil {
		return err
	}
	if _, ok := m.Packages[name]; !ok {
		return &PublishError{
			Msg:  "package " + name + " is not in the repo manifest",
			Hint: "run `polypkg repo status` to list registered packages",
		}
	}
	delete(m.Packages, name)
	return saveManifest(path, m)
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

// saveManifest re-marshals m to YAML and atomically overwrites path; any
// user-authored YAML comments are not preserved because the manifest is
// machine-managed.
func saveManifest(path string, m *schema.RepoManifest) error {
	raw, err := yaml.Marshal(m)
	if err != nil {
		return err
	}
	return writeAtomic(path, raw)
}

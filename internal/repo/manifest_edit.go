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

// PackageAdd is one package source for PlanAddPackage to register: the name
// its polypkg.yaml declares and its source directory as the manifest stores it.
type PackageAdd struct {
	Name   string
	Source string
}

// PlanAddPackage computes the manifest at path with every add registered, in
// order, writing nothing. Entries are deduplicated by source path: re-adding
// the same path updates that entry in place, a new path appends a version. One
// edit can therefore register several builds of one package (one per
// platform) as well as several packages, and the caller reconciles them all
// against a single manifest.
//
// Deduplicating by source rather than by version keeps this function free of
// I/O — reading a version means parsing the source tree, or extracting a
// prebuilt artifact. Two entries declaring the same version is therefore
// possible here and is rejected by Build, which already parses every entry.
func PlanAddPackage(path string, adds ...PackageAdd) (*ManifestEdit, error) {
	m, err := loadManifestForEdit(path)
	if err != nil {
		return nil, err
	}
	if m.Packages == nil {
		m.Packages = map[string][]schema.RepoPackage{}
	}
	for _, a := range adds {
		entries := m.Packages[a.Name]
		replaced := false
		for i := range entries {
			if entries[i].Source == a.Source {
				entries[i] = schema.RepoPackage{Source: a.Source}
				replaced = true
				break
			}
		}
		if !replaced {
			entries = append(entries, schema.RepoPackage{Source: a.Source})
		}
		m.Packages[a.Name] = entries
	}
	return planEdit(path, m)
}

// PlanRemovePackage computes the manifest at path with every entry for name
// dropped, writing nothing. It errors if the package is not registered.
func PlanRemovePackage(path, name string) (*ManifestEdit, error) {
	m, err := loadManifestForEdit(path)
	if err != nil {
		return nil, err
	}
	if len(m.Packages[name]) == 0 {
		return nil, &PublishError{
			Msg:  "package " + name + " is not in the repo manifest",
			Hint: "run `polypkg repo status` to list registered packages",
		}
	}
	delete(m.Packages, name)
	return planEdit(path, m)
}

// PlanRemovePackageSource computes the manifest at path with one entry per
// identifier dropped from name, writing nothing. `repo remove name@version`
// passes every entry that builds the version (one per platform for a
// per-platform release). Removing the last entry deletes the name: the schema
// requires at least one entry per name, so an empty list would not round-trip.
// Every identifier must match an entry; otherwise nothing is planned, so a
// version is never left half-withdrawn.
//
// An identifier is matched against EntryIdentifier(e): a source entry's
// Source, or a prebuilt entry's artifact path. Both are manifest-authored
// strings, so one string per entry covers either kind without the caller
// needing to know which one a given entry is — the caller (runRepoRemove)
// learns the identifiers the same way it learns the versions, by reading them
// off the entries EntryVersion resolved.
func PlanRemovePackageSource(path, name string, identifiers ...string) (*ManifestEdit, error) {
	m, err := loadManifestForEdit(path)
	if err != nil {
		return nil, err
	}
	pending := make(map[string]int, len(identifiers))
	for _, id := range identifiers {
		pending[id]++
	}
	entries := m.Packages[name]
	kept := make([]schema.RepoPackage, 0, len(entries))
	for _, e := range entries {
		if id := EntryIdentifier(e); pending[id] > 0 {
			pending[id]--
			continue
		}
		kept = append(kept, e)
	}
	for _, id := range identifiers {
		if pending[id] > 0 {
			return nil, &PublishError{
				Msg:  "package " + name + " has no entry with source " + id,
				Hint: "run `polypkg repo status` to list registered packages",
			}
		}
	}
	if len(kept) == 0 {
		delete(m.Packages, name)
	} else {
		m.Packages[name] = kept
	}
	return planEdit(path, m)
}

// EntryIdentifier returns the manifest-authored path that identifies a
// package entry: a source entry's Source, or a prebuilt entry's artifact
// path. The two are mutually exclusive (schema oneOf), so exactly one is
// non-empty. Exported so callers resolving "@<version>" (internal/cli) can
// recover the identifier for the entry EntryVersion matched, without
// reimplementing the Source/Prebuilt branch.
func EntryIdentifier(e schema.RepoPackage) string {
	if e.Prebuilt != nil {
		return e.Prebuilt.Artifact
	}
	return e.Source
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

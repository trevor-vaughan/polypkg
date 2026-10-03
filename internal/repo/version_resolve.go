package repo

import (
	"bytes"
	"fmt"
	"os"

	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/source"
)

// EntryVersion returns the version one manifest entry builds, resolving paths
// against manifestDir.
//
// A source entry costs one YAML read. A prebuilt entry has no version field of
// its own — the version lives inside the artifact — so resolving it costs a
// full extraction (mirrors ingestPackage's extraction, but without the cache
// ingestPackage has, since EntryVersion runs before a build ever starts). That
// is acceptable here: the only caller is `repo remove name@version`, a rare
// interactive command that stops at the first entry whose version matches.
func EntryVersion(manifestDir string, pkg schema.RepoPackage) (string, error) {
	if pkg.Prebuilt == nil {
		p, err := ReadPackageSource(resolveRel(manifestDir, pkg.Source))
		if err != nil {
			return "", &PublishError{
				Msg:  fmt.Sprintf("cannot read package source %s", pkg.Source),
				Hint: "check that the path in polypkg-repo.yaml exists and holds a polypkg.yaml",
				Err:  err,
			}
		}
		return p.Version, nil
	}

	artPath := resolveRel(manifestDir, pkg.Prebuilt.Artifact)
	artifact, err := os.ReadFile(artPath) //nolint:gosec // G304: operator-declared prebuilt artifact
	if err != nil {
		return "", &PublishError{
			Msg:  fmt.Sprintf("cannot read prebuilt artifact %s", pkg.Prebuilt.Artifact),
			Hint: "check packages.<name>.prebuilt.artifact in polypkg-repo.yaml",
			Err:  err,
		}
	}

	// The version is only inside the artifact, so extract it into a scratch dir
	// and read it back out.
	scratch, err := os.MkdirTemp("", "polypkg-version-resolve-*")
	if err != nil {
		return "", fmt.Errorf("create version-resolve scratch dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	if err := source.ExtractTarZst(bytes.NewReader(artifact), scratch); err != nil {
		return "", &PublishError{
			Msg:  fmt.Sprintf("cannot extract prebuilt artifact %s", pkg.Prebuilt.Artifact),
			Hint: "the prebuilt artifact must be a polypkg .tar.zst (polypkg.yaml + content/**)",
			Err:  err,
		}
	}
	p, err := ReadPackageSource(scratch)
	if err != nil {
		return "", &PublishError{
			Msg: fmt.Sprintf("prebuilt artifact %s has no valid polypkg.yaml", pkg.Prebuilt.Artifact), Err: err,
		}
	}
	return p.Version, nil
}

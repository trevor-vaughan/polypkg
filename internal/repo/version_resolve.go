package repo

import (
	"bytes"
	"fmt"
	"os"

	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/source"
)

// EntryVersion returns the version one manifest entry builds and the platform
// it targets ("" for platform-agnostic), resolving paths against manifestDir.
//
// A source entry costs one YAML read. A prebuilt entry has no version or
// platform field of its own — both live inside the artifact — so resolving it
// costs a full extraction (mirrors ingestPackage's extraction, but without the
// cache ingestPackage has, since EntryVersion runs before a build ever starts).
// That is acceptable here: the only caller is `repo remove name@version`, a
// rare interactive command.
func EntryVersion(manifestDir string, pkg schema.RepoPackage) (version, platform string, err error) {
	if pkg.Prebuilt == nil {
		p, rerr := ReadPackageSource(resolveRel(manifestDir, pkg.Source))
		if rerr != nil {
			return "", "", &PublishError{
				Msg:  fmt.Sprintf("cannot read package source %s", pkg.Source),
				Hint: "check that the path in polypkg-repo.yaml exists and holds a polypkg.yaml",
				Err:  rerr,
			}
		}
		return p.Version, p.Platform, nil
	}

	artPath := resolveRel(manifestDir, pkg.Prebuilt.Artifact)
	artifact, rerr := os.ReadFile(artPath) //nolint:gosec // G304: operator-declared prebuilt artifact
	if rerr != nil {
		return "", "", &PublishError{
			Msg:  fmt.Sprintf("cannot read prebuilt artifact %s", pkg.Prebuilt.Artifact),
			Hint: "check packages.<name>.prebuilt.artifact in polypkg-repo.yaml",
			Err:  rerr,
		}
	}

	// The version and platform are only inside the artifact, so extract it
	// into a scratch dir and read them back out.
	scratch, rerr := os.MkdirTemp("", "polypkg-version-resolve-*")
	if rerr != nil {
		return "", "", fmt.Errorf("create version-resolve scratch dir: %w", rerr)
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	if xerr := source.ExtractTarZst(bytes.NewReader(artifact), scratch); xerr != nil {
		return "", "", &PublishError{
			Msg:  fmt.Sprintf("cannot extract prebuilt artifact %s", pkg.Prebuilt.Artifact),
			Hint: "the prebuilt artifact must be a polypkg .tar.zst (polypkg.yaml + content/**)",
			Err:  xerr,
		}
	}
	p, rerr := ReadPackageSource(scratch)
	if rerr != nil {
		return "", "", &PublishError{
			Msg: fmt.Sprintf("prebuilt artifact %s has no valid polypkg.yaml", pkg.Prebuilt.Artifact), Err: rerr,
		}
	}
	return p.Version, p.Platform, nil
}

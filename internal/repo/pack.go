package repo

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/trevor-vaughan/polypkg/internal/archive"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// ReadPackageSource parses the polypkg.yaml at the root of a package source dir.
func ReadPackageSource(dir string) (*schema.Package, error) {
	f, err := os.Open(filepath.Join(dir, "polypkg.yaml")) //nolint:gosec // G304: dir is the package source directory supplied by the operator
	if err != nil {
		return nil, fmt.Errorf("open package manifest: %w", err)
	}
	defer func() { _ = f.Close() }()
	// ParsePackage uses the name arg to select the parser format;
	// "" selects YAML (the default), which is what polypkg.yaml requires.
	// Name and version are read from the YAML content itself.
	pkg, err := schema.ParsePackage(f, "")
	if err != nil {
		return nil, fmt.Errorf("parse package manifest in %s: %w", dir, err)
	}
	if pkg.Name == "" || pkg.Version == "" {
		return nil, fmt.Errorf("package manifest in %s must set name and version", dir)
	}
	return pkg, nil
}

// PackRefusal is PackArtifact refusing a package source for what it holds
// rather than for an I/O failure: Msg says which file and why, as a sentence
// for the author, with untrusted names quoted; Hint says what to change.
type PackRefusal struct {
	Msg  string
	Hint string
}

func (e *PackRefusal) Error() string { return e.Msg + "; " + e.Hint }

// PackArtifact packs polypkg.yaml + content/** from dir into a deterministic
// tar.zst (sorted paths, zeroed mtime/uid/gid) and returns the bytes plus the
// parsed package manifest. Determinism keeps the content hash stable across
// rebuilds of unchanged sources. Callers use pkg.Name, pkg.Version, and the
// relation slices (Depends/Provides/Conflicts/Obsoletes) directly.
func PackArtifact(dir string) (artifact []byte, pkg *schema.Package, err error) {
	pkg, err = ReadPackageSource(dir)
	if err != nil {
		return nil, nil, err
	}

	type entry struct {
		arcName string
		abs     string
		mode    int64
	}
	var entries []entry
	entries = append(entries, entry{arcName: "polypkg.yaml", abs: filepath.Join(dir, "polypkg.yaml"), mode: 0o644})

	contentRoot := filepath.Join(dir, "content")
	if _, statErr := os.Stat(contentRoot); statErr == nil {
		walkErr := filepath.WalkDir(contentRoot, func(p string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if d.IsDir() {
				return nil
			}
			rel, relErr := filepath.Rel(dir, p)
			if relErr != nil {
				return relErr
			}
			if err := archive.CheckNameBounds(filepath.ToSlash(rel)); err != nil {
				hint := "shorten the path under content/ (fewer or shorter directory names) and build again"
				if errors.Is(err, archive.ErrNameNotUTF8) {
					hint = "rename it, and any directory above it, to valid UTF-8 and build again"
				}
				return &PackRefusal{Msg: fmt.Sprintf("%v, so no install could extract it", err), Hint: hint}
			}
			if d.Type()&fs.ModeType != 0 {
				return &PackRefusal{
					Msg:  fmt.Sprintf("%q is not a regular file (symlinks and special files are not supported)", filepath.ToSlash(rel)),
					Hint: "replace it with a regular file, or remove it from content/, and build again",
				}
			}
			info, infoErr := d.Info()
			if infoErr != nil {
				return infoErr
			}
			// Perm() below would silently drop these bits, and install would
			// refuse an artifact that kept them (a prebuilt one, say), so a
			// package never carries them.
			if special := archive.SpecialBits(info.Mode()); special != "" {
				return &PackRefusal{
					Msg:  fmt.Sprintf("%q is %s; a package cannot carry setuid, setgid or sticky bits", filepath.ToSlash(rel), special),
					Hint: "clear them (chmod u-s,g-s,-t) and build again",
				}
			}
			// Every install unpacks the artifact under this per-member limit,
			// so a larger file would publish a package that can never install.
			if limit := archive.DefaultLimits().MaxFileBytes; info.Size() > limit {
				return &PackRefusal{
					Msg: fmt.Sprintf("%q is %d bytes; package members are limited to %d GiB, so the package could never install",
						filepath.ToSlash(rel), info.Size(), limit>>30),
					Hint: "remove the file from content/ or make it smaller, and build again",
				}
			}
			entries = append(entries, entry{arcName: filepath.ToSlash(rel), abs: p, mode: int64(info.Mode().Perm())})
			return nil
		})
		if walkErr != nil {
			return nil, nil, fmt.Errorf("walk content: %w", walkErr)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].arcName < entries[j].arcName })
	names := make([]string, len(entries))
	for i, en := range entries {
		names[i] = en.arcName
	}
	if n, limit := extractedEntries(names), archive.DefaultLimits().MaxEntries; n > limit {
		return nil, nil, &PackRefusal{
			Msg:  fmt.Sprintf("the package holds %d entries (files and the directories that hold them); packages are limited to %d, so the package could never install", n, limit),
			Hint: "reduce the number of files and directories under content/ and build again",
		}
	}

	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	// zeroTime ensures PAX format does not embed real timestamps, which would
	// break byte-for-byte determinism across rebuilds.
	zeroTime := time.Time{}
	for _, en := range entries {
		body, readErr := os.ReadFile(en.abs)
		if readErr != nil {
			return nil, nil, fmt.Errorf("read %s: %w", en.arcName, readErr)
		}
		hdr := &tar.Header{
			Name:       en.arcName,
			Mode:       en.mode,
			Size:       int64(len(body)),
			Format:     tar.FormatPAX,
			ModTime:    zeroTime,
			AccessTime: zeroTime,
			ChangeTime: zeroTime,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, nil, err
		}
		if _, err := tw.Write(body); err != nil {
			return nil, nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, nil, err
	}

	var z bytes.Buffer
	enc, err := zstd.NewWriter(&z)
	if err != nil {
		return nil, nil, err
	}
	if _, err := enc.Write(raw.Bytes()); err != nil {
		return nil, nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, nil, err
	}
	return z.Bytes(), pkg, nil
}

// extractedEntries is how many entries extracting a package whose members
// are names counts against archive.Limits.MaxEntries: every member, plus every
// directory extraction creates as an implicit parent. PackArtifact writes no
// directory members, so each parent directory is one implicit entry.
func extractedEntries(names []string) int {
	dirs := map[string]bool{}
	for _, n := range names {
		for d := path.Dir(n); d != "."; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	return len(names) + len(dirs)
}

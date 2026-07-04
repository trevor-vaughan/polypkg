package repo

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/trevor-vaughan/polypkg/internal/attest"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// carriedBinding is the result of binding one carried attestation envelope: the
// fields for its AttestationRef plus the link materials for the targets it
// covers.
type carriedBinding struct {
	PredicateType  string
	Format         string
	SubjectScope   string            // "artifact" | "content:<path>" — the first bound subject
	SubjectDigests map[string]string // the first bound subject's advisory digests
	Materials      []attest.LinkMaterial
}

// bindCarried parses a carried attestation envelope (DSSE-wrapped or bare
// in-toto) and binds its subjects, BY DIGEST, against the packed artifact and
// each content file under srcDir/content. The subject NAME is advisory —
// selection is by digest (threat G5) — via attest.MatchSubjectDigests at the
// sha256 floor. It errors if no subject binds (the provenance describes nothing
// polypkg packed). It does NOT verify the builder signature (that is 2c).
func bindCarried(srcDir string, artifact, carried []byte) (carriedBinding, error) {
	predicateType, format, subjects, err := attest.ExtractCarriedSubjects(carried)
	if err != nil {
		return carriedBinding{}, err
	}
	targets, err := carriedTargets(srcDir, artifact)
	if err != nil {
		return carriedBinding{}, err
	}
	materials, err := attest.BindSubjects(subjects, targets)
	if err != nil {
		return carriedBinding{}, fmt.Errorf("carried attestation (%s) binds nothing polypkg packed: no subject digest matches the artifact or any content file", format)
	}
	return carriedBinding{
		PredicateType:  predicateType,
		Format:         format,
		SubjectScope:   materials[0].Name,
		SubjectDigests: materials[0].Digest,
		Materials:      materials,
	}, nil
}

// carriedTargets assembles the pack-time binding targets: the packed artifact
// (scope "artifact") first, then each regular file under srcDir/content by
// sorted relative path (scope "content:<rel>"). Non-regular entries (symlinks,
// etc.) are skipped — a provenance subject must be concrete bytes, never a
// redirect — so a subject pointed at one cannot bind (fail closed).
func carriedTargets(srcDir string, artifact []byte) ([]attest.Target, error) {
	targets := []attest.Target{{Scope: "artifact", Bytes: artifact}}
	contentRoot := filepath.Join(srcDir, "content")
	if _, statErr := os.Stat(contentRoot); statErr != nil {
		if os.IsNotExist(statErr) {
			return targets, nil
		}
		return nil, fmt.Errorf("stat content for binding: %w", statErr)
	}
	walkErr := filepath.WalkDir(contentRoot, func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() || d.Type()&fs.ModeType != 0 {
			return nil
		}
		rel, relErr := filepath.Rel(contentRoot, p)
		if relErr != nil {
			return relErr
		}
		body, readErr := os.ReadFile(p) //nolint:gosec // G304: p is under the operator's package source content tree
		if readErr != nil {
			return readErr
		}
		targets = append(targets, attest.Target{Scope: "content:" + filepath.ToSlash(rel), Bytes: body})
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("walk content for binding: %w", walkErr)
	}
	return targets, nil
}

// discoverCarried returns the sorted paths of carried attestation files in
// srcDir/attestations (top-level *.json only). A missing dir yields no files.
func discoverCarried(srcDir string) ([]string, error) {
	attDir := filepath.Join(srcDir, "attestations")
	ents, err := os.ReadDir(attDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read attestations dir: %w", err)
	}
	var files []string
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		files = append(files, filepath.Join(attDir, e.Name()))
	}
	sort.Strings(files)
	return files, nil
}

// attRefLess orders attestation refs deterministically for a stable published
// index: by content hash (unique per blob), a total order over distinct blobs,
// so no-op rebuilds keep byte-identical ref lists.
func attRefLess(a, b schema.AttestationRef) bool { return a.ContentHash < b.ContentHash }

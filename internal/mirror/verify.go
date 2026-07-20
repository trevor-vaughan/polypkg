// Package mirror verifies offline repository mirror bundles produced by
// `polypkg repo export-bundle`. Verification checks the signed completeness
// manifest, freshness (with optional accept_expiry_until grace), and that every
// listed blob is present and byte-identical — and that no un-listed file was
// smuggled in.
package mirror

import (
	"archive/tar"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"lukechampine.com/blake3"

	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

const (
	manifestName    = "pool-manifest.json"
	manifestSigName = "pool-manifest.json.minisig"
	trustRootName   = "trust_root.pub"
)

// VerifyOptions configures a bundle verification.
type VerifyOptions struct {
	// TrustRootPath, when set, pins the trust_root.pub the manifest signature is
	// checked against (authenticity). When empty, the bundle's carried
	// trust_root.pub is used (integrity/self-consistency only).
	TrustRootPath string
	// AcceptExpiryUntil is an optional RFC3339 freshness-grace ceiling for a
	// frozen mirror whose manifest has expired (phase 2e-1 semantics).
	AcceptExpiryUntil string
}

// VerifyResult summarizes a successful verification.
type VerifyResult struct {
	Source         string
	Serial         uint64
	Expires        string
	EntriesChecked int
	Graced         bool
}

// VerifyBundle verifies a mirror bundle tarball. It returns an error naming the
// first missing, tampered, or un-listed file, or an expired manifest past grace.
func VerifyBundle(tarPath string, opts VerifyOptions) (VerifyResult, error) {
	files, err := readTar(tarPath)
	if err != nil {
		return VerifyResult{}, err
	}
	manifestBytes, ok := files[manifestName]
	if !ok {
		return VerifyResult{}, fmt.Errorf("bundle is missing %s", manifestName)
	}
	sigBytes, ok := files[manifestSigName]
	if !ok {
		return VerifyResult{}, fmt.Errorf("bundle is missing %s", manifestSigName)
	}

	rootPub, err := resolveRoot(opts.TrustRootPath, files)
	if err != nil {
		return VerifyResult{}, err
	}
	if err := trust.Verify(rootPub, manifestBytes, string(sigBytes)); err != nil {
		return VerifyResult{}, fmt.Errorf("pool manifest signature: %w", err)
	}
	m, err := schema.ParsePoolManifest(bytes.NewReader(manifestBytes))
	if err != nil {
		return VerifyResult{}, err
	}
	graced, err := trust.CheckExpiry("pool manifest", m.Expires, opts.AcceptExpiryUntil)
	if err != nil {
		return VerifyResult{}, err
	}

	listed := make(map[string]struct{}, len(m.Entries))
	for _, e := range m.Entries {
		body, present := files[e.Path]
		if !present {
			return VerifyResult{}, fmt.Errorf("bundle is missing manifest entry %q (kind %s)", e.Path, e.Kind)
		}
		if got := contentHash(body); got != e.ContentHash {
			return VerifyResult{}, fmt.Errorf("bundle entry %q content hash mismatch: manifest %s, actual %s", e.Path, e.ContentHash, got)
		}
		listed[e.Path] = struct{}{}
	}
	// No un-listed file may ride along under a signed manifest.
	for name := range files {
		if name == manifestName || name == manifestSigName {
			continue
		}
		if _, ok := listed[name]; !ok {
			return VerifyResult{}, fmt.Errorf("bundle contains file %q not covered by the signed manifest", name)
		}
	}
	return VerifyResult{Source: m.Source, Serial: m.Serial, Expires: m.Expires, EntriesChecked: len(m.Entries), Graced: graced}, nil
}

func resolveRoot(pinnedPath string, files map[string][]byte) (string, error) {
	if pinnedPath != "" {
		data, err := os.ReadFile(filepath.Clean(pinnedPath))
		if err != nil {
			return "", fmt.Errorf("read --trust-root: %w", err)
		}
		return string(data), nil
	}
	embedded, ok := files[trustRootName]
	if !ok {
		return "", fmt.Errorf("bundle has no %s and no --trust-root was given", trustRootName)
	}
	return string(embedded), nil
}

func contentHash(b []byte) string {
	h := blake3.New(32, nil)
	_, _ = h.Write(b)
	return "blake3:" + hex.EncodeToString(h.Sum(nil))
}

// readTar loads all regular-file entries into a name->bytes map, rejecting
// path-traversal names and duplicate paths.
func readTar(path string) (map[string][]byte, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("open bundle: %w", err)
	}
	defer func() { _ = f.Close() }()
	tr := tar.NewReader(f)
	files := make(map[string][]byte)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read bundle tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("bundle contains non-regular member %q (tar type %q); mirror bundles must contain regular files only", hdr.Name, string(hdr.Typeflag))
		}
		name := filepath.Clean(hdr.Name)
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") {
			return nil, fmt.Errorf("bundle contains unsafe path %q", hdr.Name)
		}
		if _, dup := files[name]; dup {
			return nil, fmt.Errorf("bundle contains duplicate path %q", hdr.Name)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("read bundle entry %q: %w", hdr.Name, err)
		}
		files[name] = body
	}
	return files, nil
}

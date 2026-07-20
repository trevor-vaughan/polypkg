package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Compile-time assertions that NativeBackend satisfies Backend and the
// optional ArtifactRefetcher capability.
var (
	_ Backend           = (*NativeBackend)(nil)
	_ ArtifactRefetcher = (*NativeBackend)(nil)
)

const (
	// maxArtifactBytes caps an artifact download so a hostile or compromised
	// mirror cannot exhaust memory before the signature is even verified.
	maxArtifactBytes int64 = 2 << 30 // 2 GiB
	// maxSignatureBytes caps a signature download; a minisig is a few hundred
	// bytes, so this is generous while still bounded.
	maxSignatureBytes int64 = 64 << 10 // 64 KiB
	// maxIndexBytes caps the source index download (pre-verification).
	maxIndexBytes int64 = 16 << 20 // 16 MiB
	// maxTrustDocBytes caps the trust-document download (pre-verification).
	maxTrustDocBytes int64 = 1 << 20 // 1 MiB
	// maxRevocationBytes caps the revocation-list download (pre-verification).
	maxRevocationBytes int64 = 1 << 20 // 1 MiB (revocation list; same bound as trust doc)
)

// transport fetches a named repository file, size-bounded.
type transport interface {
	get(ctx context.Context, name string, limit int64) ([]byte, error)
}

// httpTransport fetches files over HTTP/HTTPS from a base URL.
type httpTransport struct {
	base   string
	client *http.Client
}

func (t *httpTransport) get(ctx context.Context, name string, limit int64) ([]byte, error) {
	rawURL := fmt.Sprintf("%s/%s", t.base, name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, newNetworkFetchError("native", t.base, rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, newStatusFetchError("native", t.base, rawURL, resp.StatusCode)
	}
	data, err := readLimited(resp.Body, limit)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	return data, nil
}

// localTransport fetches files from a local filesystem directory.
type localTransport struct {
	root string
}

func (t *localTransport) get(_ context.Context, name string, limit int64) ([]byte, error) {
	clean := filepath.Clean(filepath.Join(t.root, name))

	// Security: reject any name that escapes root. filepath.Rel returns a path
	// starting with ".." when clean is outside root, so any such prefix means
	// path traversal was attempted.
	//
	// This guard is lexical only: it inspects the cleaned path string, not the
	// resolved inode. A symlink *inside* root that points outside it is still
	// followed by os.Open below. That is acceptable because root is the
	// operator's own local source directory (configured as a file:// URL or
	// absolute path); callers must trust the contents of root itself.
	rel, err := filepath.Rel(t.root, clean)
	if err != nil || strings.HasPrefix(rel, "..") {
		return nil, fmt.Errorf("path %q escapes source root", name)
	}

	f, err := os.Open(clean)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, newStatusFetchError("native", t.root, clean, http.StatusNotFound)
		}
		return nil, fmt.Errorf("open %s: %w", clean, err)
	}
	defer func() { _ = f.Close() }()

	data, err := readLimited(f, limit)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", clean, err)
	}
	return data, nil
}

// NativeBackendOpts configures a NativeBackend.
type NativeBackendOpts struct {
	URL      string
	CacheDir string
}

// NativeBackend fetches packages from an HTTPS-served polypkg repo
// with on-disk caching, or from a local filesystem directory (cache-bypassed).
type NativeBackend struct {
	transport   transport
	cacheDir    string
	localSource bool
}

// NewNativeBackend constructs a NativeBackend. When the URL is a local path
// (absolute or file://) the backend reads directly from the filesystem and
// bypasses the on-disk cache. Otherwise it fetches over HTTP/HTTPS with a
// client derived from the standard transport (preserving proxy, dial, and
// TLS-handshake timeouts) with an added response-header timeout so a stalled
// server cannot hang an apply indefinitely when the caller's context has no
// deadline.
func NewNativeBackend(opts NativeBackendOpts) *NativeBackend {
	if root, ok := isLocalSourceURL(opts.URL); ok {
		return &NativeBackend{
			transport:   &localTransport{root: root},
			cacheDir:    opts.CacheDir,
			localSource: true,
		}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = 30 * time.Second
	return &NativeBackend{
		transport: &httpTransport{
			base:   opts.URL,
			client: &http.Client{Transport: tr},
		},
		cacheDir:    opts.CacheDir,
		localSource: false,
	}
}

// isLocalSourceURL reports whether rawURL identifies a local filesystem
// directory and returns its root path. It recognises:
//   - file:// URLs  (file:///a/b → /a/b)
//   - bare absolute paths (/abs/path)
//
// http/https URLs and bare relative paths return ("", false).
func isLocalSourceURL(rawURL string) (root string, ok bool) {
	if strings.HasPrefix(rawURL, "file://") {
		u, err := url.Parse(rawURL)
		if err != nil || u.Path == "" {
			return "", false
		}
		// A non-empty host other than "localhost" means the URL has the form
		// file://host/path. normalizeSourceURL rejects these at config time, but
		// guard here so we never silently read a local path the operator did not
		// name (the host would be discarded and u.Path would be the wrong dir).
		if u.Host != "" && u.Host != "localhost" {
			return "", false
		}
		return u.Path, true
	}
	if strings.HasPrefix(rawURL, "/") {
		return rawURL, true
	}
	return "", false
}

// readLimited reads from r up to limit bytes, returning an error if the source
// would exceed limit. It reads one byte past the limit to distinguish "exactly
// at the limit" (allowed) from "over the limit" (rejected).
func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response exceeds %d-byte limit", limit)
	}
	return data, nil
}

// Name returns the backend's identifier.
func (b *NativeBackend) Name() string { return "native" }

// Fetch retrieves the package artifact at the index-supplied relative path.
// For local sources the directory is read directly (no cache) so rebuilt
// repos are always served fresh. For HTTP sources the on-disk cache is
// checked first; a miss downloads, stores, and returns.
func (b *NativeBackend) Fetch(ctx context.Context, artifact string) ([]byte, error) {
	if b.localSource {
		return b.transport.get(ctx, artifact, maxArtifactBytes)
	}

	cachePath := filepath.Clean(filepath.Join(b.cacheDir, filepath.Base(artifact)))

	if data, err := os.ReadFile(cachePath); err == nil {
		return data, nil
	}

	data, err := b.transport.get(ctx, artifact, maxArtifactBytes)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(b.cacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir cache: %w", err)
	}
	tmp := cachePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return nil, fmt.Errorf("write cache tmp: %w", err)
	}
	if err := os.Rename(tmp, cachePath); err != nil {
		return nil, fmt.Errorf("rename cache: %w", err)
	}

	return data, nil
}

// RefetchArtifact discards any cached copy of artifact and fetches it fresh.
// The planner calls this when cached bytes fail signature or hash
// verification: the cache is keyed by base name only, so a repository that
// republishes different bytes under the same path (hand-rolled layouts;
// polypkg's own pool is content-addressed) would otherwise wedge the client
// on the stale entry forever.
func (b *NativeBackend) RefetchArtifact(ctx context.Context, artifact string) ([]byte, error) {
	if !b.localSource {
		cachePath := filepath.Clean(filepath.Join(b.cacheDir, filepath.Base(artifact)))
		if err := os.Remove(cachePath); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("evict cached artifact %s: %w", cachePath, err)
		}
	}
	return b.Fetch(ctx, artifact)
}

// FetchIndex retrieves index.json (size-bounded) and its detached minisign
// signature. For HTTP sources the index is cached to disk. For local sources
// the cache write is skipped. The caller verifies the signature before parsing.
func (b *NativeBackend) FetchIndex(ctx context.Context) (index []byte, signature string, err error) {
	raw, err := b.transport.get(ctx, "index.json", maxIndexBytes)
	if err != nil {
		return nil, "", err
	}
	if !b.localSource {
		if err := os.MkdirAll(b.cacheDir, 0o700); err != nil {
			return nil, "", fmt.Errorf("mkdir cache: %w", err)
		}
		cachePath := filepath.Clean(filepath.Join(b.cacheDir, "index.json"))
		tmp := cachePath + ".tmp"
		if err := os.WriteFile(tmp, raw, 0o600); err != nil {
			return nil, "", fmt.Errorf("write index cache tmp: %w", err)
		}
		if err := os.Rename(tmp, cachePath); err != nil {
			return nil, "", fmt.Errorf("rename index cache: %w", err)
		}
	}
	sig, err := b.transport.get(ctx, "index.json.minisig", maxSignatureBytes)
	if err != nil {
		return nil, "", err
	}
	return raw, string(sig), nil
}

// FetchTrustDoc retrieves trust.json (size-bounded) and its detached minisign
// signature. For HTTP sources the document is cached to disk. For local sources
// the cache write is skipped. The caller verifies the signature before parsing.
func (b *NativeBackend) FetchTrustDoc(ctx context.Context) (raw []byte, sig string, err error) {
	doc, err := b.transport.get(ctx, "trust.json", maxTrustDocBytes)
	if err != nil {
		return nil, "", err
	}
	if !b.localSource {
		if err := os.MkdirAll(b.cacheDir, 0o700); err != nil {
			return nil, "", fmt.Errorf("mkdir cache: %w", err)
		}
		cachePath := filepath.Clean(filepath.Join(b.cacheDir, "trust.json"))
		tmp := cachePath + ".tmp"
		if err := os.WriteFile(tmp, doc, 0o600); err != nil {
			return nil, "", fmt.Errorf("write trust cache tmp: %w", err)
		}
		if err := os.Rename(tmp, cachePath); err != nil {
			return nil, "", fmt.Errorf("rename trust cache: %w", err)
		}
	}
	s, err := b.transport.get(ctx, "trust.json.minisig", maxSignatureBytes)
	if err != nil {
		return nil, "", err
	}
	return doc, string(s), nil
}

// FetchTrustBundle retrieves trust-bundle.json (size-bounded) and its detached
// minisign signature. A 404/absent on the document itself yields
// ErrMetadataAbsent (the source publishes no bundle); a present document whose
// signature is missing is a hard error — a stripped signature must never read
// as "no bundle". Cached to disk for HTTP sources; the caller verifies the
// signature before parsing.
func (b *NativeBackend) FetchTrustBundle(ctx context.Context) (raw []byte, sig string, err error) {
	return b.fetchOptionalMeta(ctx, "trust-bundle.json", maxTrustDocBytes)
}

// FetchRevocationList retrieves revocations.json and its detached signature,
// with the same absence/tamper semantics as FetchTrustBundle.
func (b *NativeBackend) FetchRevocationList(ctx context.Context) (raw []byte, sig string, err error) {
	return b.fetchOptionalMeta(ctx, "revocations.json", maxRevocationBytes)
}

// fetchOptionalMeta fetches an optional signed metadata document (name) plus its
// name+".minisig" signature. A not-found on the DOCUMENT is reported as
// ErrMetadataAbsent; a not-found on the signature of a present document is a
// hard error (tamper). HTTP sources cache the document to disk.
func (b *NativeBackend) fetchOptionalMeta(ctx context.Context, name string, limit int64) (raw []byte, sig string, err error) {
	doc, err := b.transport.get(ctx, name, limit)
	if err != nil {
		var fe *FetchError
		if errors.As(err, &fe) && fe.Status == http.StatusNotFound {
			return nil, "", fmt.Errorf("%w: %s", ErrMetadataAbsent, name)
		}
		return nil, "", err
	}
	if !b.localSource {
		if err := os.MkdirAll(b.cacheDir, 0o700); err != nil {
			return nil, "", fmt.Errorf("mkdir cache: %w", err)
		}
		cachePath := filepath.Clean(filepath.Join(b.cacheDir, name))
		tmp := cachePath + ".tmp"
		if err := os.WriteFile(tmp, doc, 0o600); err != nil {
			return nil, "", fmt.Errorf("write %s cache tmp: %w", name, err)
		}
		if err := os.Rename(tmp, cachePath); err != nil {
			return nil, "", fmt.Errorf("rename %s cache: %w", name, err)
		}
	}
	s, err := b.transport.get(ctx, name+".minisig", maxSignatureBytes)
	if err != nil {
		// Document present, signature absent: tamper, not absence. Break the
		// FetchError chain (%v, not %w) so errors.Is(_, ErrMetadataAbsent) and
		// any 404 predicate cannot match — a stripped signature must fail loud.
		return nil, "", fmt.Errorf("%s present but signature missing: %v", name, err) //nolint:errorlint // intentional: %v breaks the chain so a stripped signature can never satisfy errors.Is(_, ErrMetadataAbsent) or a 404 predicate
	}
	return doc, string(s), nil
}

// FetchSignature retrieves the detached minisign signature for the artifact at
// the index-supplied relative path (i.e. artifact + ".minisig").
func (b *NativeBackend) FetchSignature(ctx context.Context, artifact string) (string, error) {
	data, err := b.transport.get(ctx, artifact+".minisig", maxSignatureBytes)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Package ghreleasetest is a test double for the GitHub REST API and release
// asset host that internal/ghrelease talks to. A Fake serves one release: its
// metadata, its assets, and, for each asset marked Attest, the two
// attestations GitHub serves for a release asset: SLSA provenance, a genuine
// sigstore bundle minted under a throwaway Fulcio CA and Rekor log, and a
// release attestation signed under another, unrelated CA, as GitHub signs
// those with its own. Fake.TrustedRoot returns the trusted_root.json that
// verifies the provenance offline, exactly as GitHub's verifies against the
// Sigstore public-good root, so tests exercise real verification without the
// network.
//
// It is test support for polypkg's own tests and the e2e fake server. No
// production package may import it.
package ghreleasetest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/snappy"
)

// Asset is one release asset a Fake serves.
type Asset struct {
	Name string
	Data []byte
	// Attest mints a SLSA provenance bundle whose in-toto subject is Data's
	// sha256, and a release attestation (predicate
	// https://in-toto.io/attestation/release/v0.2, the release named by a purl
	// uri subject) under a CA TrustedRoot does not hold.
	Attest bool
	// AttestRepo, when set, is the OWNER/REPO the provenance certificate
	// names as its source repository (and in its SAN) instead of the
	// release's own.
	AttestRepo string
	// Digest, when set, is reported as the asset's digest in place of the
	// real "sha256:<hex>". OmitDigest reports none, as GitHub does for assets
	// uploaded before it computed digests.
	Digest     string
	OmitDigest bool
}

// Release is the single release a Fake serves.
type Release struct {
	Owner       string
	Repo        string
	Tag         string
	Description string
	Prerelease  bool
	Assets      []Asset
	// RateLimited fails every API request the way GitHub does when the
	// caller's rate limit is exhausted.
	RateLimited bool
}

// Request is one request a Fake received.
type Request struct {
	Path          string
	Authorization string
}

// Fake serves one Release as GitHub's REST API and release-asset host do:
//
//	GET /repos/{owner}/{repo}                            repository metadata
//	GET /repos/{owner}/{repo}/releases/latest            the release, unless it is a prerelease
//	GET /repos/{owner}/{repo}/releases/tags/{tag}        the release
//	GET /repos/{owner}/{repo}/attestations/sha256:{hex}  an attested asset's attestations, paged by per_page and page
//	GET /blobs/{id}                                      one attestation's bundle, snappy block-compressed
//	GET /download/{tag}/{name}                           302 to the asset's /objects/ URL
//	GET /objects/{hex}                                   an asset's bytes, by their sha256
//
// Owner and repository names match case-insensitively, as on GitHub. As
// GitHub does today, an attestation carries no inline bundle, only a
// bundle_url, and an attestations page past the last carries a Link header
// to the next. Download and bundle URLs name the scheme and host the
// request reached, and a download redirects to a host-relative /objects/
// path, so they lead back to the Fake whatever address it listens on.
type Fake struct {
	rel         Release
	trustedRoot []byte
	bundles     map[string][]string // asset sha256 hex -> blob IDs of its attestations, in order
	blobs       map[string][]byte   // blob ID (sha256 hex of the bundle) -> bundle JSON
	mux         *http.ServeMux

	mu       sync.Mutex
	requests []Request
}

// New mints the release's attestations and returns a Fake serving it.
func New(rel Release) (*Fake, error) {
	now := time.Now()
	auth, err := newAuthority(now)
	if err != nil {
		return nil, err
	}
	// GitHub signs release attestations under its own CA, which the
	// public-good root, and so the Fake's trusted root, does not hold.
	githubCA, err := newAuthority(now)
	if err != nil {
		return nil, err
	}
	f := &Fake{rel: rel, trustedRoot: auth.trustedRoot, bundles: map[string][]string{}, blobs: map[string][]byte{}}
	for _, a := range rel.Assets {
		if !a.Attest {
			continue
		}
		repo := rel.Owner + "/" + rel.Repo
		if a.AttestRepo != "" {
			repo = a.AttestRepo
		}
		sum := sha256.Sum256(a.Data)
		statement, err := provenanceStatement(a.Name, sum)
		if err != nil {
			return nil, fmt.Errorf("statement for %s: %w", a.Name, err)
		}
		provenance, err := auth.attest(statement, repo, rel.Tag, now)
		if err != nil {
			return nil, fmt.Errorf("attest %s: %w", a.Name, err)
		}
		statement, err = releaseStatement(rel.Owner+"/"+rel.Repo, rel.Tag, a.Name, sum)
		if err != nil {
			return nil, fmt.Errorf("release statement for %s: %w", a.Name, err)
		}
		release, err := githubCA.attest(statement, rel.Owner+"/"+rel.Repo, rel.Tag, now)
		if err != nil {
			return nil, fmt.Errorf("release attestation for %s: %w", a.Name, err)
		}
		key := hex.EncodeToString(sum[:])
		for _, b := range [][]byte{provenance, release} {
			id := sha256.Sum256(b)
			f.blobs[hex.EncodeToString(id[:])] = b
			f.bundles[key] = append(f.bundles[key], hex.EncodeToString(id[:]))
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{owner}/{repo}", f.serveRepo)
	mux.HandleFunc("GET /repos/{owner}/{repo}/releases/latest", f.serveLatest)
	mux.HandleFunc("GET /repos/{owner}/{repo}/releases/tags/{tag}", f.serveTag)
	mux.HandleFunc("GET /repos/{owner}/{repo}/attestations/{digest}", f.serveAttestations)
	mux.HandleFunc("GET /blobs/{digest}", f.serveBlob)
	mux.HandleFunc("GET /download/{tag}/{name}", f.serveDownload)
	mux.HandleFunc("GET /objects/{digest}", f.serveObject)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { writeNotFound(w) })
	f.mux = mux
	return f, nil
}

// TrustedRoot returns the trusted_root.json that verifies the Fake's
// attestations.
func (f *Fake) TrustedRoot() []byte { return append([]byte(nil), f.trustedRoot...) }

// Requests returns every request the Fake has received, in order.
func (f *Fake) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Request(nil), f.requests...)
}

// ServeHTTP records the request, then serves it.
func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, Request{Path: r.URL.Path, Authorization: r.Header.Get("Authorization")})
	f.mu.Unlock()
	if f.rel.RateLimited && strings.HasPrefix(r.URL.Path, "/repos/") {
		w.Header().Set("X-RateLimit-Limit", "60")
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
		writeJSON(w, http.StatusForbidden, map[string]string{"message": "API rate limit exceeded"})
		return
	}
	f.mux.ServeHTTP(w, r)
}

func (f *Fake) ownRepo(r *http.Request) bool {
	return strings.EqualFold(r.PathValue("owner"), f.rel.Owner) && strings.EqualFold(r.PathValue("repo"), f.rel.Repo)
}

func (f *Fake) serveRepo(w http.ResponseWriter, r *http.Request) {
	if !f.ownRepo(r) {
		writeNotFound(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"full_name":   f.rel.Owner + "/" + f.rel.Repo,
		"description": f.rel.Description,
	})
}

func (f *Fake) serveLatest(w http.ResponseWriter, r *http.Request) {
	if !f.ownRepo(r) || f.rel.Prerelease {
		writeNotFound(w)
		return
	}
	writeJSON(w, http.StatusOK, f.releaseDoc(r))
}

func (f *Fake) serveTag(w http.ResponseWriter, r *http.Request) {
	if !f.ownRepo(r) || r.PathValue("tag") != f.rel.Tag {
		writeNotFound(w)
		return
	}
	writeJSON(w, http.StatusOK, f.releaseDoc(r))
}

func (f *Fake) serveAttestations(w http.ResponseWriter, r *http.Request) {
	h, ok := strings.CutPrefix(r.PathValue("digest"), "sha256:")
	ids, attested := f.bundles[h]
	if !f.ownRepo(r) || !ok || !attested {
		writeNotFound(w)
		return
	}
	perPage, page := queryInt(r, "per_page", 30), queryInt(r, "page", 1)
	perPage = min(max(perPage, 1), 100)
	page = max(page, 1)
	start := min((page-1)*perPage, len(ids))
	end := min(start+perPage, len(ids))
	if end < len(ids) {
		next := *r.URL
		q := next.Query()
		q.Set("per_page", strconv.Itoa(perPage))
		q.Set("page", strconv.Itoa(page+1))
		next.RawQuery = q.Encode()
		w.Header().Set("Link", fmt.Sprintf("<%s%s>; rel=\"next\"", origin(r), next.RequestURI()))
	}
	list := make([]map[string]any, 0, end-start)
	for _, id := range ids[start:end] {
		list = append(list, map[string]any{
			"repository_id": 1,
			"bundle":        nil,
			"bundle_url":    origin(r) + "/blobs/" + id,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"attestations": list})
}

// queryInt is r's query parameter name as an integer, or def when it is
// absent or not one.
func queryInt(r *http.Request, name string, def int) int {
	n, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil {
		return def
	}
	return n
}

func (f *Fake) serveBlob(w http.ResponseWriter, r *http.Request) {
	b, ok := f.blobs[r.PathValue("digest")]
	if !ok {
		writeNotFound(w)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(snappy.Encode(nil, b))
}

// serveDownload redirects to the asset's object URL, as GitHub redirects a
// browser_download_url to its separate release-asset host.
func (f *Fake) serveDownload(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("tag") == f.rel.Tag {
		for _, a := range f.rel.Assets {
			if a.Name == r.PathValue("name") {
				sum := sha256.Sum256(a.Data)
				http.Redirect(w, r, "/objects/"+hex.EncodeToString(sum[:]), http.StatusFound)
				return
			}
		}
	}
	writeNotFound(w)
}

func (f *Fake) serveObject(w http.ResponseWriter, r *http.Request) {
	for _, a := range f.rel.Assets {
		if sum := sha256.Sum256(a.Data); hex.EncodeToString(sum[:]) == r.PathValue("digest") {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(a.Data)
			return
		}
	}
	writeNotFound(w)
}

// releaseDoc is the release as GitHub's API renders it.
func (f *Fake) releaseDoc(r *http.Request) map[string]any {
	assets := make([]map[string]any, 0, len(f.rel.Assets))
	for _, a := range f.rel.Assets {
		entry := map[string]any{
			"name": a.Name,
			"size": len(a.Data),
			"browser_download_url": origin(r) + "/download/" +
				url.PathEscape(f.rel.Tag) + "/" + url.PathEscape(a.Name),
		}
		switch {
		case a.OmitDigest:
			entry["digest"] = nil
		case a.Digest != "":
			entry["digest"] = a.Digest
		default:
			sum := sha256.Sum256(a.Data)
			entry["digest"] = "sha256:" + hex.EncodeToString(sum[:])
		}
		assets = append(assets, entry)
	}
	return map[string]any{
		"tag_name":   f.rel.Tag,
		"draft":      false,
		"prerelease": f.rel.Prerelease,
		"assets":     assets,
	}
}

// origin is the scheme and host the request reached.
func origin(r *http.Request) string {
	if r.TLS != nil {
		return "https://" + r.Host
	}
	return "http://" + r.Host
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func writeNotFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, map[string]string{"message": "Not Found"})
}

// TarEntry is one regular file in an archive TarGz builds.
type TarEntry struct {
	Name string
	Mode int64
	Body []byte
}

// TarGz returns a gzip-compressed tar holding entries in order: the shape of
// a typical release archive.
func TarGz(entries ...TarEntry) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.Name, Typeflag: tar.TypeReg, Mode: e.Mode, Size: int64(len(e.Body))}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("write tar header %s: %w", e.Name, err)
		}
		if _, err := tw.Write(e.Body); err != nil {
			return nil, fmt.Errorf("write tar body %s: %w", e.Name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("close gzip: %w", err)
	}
	return buf.Bytes(), nil
}

package importer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/ghrelease"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/source"
)

// fakeAsset is one release asset the fake serves. digest is the API's
// "digest" field; "" serves null, as GitHub does for older assets. size is
// the API's "size" field; 0 serves len(data).
type fakeAsset struct {
	name   string
	data   []byte
	digest string
	size   int
}

// digested returns an asset whose API digest matches its bytes.
func digested(name string, data []byte) fakeAsset {
	return fakeAsset{name: name, data: data, digest: "sha256:" + assetSHA256(data)}
}

// fakeGitHub serves the slice of the GitHub REST API an import uses — one
// release of acme/tool, the repository, artifact attestations and asset
// downloads — and records every request path.
type fakeGitHub struct {
	srv          *httptest.Server
	tag          string
	assets       []fakeAsset
	attestations map[string][][]byte // asset sha256 hex → bundles
	mu           sync.Mutex
	paths        []string
}

func newFakeGitHub(t *testing.T, tag string, assets ...fakeAsset) *fakeGitHub {
	t.Helper()
	f := &fakeGitHub{tag: tag, assets: assets, attestations: map[string][][]byte{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.Path)
	f.mu.Unlock()
	const attestations = "/repos/acme/tool/attestations/sha256:"
	switch p := r.URL.Path; {
	case p == "/repos/acme/tool/releases/latest", p == "/repos/acme/tool/releases/tags/"+f.tag:
		assets := make([]map[string]any, 0, len(f.assets))
		for _, a := range f.assets {
			var digest any
			if a.digest != "" {
				digest = a.digest
			}
			size := a.size
			if size == 0 {
				size = len(a.data)
			}
			assets = append(assets, map[string]any{
				"name": a.name, "size": size, "digest": digest,
				"browser_download_url": f.srv.URL + "/download/" + url.PathEscape(a.name),
			})
		}
		writeJSON(w, map[string]any{"tag_name": f.tag, "prerelease": false, "assets": assets})
	case p == "/repos/acme/tool":
		writeJSON(w, map[string]any{"description": "  A tool\nfor testing.  "})
	case strings.HasPrefix(p, attestations):
		bundles := f.attestations[strings.TrimPrefix(p, attestations)]
		if len(bundles) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
			return
		}
		list := make([]map[string]any, 0, len(bundles))
		for _, b := range bundles {
			list = append(list, map[string]any{"bundle": json.RawMessage(b)})
		}
		writeJSON(w, map[string]any{"attestations": list})
	case strings.HasPrefix(p, "/download/"):
		for _, a := range f.assets {
			if "/download/"+a.name == p {
				_, _ = w.Write(a.data)
				return
			}
		}
		http.NotFound(w, r)
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func (f *fakeGitHub) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.paths)
}

func (f *fakeGitHub) downloads() int {
	n := 0
	for _, p := range f.requests() {
		if strings.HasPrefix(p, "/download/") {
			n++
		}
	}
	return n
}

func testOptions(t *testing.T, f *fakeGitHub, outDir string) Options {
	t.Helper()
	trustedRoot := readAttestFixture(t, "github-trusted-root.json")
	return Options{
		Owner:       "acme",
		Repo:        "tool",
		OutDir:      outDir,
		Client:      ghrelease.New(f.srv.URL, "", source.NewHTTPClient()),
		TrustedRoot: func(context.Context) ([]byte, error) { return trustedRoot, nil },
		Lint:        PkgLint,
	}
}

func readRecipe(t *testing.T, dir string) *schema.Package {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "polypkg.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := schema.ParsePackage(bytes.NewReader(raw), "polypkg.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// assertJSONFile fails unless path holds JSON equal to want.
func assertJSONFile(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(want, &w); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Fatalf("%s holds a different JSON document than expected", path)
	}
}

func assertMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%s: %v, want it absent", path, err)
	}
}

func skippedReason(res *Result, asset string) string {
	for _, s := range res.Skipped {
		if s.Name == asset {
			return s.Reason
		}
	}
	return ""
}

func TestRunImportsArchiveAndBareAssets(t *testing.T) {
	sandboxHome(t)
	archiveData := toolArchive(t)
	f := newFakeGitHub(t, "v1.2.3",
		digested("tool_1.2.3_linux_amd64.tar.gz", archiveData),
		digested("tool_1.2.3_darwin_arm64", machOBinary),
		digested("tool_1.2.3_windows_amd64.zip", []byte("PK\x03\x04")),
	)
	out := filepath.Join(t.TempDir(), "imports")
	res, err := Run(context.Background(), testOptions(t, f, out))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if res.Name != "tool" || res.Version != "1.2.3" {
		t.Fatalf("name, version = %q, %q; want tool, 1.2.3", res.Name, res.Version)
	}
	if res.TrustedRootPath != filepath.Join(out, "sigstore-trusted-root.json") {
		t.Fatalf("trusted root path = %q", res.TrustedRootPath)
	}
	assertFile(t, res.TrustedRootPath, readAttestFixture(t, "github-trusted-root.json"), 0o644)
	darwin := filepath.Join(out, "tool", "1.2.3", "darwin-arm64")
	linux := filepath.Join(out, "tool", "1.2.3", "linux-amd64")
	wantPlatforms := []PlatformResult{
		{Platform: "darwin/arm64", Asset: "tool_1.2.3_darwin_arm64", Integrity: "github-digest", Dir: darwin},
		{Platform: "linux/amd64", Asset: "tool_1.2.3_linux_amd64.tar.gz", Integrity: "github-digest", Dir: linux},
	}
	if !reflect.DeepEqual(res.Platforms, wantPlatforms) {
		t.Fatalf("platforms:\n got %+v\nwant %+v", res.Platforms, wantPlatforms)
	}
	if skippedReason(res, "tool_1.2.3_windows_amd64.zip") == "" {
		t.Fatalf("the windows asset is not reported as skipped: %+v", res.Skipped)
	}

	wantLinux := &schema.Package{
		Schema: "polypkg.package/v1", Name: "tool", Version: "1.2.3", Platform: "linux/amd64",
		Title: "tool", Description: "A tool for testing.",
		Actions: []schema.PackageAction{
			{Phase: "post-place", Action: "extract", Params: map[string]any{
				"src": "$PKG/content/tool_1.2.3_linux_amd64.tar.gz", "dest": "$ACTIVE/tool/dist", "strip_components": 1}},
			{Phase: "post-place", Action: "path", Params: map[string]any{"name": "tool", "source": "$ACTIVE/tool/dist/tool"}},
		},
	}
	if got := readRecipe(t, linux); !reflect.DeepEqual(got, wantLinux) {
		t.Fatalf("linux recipe:\n got %+v\nwant %+v", got, wantLinux)
	}
	wantDarwin := &schema.Package{
		Schema: "polypkg.package/v1", Name: "tool", Version: "1.2.3", Platform: "darwin/arm64",
		Title: "tool", Description: "A tool for testing.",
		Actions: []schema.PackageAction{
			{Phase: "post-place", Action: "install", Params: map[string]any{
				"src": "$PKG/content/tool_1.2.3_darwin_arm64", "dest": "$ACTIVE/tool/bin/tool", "policy": "copy"}},
			{Phase: "post-place", Action: "path", Params: map[string]any{"name": "tool", "source": "$ACTIVE/tool/bin/tool"}},
		},
	}
	if got := readRecipe(t, darwin); !reflect.DeepEqual(got, wantDarwin) {
		t.Fatalf("darwin recipe:\n got %+v\nwant %+v", got, wantDarwin)
	}
	assertFile(t, filepath.Join(linux, "content", "tool_1.2.3_linux_amd64.tar.gz"), archiveData, 0o644)
	assertFile(t, filepath.Join(darwin, "content", "tool_1.2.3_darwin_arm64"), machOBinary, 0o755)
	assertMissing(t, filepath.Join(linux, "attestations"))

	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Name() != "sigstore-trusted-root.json" || entries[1].Name() != "tool" {
		t.Fatalf("out-dir holds %v, want the trusted root and the package only", entries)
	}
}

func TestRunLintsEverySourceBeforeCommitting(t *testing.T) {
	sandboxHome(t)
	f := newFakeGitHub(t, "v1.2.3",
		digested("tool_1.2.3_linux_amd64.tar.gz", toolArchive(t)),
		digested("tool_1.2.3_darwin_arm64", machOBinary),
	)
	out := filepath.Join(t.TempDir(), "imports")
	opts := testOptions(t, f, out)
	var linted []string
	opts.Lint = func(dir string) ([]string, error) {
		if !strings.HasPrefix(dir, filepath.Join(out, stagingPrefix)) {
			t.Errorf("lint ran on %s, outside the staging directory", dir)
		}
		if _, err := os.Lstat(filepath.Join(out, "tool", "1.2.3", filepath.Base(dir))); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s was committed before it was linted", filepath.Base(dir))
		}
		linted = append(linted, filepath.Base(dir))
		return PkgLint(dir)
	}
	if _, err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !reflect.DeepEqual(linted, []string{"darwin-arm64", "linux-amd64"}) {
		t.Fatalf("linted %q, want every platform", linted)
	}
}

func TestRunRefusesOnALintFindingAndLeavesOutDirUnchanged(t *testing.T) {
	sandboxHome(t)
	f := newFakeGitHub(t, "v1.2.3",
		digested("tool_1.2.3_linux_amd64.tar.gz", toolArchive(t)),
		digested("tool_1.2.3_darwin_arm64", machOBinary),
	)
	out := t.TempDir()
	writeTree(t, out, map[string]string{"other/1.0.0/linux-amd64/polypkg.yaml": "other"})
	before := snapshot(t, out)
	opts := testOptions(t, f, out)
	opts.Lint = func(dir string) ([]string, error) {
		if filepath.Base(dir) == "linux-amd64" {
			return []string{"warning PKG999 polypkg.yaml: synthetic finding"}, nil
		}
		return PkgLint(dir)
	}
	_, err := Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "fails pkg lint") || !strings.Contains(err.Error(), "synthetic finding") {
		t.Fatalf("error = %v, want the lint finding", err)
	}
	if after := snapshot(t, out); !reflect.DeepEqual(after, before) {
		t.Fatalf("out-dir changed:\nbefore %v\nafter  %v", before, after)
	}
}

func TestRunCarriesVerifiedAttestationsAndDropsOthers(t *testing.T) {
	sandboxHome(t)
	asset := readAttestFixture(t, "github-asset.bin")
	genuine := readAttestFixture(t, "github-bundle.json")
	f := newFakeGitHub(t, "v1.2.3", digested("tool-linux-amd64", asset))
	f.attestations[assetSHA256(asset)] = [][]byte{
		readAttestFixture(t, "github-bundle-wrong-repo.json"),
		readAttestFixture(t, "github-bundle-release.json"),
		genuine,
		readAttestFixture(t, "github-bundle-wrong-issuer.json"),
	}
	out := filepath.Join(t.TempDir(), "imports")
	res, err := Run(context.Background(), testOptions(t, f, out))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Platforms) != 1 {
		t.Fatalf("platforms = %+v, want linux/amd64 only", res.Platforms)
	}
	p := res.Platforms[0]
	if p.Platform != "linux/amd64" || p.Attestations != 1 || len(p.Warnings) != 2 || len(p.Notes) != 1 {
		t.Fatalf("platform = %+v, want one kept attestation, two warnings and one note", p)
	}
	if !strings.Contains(p.Warnings[0], "mallory/tool") || !strings.Contains(p.Warnings[1], "accounts.google.com") {
		t.Fatalf("warnings = %q", p.Warnings)
	}
	if !strings.Contains(p.Notes[0], "https://in-toto.io/attestation/release/v0.2") {
		t.Fatalf("notes = %q, want the skipped release attestation", p.Notes)
	}
	assertJSONFile(t, filepath.Join(p.Dir, "attestations", "1.json"), genuine)
	assertMissing(t, filepath.Join(p.Dir, "attestations", "2.json"))
	assertFile(t, filepath.Join(p.Dir, "content", "tool-linux-amd64"), asset, 0o755)
}

// TestRunKeepsProvenanceBesideAGitHubReleaseAttestation is the shape every
// attested GitHub release serves today: SLSA provenance plus a release
// attestation whose first subject is a purl uri, not a name. The release
// attestation is noted and skipped, never parsed strictly; the provenance is
// kept.
func TestRunKeepsProvenanceBesideAGitHubReleaseAttestation(t *testing.T) {
	sandboxHome(t)
	asset := readAttestFixture(t, "github-asset.bin")
	genuine := readAttestFixture(t, "github-bundle.json")
	f := newFakeGitHub(t, "v1.2.3", digested("tool-linux-amd64", asset))
	f.attestations[assetSHA256(asset)] = [][]byte{readAttestFixture(t, "github-bundle-release.json"), genuine}
	out := filepath.Join(t.TempDir(), "imports")
	res, err := Run(context.Background(), testOptions(t, f, out))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	p := res.Platforms[0]
	if p.Attestations != 1 || len(p.Warnings) != 0 || len(p.Notes) != 1 {
		t.Fatalf("platform = %+v, want one kept attestation, no warning and one note", p)
	}
	if !strings.Contains(p.Notes[0], "https://in-toto.io/attestation/release/v0.2") {
		t.Fatalf("notes = %q, want the skipped release attestation", p.Notes)
	}
	assertJSONFile(t, filepath.Join(p.Dir, "attestations", "1.json"), genuine)
	assertMissing(t, filepath.Join(p.Dir, "attestations", "2.json"))
}

func TestRunNumbersAttestationsByTheirDigest(t *testing.T) {
	sandboxHome(t)
	asset := readAttestFixture(t, "github-asset.bin")
	original := readAttestFixture(t, "github-bundle.json")
	// The same bundle with its keys sorted (the fixture starts with
	// mediaType): byte-distinct, still compact as the API serves it, and it
	// verifies just the same.
	var doc map[string]any
	if err := json.Unmarshal(original, &doc); err != nil {
		t.Fatal(err)
	}
	sorted, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sorted, original) {
		t.Fatal("re-encoding the bundle did not change its bytes")
	}
	// Whichever order the API returns them in, the lower sha256 is 1.json.
	first, second := original, sorted
	if assetSHA256(second) < assetSHA256(first) {
		first, second = second, first
	}
	for _, order := range [][][]byte{{original, sorted}, {sorted, original}} {
		f := newFakeGitHub(t, "v1.2.3", digested("tool-linux-amd64", asset))
		f.attestations[assetSHA256(asset)] = order
		out := filepath.Join(t.TempDir(), "imports")
		res, err := Run(context.Background(), testOptions(t, f, out))
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		dir := res.Platforms[0].Dir
		assertFile(t, filepath.Join(dir, "attestations", "1.json"), first, 0o644)
		assertFile(t, filepath.Join(dir, "attestations", "2.json"), second, 0o644)
	}
}

func TestRunSkipsAReleaseAttestationItCannotVerify(t *testing.T) {
	sandboxHome(t)
	asset := readAttestFixture(t, "github-asset.bin")
	f := newFakeGitHub(t, "v1.2.3", digested("tool-linux-amd64", asset))
	// Signed by a CA the trusted root does not hold, as GitHub's internal
	// Fulcio is: never verified, never carried, never a refusal.
	f.attestations[assetSHA256(asset)] = [][]byte{readAttestFixture(t, "github-bundle-release.json")}
	out := filepath.Join(t.TempDir(), "imports")
	res, err := Run(context.Background(), testOptions(t, f, out))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	p := res.Platforms[0]
	if p.Attestations != 0 || len(p.Warnings) != 0 || len(p.Notes) != 1 {
		t.Fatalf("platform = %+v, want no attestation carried, no warning and one note", p)
	}
	assertMissing(t, filepath.Join(p.Dir, "attestations"))
}

func TestRunRequireAttestationCountsOnlyProvenance(t *testing.T) {
	sandboxHome(t)
	asset := readAttestFixture(t, "github-asset.bin")
	f := newFakeGitHub(t, "v1.2.3", digested("tool-linux-amd64", asset))
	f.attestations[assetSHA256(asset)] = [][]byte{readAttestFixture(t, "github-bundle-release.json")}
	out := filepath.Join(t.TempDir(), "imports")
	opts := testOptions(t, f, out)
	opts.RequireAttestation = true
	_, err := Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "attestations are required") {
		t.Fatalf("error = %v, want the only platform refused for lack of provenance", err)
	}
	assertMissing(t, out)
}

func TestRunRefusesATamperedAttestation(t *testing.T) {
	sandboxHome(t)
	asset := readAttestFixture(t, "github-asset.bin")
	f := newFakeGitHub(t, "v1.2.3", digested("tool-linux-amd64", asset))
	f.attestations[assetSHA256(asset)] = [][]byte{tamperSignature(t, readAttestFixture(t, "github-bundle.json"))}
	out := filepath.Join(t.TempDir(), "imports")
	_, err := Run(context.Background(), testOptions(t, f, out))
	if err == nil || !strings.Contains(err.Error(), "provenance attestation 1 of 1 for tool-linux-amd64 does not verify against the Sigstore trusted root: ") ||
		!strings.Contains(err.Error(), "GitHub Enterprise Server") {
		t.Fatalf("error = %v, want a verification refusal naming the asset and both causes", err)
	}
	var pe *ProvenanceError
	if !errors.As(err, &pe) || pe.Asset != "tool-linux-amd64" || pe.Index != 1 || pe.Total != 1 || pe.Reason == "" {
		t.Fatalf("error = %#v, want a *ProvenanceError for attestation 1 of 1 of tool-linux-amd64 with sigstore's reason", err)
	}
	assertMissing(t, out)
}

func TestRunRefusesAnAttestationForAnotherAsset(t *testing.T) {
	sandboxHome(t)
	f := newFakeGitHub(t, "v1.2.3", digested("tool-linux-amd64", elfBinary))
	f.attestations[assetSHA256(elfBinary)] = [][]byte{readAttestFixture(t, "github-bundle.json")}
	out := filepath.Join(t.TempDir(), "imports")
	_, err := Run(context.Background(), testOptions(t, f, out))
	if err == nil || !strings.Contains(err.Error(), "none of its subjects is this asset") {
		t.Fatalf("error = %v, want a subject refusal", err)
	}
	assertMissing(t, out)
}

func TestRunRequireAttestationDropsAnUnattestedPlatform(t *testing.T) {
	sandboxHome(t)
	attested := readAttestFixture(t, "github-asset.bin")
	f := newFakeGitHub(t, "v1.2.3", digested("tool-linux-amd64", attested), digested("tool-linux-arm64", elfARM64Binary))
	f.attestations[assetSHA256(attested)] = [][]byte{readAttestFixture(t, "github-bundle.json")}
	out := filepath.Join(t.TempDir(), "imports")
	opts := testOptions(t, f, out)
	opts.RequireAttestation = true
	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Platforms) != 1 || res.Platforms[0].Platform != "linux/amd64" || res.Platforms[0].Attestations != 1 {
		t.Fatalf("platforms = %+v, want only the attested linux/amd64", res.Platforms)
	}
	if reason := skippedReason(res, "tool-linux-arm64"); !strings.Contains(reason, "linux/arm64: ") || !strings.Contains(reason, "attestations are required") {
		t.Fatalf("linux/arm64 skip reason = %q", reason)
	}
	assertMissing(t, filepath.Join(out, "tool", "1.2.3", "linux-arm64"))
}

func TestRunRequireAttestationRefusesWhenNoPlatformHasOne(t *testing.T) {
	sandboxHome(t)
	f := newFakeGitHub(t, "v1.2.3", digested("tool-linux-arm64", elfARM64Binary))
	out := filepath.Join(t.TempDir(), "imports")
	opts := testOptions(t, f, out)
	opts.RequireAttestation = true
	_, err := Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "no platform") || !strings.Contains(err.Error(), "attestations are required") {
		t.Fatalf("error = %v, want every platform refused", err)
	}
	assertMissing(t, out)
}

func TestRunRefusesADigestMismatchAndLeavesOutDirUnchanged(t *testing.T) {
	sandboxHome(t)
	f := newFakeGitHub(t, "v1.2.3",
		digested("tool_1.2.3_darwin_arm64", machOBinary),
		fakeAsset{name: "tool_1.2.3_linux_amd64.tar.gz", data: toolArchive(t), digest: "sha256:" + strings.Repeat("0", 64)},
	)
	out := t.TempDir()
	writeTree(t, out, map[string]string{
		"other/1.0.0/linux-amd64/polypkg.yaml": "other",
		"sigstore-trusted-root.json":           "old root",
	})
	before := snapshot(t, out)
	_, err := Run(context.Background(), testOptions(t, f, out))
	var integrity *ghrelease.IntegrityError
	if !errors.As(err, &integrity) {
		t.Fatalf("error = %v, want a *ghrelease.IntegrityError", err)
	}
	// darwin/arm64 sorts first, so it was staged before linux/amd64 failed.
	if after := snapshot(t, out); !reflect.DeepEqual(after, before) {
		t.Fatalf("out-dir changed:\nbefore %v\nafter  %v", before, after)
	}
}

func TestRunRefusesADownloadThatIsNotItsListedSize(t *testing.T) {
	sandboxHome(t)
	data := toolArchive(t)
	for _, c := range []struct {
		name    string
		size    int
		wantErr string
	}{
		{"shorter than listed", len(data) + 1, "release lists it as"},
		{"longer than listed", len(data) - 1, "exceeds"},
	} {
		t.Run(c.name, func(t *testing.T) {
			// The digest matches the bytes served, so only the size check can
			// refuse: it runs before the integrity check.
			a := digested("tool_1.2.3_linux_amd64.tar.gz", data)
			a.size = c.size
			f := newFakeGitHub(t, "v1.2.3", a)
			out := filepath.Join(t.TempDir(), "imports")
			_, err := Run(context.Background(), testOptions(t, f, out))
			if err == nil || !strings.Contains(err.Error(), c.wantErr) || !strings.Contains(err.Error(), "tool_1.2.3_linux_amd64.tar.gz") {
				t.Fatalf("error = %v, want a size refusal naming the asset", err)
			}
			assertMissing(t, out)
		})
	}
}

func TestRunDropsAnAssetListedAsTooLargeWithoutDownloadingIt(t *testing.T) {
	sandboxHome(t)
	big := digested("tool-linux-arm64", elfARM64Binary)
	big.size = maxAssetBytes + 1
	f := newFakeGitHub(t, "v1.2.3", digested("tool-linux-amd64", elfBinary), big)
	res, err := Run(context.Background(), testOptions(t, f, filepath.Join(t.TempDir(), "imports")))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Platforms) != 1 || res.Platforms[0].Platform != "linux/amd64" {
		t.Fatalf("platforms = %+v, want linux/amd64 only", res.Platforms)
	}
	if reason := skippedReason(res, "tool-linux-arm64"); !strings.Contains(reason, "larger than the 2147483648-byte limit") {
		t.Fatalf("linux/arm64 skip reason = %q", reason)
	}
	for _, p := range f.requests() {
		if p == "/download/tool-linux-arm64" {
			t.Fatal("downloaded an asset listed as larger than the limit")
		}
	}
}

func TestRunDropsAnExecutableBuiltForAnotherArchitecture(t *testing.T) {
	sandboxHome(t)
	f := newFakeGitHub(t, "v1.2.3",
		digested("tool-linux-amd64", elfBinary),
		digested("tool-linux-arm64", elfBinary),
		digested("tool-darwin-amd64", machOBinary),
	)
	res, err := Run(context.Background(), testOptions(t, f, filepath.Join(t.TempDir(), "imports")))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Platforms) != 1 || res.Platforms[0].Platform != "linux/amd64" {
		t.Fatalf("platforms = %+v, want linux/amd64 only", res.Platforms)
	}
	if reason := skippedReason(res, "tool-linux-arm64"); !strings.Contains(reason, "is an ELF executable for amd64, not linux/arm64") {
		t.Fatalf("linux/arm64 skip reason = %q", reason)
	}
	if reason := skippedReason(res, "tool-darwin-amd64"); !strings.Contains(reason, "is a Mach-O executable for arm64, not darwin/amd64") {
		t.Fatalf("darwin/amd64 skip reason = %q", reason)
	}
}

func TestRunFallsBackToAChecksumsFile(t *testing.T) {
	sandboxHome(t)
	data := toolArchive(t)
	f := newFakeGitHub(t, "v1.2.3",
		fakeAsset{name: "tool_1.2.3_linux_amd64.tar.gz", data: data},
		fakeAsset{name: "checksums.txt", data: []byte(assetSHA256(data) + "  tool_1.2.3_linux_amd64.tar.gz\n")},
	)
	res, err := Run(context.Background(), testOptions(t, f, filepath.Join(t.TempDir(), "imports")))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Platforms) != 1 || res.Platforms[0].Integrity != "checksums-file" {
		t.Fatalf("platforms = %+v, want linux/amd64 verified by the checksums file", res.Platforms)
	}
}

func TestRunAssetWithoutAnIntegritySource(t *testing.T) {
	sandboxHome(t)
	f := newFakeGitHub(t, "v1.2.3", fakeAsset{name: "tool_1.2.3_linux_amd64.tar.gz", data: toolArchive(t)})
	out := filepath.Join(t.TempDir(), "imports")
	opts := testOptions(t, f, out)
	_, err := Run(context.Background(), opts)
	var np *NoPlatformError
	if !errors.As(err, &np) || len(np.Reasons) != 1 || !strings.Contains(err.Error(), "no platform") ||
		!errors.Is(err, ghrelease.ErrUnverifiable) {
		t.Fatalf("error = %v, want a *NoPlatformError with one reason, wrapping ghrelease.ErrUnverifiable", err)
	}
	assertMissing(t, out)

	opts.InsecureSkipDigest = true
	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Platforms) != 1 || res.Platforms[0].Integrity != "UNVERIFIED" {
		t.Fatalf("platforms = %+v, want linux/amd64 marked UNVERIFIED", res.Platforms)
	}
}

func TestRunDropsPlatformsItCannotInstall(t *testing.T) {
	sandboxHome(t)
	f := newFakeGitHub(t, "v1.2.3",
		digested("tool_1.2.3_linux_amd64.tar.gz", tarGz(t, tarEntry{name: "tool-1.2.3/other", mode: 0o755, body: "x"})),
		digested("tool_1.2.3_linux_arm64", []byte("#!/bin/sh\necho tool\n")),
		digested("tool_1.2.3_darwin_arm64", machOBinary),
	)
	res, err := Run(context.Background(), testOptions(t, f, filepath.Join(t.TempDir(), "imports")))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Platforms) != 1 || res.Platforms[0].Platform != "darwin/arm64" {
		t.Fatalf("platforms = %+v, want darwin/arm64 only", res.Platforms)
	}
	if reason := skippedReason(res, "tool_1.2.3_linux_amd64.tar.gz"); !strings.Contains(reason, `no executable named "tool"; executables found: "other"`) {
		t.Fatalf("linux/amd64 skip reason = %q", reason)
	}
	if reason := skippedReason(res, "tool_1.2.3_linux_arm64"); !strings.Contains(reason, "is neither an archive") {
		t.Fatalf("linux/arm64 skip reason = %q", reason)
	}
}

func TestRunRefusesSeveralBinsForABareAsset(t *testing.T) {
	sandboxHome(t)
	f := newFakeGitHub(t, "v1.2.3", digested("tool_1.2.3_darwin_arm64", machOBinary))
	opts := testOptions(t, f, filepath.Join(t.TempDir(), "imports"))
	opts.Bins = []string{"tool", "helper"}
	if _, err := Run(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "single executable") {
		t.Fatalf("error = %v, want a refusal of two --bin for a bare asset", err)
	}
}

func TestRunRefusesAnExistingTargetBeforeDownloading(t *testing.T) {
	sandboxHome(t)
	f := newFakeGitHub(t, "v1.2.3", digested("tool_1.2.3_linux_amd64.tar.gz", toolArchive(t)))
	out := t.TempDir()
	if err := os.MkdirAll(filepath.Join(out, "tool", "1.2.3", "linux-amd64"), 0o755); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, out)
	_, err := Run(context.Background(), testOptions(t, f, out))
	var te *TargetExistsError
	if !errors.As(err, &te) || te.Dir != filepath.Join(out, "tool", "1.2.3", "linux-amd64") || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("error = %v, want a *TargetExistsError naming the linux-amd64 directory", err)
	}
	if n := f.downloads(); n != 0 {
		t.Fatalf("%d downloads before refusing, want none", n)
	}
	if after := snapshot(t, out); !reflect.DeepEqual(after, before) {
		t.Fatalf("out-dir changed:\nbefore %v\nafter  %v", before, after)
	}
}

func TestRunRefusesACaseVariantBeforeDownloading(t *testing.T) {
	for _, tc := range []struct {
		name, tag, existing string
		want                CaseVariantError // Dir is relative to the out-dir
		wantMsg             string
	}{
		{
			"package", "v1.2.3", filepath.Join("Tool", "0.9.0", "linux-amd64"),
			CaseVariantError{Dir: ".", Existing: "Tool", Want: "tool", What: "package"},
			`already holds "Tool", which differs from the package "tool" only in letter case`,
		},
		{
			"version", "v1.2.3-rc1", filepath.Join("tool", "1.2.3-RC1", "linux-amd64"),
			CaseVariantError{Dir: "tool", Existing: "1.2.3-RC1", Want: "1.2.3-rc1", What: "version"},
			`already holds "1.2.3-RC1", which differs from the version "1.2.3-rc1" only in letter case`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sandboxHome(t)
			f := newFakeGitHub(t, tc.tag, digested("tool_1.2.3_linux_amd64.tar.gz", toolArchive(t)))
			out := t.TempDir()
			if err := os.MkdirAll(filepath.Join(out, tc.existing), 0o755); err != nil {
				t.Fatal(err)
			}
			before := snapshot(t, out)
			_, err := Run(context.Background(), testOptions(t, f, out))
			var cv *CaseVariantError
			if !errors.As(err, &cv) {
				t.Fatalf("error = %v, want a *CaseVariantError", err)
			}
			want := tc.want
			want.Dir = filepath.Join(out, want.Dir)
			if *cv != want {
				t.Fatalf("error = %+v, want %+v", *cv, want)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantMsg)
			}
			if n := f.downloads(); n != 0 {
				t.Fatalf("%d downloads before refusing, want none", n)
			}
			if after := snapshot(t, out); !reflect.DeepEqual(after, before) {
				t.Fatalf("out-dir changed:\nbefore %v\nafter  %v", before, after)
			}
		})
	}
}

func TestRunRefusesANonSemverTag(t *testing.T) {
	sandboxHome(t)
	f := newFakeGitHub(t, "nightly", digested("tool_linux_amd64.tar.gz", toolArchive(t)))
	opts := testOptions(t, f, filepath.Join(t.TempDir(), "imports"))
	opts.Tag = "nightly"
	_, err := Run(context.Background(), opts)
	var ve *VersionError
	if !errors.As(err, &ve) || ve.Version != "nightly" || !ve.FromTag {
		t.Fatalf("error = %v, want a *VersionError for the tag", err)
	}
	opts.Version = "0.1.0"
	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Version != "0.1.0" {
		t.Fatalf("version = %q, want 0.1.0", res.Version)
	}
}

func TestRunRefusesAReleaseWithNoInstallableAsset(t *testing.T) {
	sandboxHome(t)
	f := newFakeGitHub(t, "v1.2.3", digested("tool_1.2.3_windows_amd64.zip", []byte("PK\x03\x04")))
	if _, err := Run(context.Background(), testOptions(t, f, filepath.Join(t.TempDir(), "imports"))); err == nil || !strings.Contains(err.Error(), "has no asset") {
		t.Fatalf("error = %v, want a no-asset refusal", err)
	}
}

func TestRunValidatesOptionsBeforeContactingGitHub(t *testing.T) {
	sandboxHome(t)
	for _, c := range []struct {
		name   string
		mutate func(*Options)
		want   string
	}{
		{"owner", func(o *Options) { o.Owner = "acme/evil" }, "GitHub owner"},
		{"repository", func(o *Options) { o.Repo = ".." }, "GitHub repository"},
		{"out-dir", func(o *Options) { o.OutDir = "" }, "out-dir"},
		{"client", func(o *Options) { o.Client = nil }, "Options.Client"},
		{"trusted root", func(o *Options) { o.TrustedRoot = nil }, "Options.TrustedRoot"},
		{"lint", func(o *Options) { o.Lint = nil }, "Options.Lint"},
		{"package name", func(o *Options) { o.Repo = "tool.js" }, "is not a valid package name"},
		{"version", func(o *Options) { o.Version = "latest" }, `version "latest" is not a semantic version`},
		{"bin", func(o *Options) { o.Bins = []string{"bin/tool"} }, "--bin"},
		{"repeated bin", func(o *Options) { o.Bins = []string{"tool", "tool"} }, "twice"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeGitHub(t, "v1.2.3")
			opts := testOptions(t, f, t.TempDir())
			c.mutate(&opts)
			if _, err := Run(context.Background(), opts); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %v, want %q", err, c.want)
			}
			if reqs := f.requests(); len(reqs) != 0 {
				t.Fatalf("contacted GitHub before validating: %q", reqs)
			}
		})
	}
}

func TestImportPlatformRefusesAnUnsafeAssetNameBeforeDownloading(t *testing.T) {
	sandboxHome(t)
	f := newFakeGitHub(t, "v1.2.3")
	r := &importRun{opts: testOptions(t, f, t.TempDir())}
	for _, name := range []string{"../tool-linux-amd64", "tool$ACTIVE-linux-amd64", ".tool-linux-amd64", "sub/tool-linux-amd64"} {
		_, err := r.importPlatform(context.Background(), "linux/amd64",
			ghrelease.Asset{Name: name, URL: f.srv.URL + "/download/x"}, "tool/1.2.3/linux-amd64")
		var rf *refusal
		if !errors.As(err, &rf) {
			t.Fatalf("asset %q: error = %v, want a platform refusal", name, err)
		}
	}
	if n := f.downloads(); n != 0 {
		t.Fatalf("%d downloads, want none", n)
	}
}

func TestTargetDir(t *testing.T) {
	if got, err := targetDir("tool", "1.2.3", "linux/amd64"); err != nil || got != "tool/1.2.3/linux-amd64" {
		t.Fatalf(`targetDir = %q, %v; want "tool/1.2.3/linux-amd64"`, got, err)
	}
	for _, bad := range []string{"linux/arm/v7", "Linux/amd64", "linux/../x", "plan10/amd64"} {
		if _, err := targetDir("tool", "1.2.3", bad); err == nil {
			t.Errorf("targetDir accepted platform %q", bad)
		}
	}
}

func TestRunWrapsATrustedRootFailure(t *testing.T) {
	sandboxHome(t)
	f := newFakeGitHub(t, "v1.2.3", digested("tool_1.2.3_linux_amd64.tar.gz", toolArchive(t)))
	opts := testOptions(t, f, filepath.Join(t.TempDir(), "imports"))
	cause := errors.New("tuf: connection refused")
	opts.TrustedRoot = func(context.Context) ([]byte, error) { return nil, cause }
	_, err := Run(context.Background(), opts)
	if !errors.Is(err, ErrFetchTrustedRoot) || !errors.Is(err, cause) {
		t.Fatalf("error = %v, want ErrFetchTrustedRoot wrapping the fetch's cause", err)
	}
}

func TestRunMarksReleaseAndRepositoryLookups(t *testing.T) {
	sandboxHome(t)
	f := newFakeGitHub(t, "v1.2.3", digested("tool_1.2.3_linux_amd64.tar.gz", toolArchive(t)))
	opts := testOptions(t, f, filepath.Join(t.TempDir(), "imports"))
	opts.Tag = "v9.9.9"
	_, err := Run(context.Background(), opts)
	var le *LookupError
	var nf *ghrelease.NotFoundError
	if !errors.As(err, &le) || le.Lookup != "release" || !errors.As(err, &nf) {
		t.Fatalf("error = %v, want a release *LookupError wrapping *ghrelease.NotFoundError", err)
	}
}

package repo

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

// stageTrustedRoot copies the public-good trusted_root.json fixture to
// <manifest dir>/imports/trusted_root.json, appends a sigstore_roots entry
// naming it (manifest-relative) to the manifest at mPath, and returns the
// manifest bytes from before the append so a test can drop the entry again.
func stageTrustedRoot(t *testing.T, mPath string) (before []byte) {
	t.Helper()
	raw, err := os.ReadFile(publicGoodTrustedRoot)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(filepath.Dir(mPath), "imports")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "trusted_root.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return appendSigstoreRoots(t, mPath, "./imports/trusted_root.json")
}

// appendSigstoreRoots appends a top-level sigstore_roots list to the manifest
// at mPath and returns the manifest bytes from before the append.
func appendSigstoreRoots(t *testing.T, mPath string, entries ...string) (before []byte) {
	t.Helper()
	before, err := os.ReadFile(mPath)
	if err != nil {
		t.Fatal(err)
	}
	body := append([]byte{}, before...)
	body = append(body, "sigstore_roots:\n"...)
	for _, e := range entries {
		body = append(body, "  - "+e+"\n"...)
	}
	if err := os.WriteFile(mPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return before
}

// readPublishedBundle parses <pub>/trust-bundle.json with the strict parser.
func readPublishedBundle(t *testing.T, pub string) *schema.TrustBundle {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(pub, "trust-bundle.json"))
	if err != nil {
		t.Fatalf("read trust-bundle.json: %v", err)
	}
	tb, err := schema.ParseTrustBundle(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse trust-bundle.json: %v", err)
	}
	return tb
}

// publicGoodRoots is the conversion of the public-good fixture, the roots a
// build with that fixture in sigstore_roots must publish.
func publicGoodRoots(t *testing.T) []schema.SigstoreRoot {
	t.Helper()
	roots, err := sigstoreRootsFromFile("fixture", publicGoodTrustedRoot)
	if err != nil {
		t.Fatal(err)
	}
	return roots
}

func TestBuildPublishesSigstoreRoots(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	stageTrustedRoot(t, mPath)
	pub := filepath.Join(filepath.Dir(mPath), "public")

	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	r1, err := b.Build(BuildOptions{})
	if err != nil {
		t.Fatalf("build with sigstore_roots: %v", err)
	}
	tb := readPublishedBundle(t, pub)
	if len(tb.BuilderKeys) != 0 {
		t.Fatalf("builder keys = %+v, want none (nothing carried)", tb.BuilderKeys)
	}
	if want := publicGoodRoots(t); !reflect.DeepEqual(tb.SigstoreRoots, want) {
		t.Fatalf("published roots = %+v\nwant %+v", tb.SigstoreRoots, want)
	}

	// Consumer path: the signed bundle verifies under the repo key, selects
	// only the open-ended CA's root for a current bundle, and selects both CAs'
	// roots, newest first, for a bundle from their 2022 overlap.
	read := func(name string) []byte {
		raw, rerr := os.ReadFile(filepath.Join(pub, name))
		if rerr != nil {
			t.Fatal(rerr)
		}
		return raw
	}
	v, err := trust.NewVerifier("polypkg-native", b.key.PublicKeyFile("anchor"), "example")
	if err != nil {
		t.Fatal(err)
	}
	bundle, _, _, err := v.LoadBundle(read("trust-bundle.json"), string(read("trust-bundle.json.minisig")), 0, "")
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	froms := func(roots []schema.SigstoreRoot) []string {
		out := make([]string, 0, len(roots))
		for _, r := range roots {
			out = append(out, r.ValidFrom)
		}
		return out
	}
	if got := froms(bundle.SigstoreRootsAt(time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC))); !slices.Equal(got, []string{"2022-04-13T20:06:15Z"}) {
		t.Fatalf("SigstoreRootsAt(2025) valid_from = %q; want only the open-ended 2022 CA root", got)
	}
	if got := froms(bundle.SigstoreRootsAt(time.Date(2022, 6, 1, 0, 0, 0, 0, time.UTC))); !slices.Equal(got, []string{"2022-04-13T20:06:15Z", "2021-03-07T03:20:29Z"}) {
		t.Fatalf("SigstoreRootsAt(2022-06) valid_from = %q; want both CA roots, newest first", got)
	}

	// A rebuild with nothing changed is a no-op: same serial, same bytes.
	before := read("trust-bundle.json")
	b2, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := b2.Build(BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if r2.Changed || r2.SerialAfter != r1.SerialAfter {
		t.Fatalf("no-op rebuild: changed=%v serial %d→%d, want unchanged", r2.Changed, r1.SerialAfter, r2.SerialAfter)
	}
	if !bytes.Equal(before, read("trust-bundle.json")) {
		t.Fatal("trust-bundle.json bytes changed on a no-op rebuild")
	}
}

func TestBuildMergesSigstoreRootsWithCarriedRoots(t *testing.T) {
	root := t.TempDir()
	converted := publicGoodRoots(t)
	// A real chain, so the build can fingerprint its root; the window alone
	// makes it a distinct root.
	distinct := converted[0]
	distinct.ValidFrom = "2019-01-01T00:00:00Z"
	// The carried bundle repeats one converted root (must publish once) and
	// adds one the sigstore_roots file does not have.
	sp := stageOnePrebuilt(t, root, "hello", bundleWithRoots(t, "1111111111111111", "QUFB", converted[1], distinct))
	mPath, keyDir := writePrebuiltManifest(t, root, sp)
	stageTrustedRoot(t, mPath)

	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(BuildOptions{}); err != nil {
		t.Fatalf("build: %v", err)
	}
	tb := readPublishedBundle(t, filepath.Join(root, "public"))
	want := []schema.SigstoreRoot{converted[0], converted[1], distinct}
	if !reflect.DeepEqual(tb.SigstoreRoots, want) {
		t.Fatalf("published roots = %+v\nwant sigstore_roots first, then the carried root not already present: %+v", tb.SigstoreRoots, want)
	}
	if len(tb.BuilderKeys) != 1 || tb.BuilderKeys[0].KeyID != "1111111111111111" {
		t.Fatalf("carried builder keys = %+v", tb.BuilderKeys)
	}
}

func TestBuildRefusesBadSigstoreRoot(t *testing.T) {
	for name, write := range map[string]func(t *testing.T, path string){
		"malformed": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte(`{"mediaType": 7}`), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"missing": func(*testing.T, string) {},
	} {
		t.Run(name, func(t *testing.T) {
			mPath, keyDir := newTestRepo(t)
			write(t, filepath.Join(filepath.Dir(mPath), "bad-root.json"))
			appendSigstoreRoots(t, mPath, "./bad-root.json")

			b, err := NewBuilder(mPath, keyDir, "pw")
			if err != nil {
				t.Fatal(err)
			}
			_, err = b.Build(BuildOptions{})
			var pe *PublishError
			if !errors.As(err, &pe) {
				t.Fatalf("Build error = %v (%T), want a *PublishError", err, err)
			}
			if !strings.Contains(pe.Msg, "./bad-root.json") {
				t.Fatalf("Msg = %q, want it to name the sigstore_roots entry", pe.Msg)
			}
			// Nothing is published by a build that fails on its trust roots.
			if _, statErr := os.Stat(filepath.Join(filepath.Dir(mPath), "public", "index.json")); !os.IsNotExist(statErr) {
				t.Fatalf("index.json published by a failed build (stat err=%v)", statErr)
			}
		})
	}
}

func TestBuildWithdrawsTrustBundleWhenSigstoreRootsRemoved(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	original := stageTrustedRoot(t, mPath)
	pub := filepath.Join(filepath.Dir(mPath), "public")

	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	r1, err := b.Build(BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mPath, original, 0o644); err != nil {
		t.Fatal(err)
	}
	b2, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := b2.Build(BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !r2.Changed || r2.SerialAfter <= r1.SerialAfter {
		t.Fatalf("dropping sigstore_roots: changed=%v serial %d→%d, want a re-signed serial bump", r2.Changed, r1.SerialAfter, r2.SerialAfter)
	}
	for _, f := range []string{"trust-bundle.json", "trust-bundle.json.minisig"} {
		if _, statErr := os.Stat(filepath.Join(pub, f)); !os.IsNotExist(statErr) {
			t.Fatalf("%s still published after sigstore_roots was removed (stat err=%v)", f, statErr)
		}
	}
}

// TestPendingTracksSigstoreRoots pins that `repo status` agrees with `repo
// build` about the trust bundle: adding, and later dropping, a sigstore_roots
// entry is pending until a build publishes (or withdraws) the bundle.
func TestPendingTracksSigstoreRoots(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	build := func() {
		t.Helper()
		b, err := NewBuilder(mPath, keyDir, "pw")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := b.Build(BuildOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	pending := func() (bool, string) {
		t.Helper()
		insp, err := NewInspector(mPath, keyDir)
		if err != nil {
			t.Fatal(err)
		}
		p, reason, err := insp.Pending()
		if err != nil {
			t.Fatalf("Pending: %v", err)
		}
		return p, reason
	}

	build()
	if p, reason := pending(); p {
		t.Fatalf("freshly built repo is pending: %q", reason)
	}
	original := stageTrustedRoot(t, mPath)
	if p, reason := pending(); !p || !strings.Contains(reason, "trust bundle") {
		t.Fatalf("after adding sigstore_roots: pending=%v reason=%q, want a pending trust-bundle change", p, reason)
	}
	build()
	if p, reason := pending(); p {
		t.Fatalf("after publishing the roots: pending with %q", reason)
	}
	if err := os.WriteFile(mPath, original, 0o644); err != nil {
		t.Fatal(err)
	}
	if p, reason := pending(); !p || !strings.Contains(reason, "trust bundle") {
		t.Fatalf("after dropping sigstore_roots: pending=%v reason=%q, want the published bundle's withdrawal pending", p, reason)
	}
	build()
	if p, reason := pending(); p {
		t.Fatalf("after withdrawing the bundle: pending with %q", reason)
	}
}

func TestPendingReportsBadSigstoreRoot(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	appendSigstoreRoots(t, mPath, "./missing-root.json")
	insp, err := NewInspector(mPath, keyDir)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = insp.Pending()
	var pe *PublishError
	if !errors.As(err, &pe) || !strings.Contains(pe.Msg, "./missing-root.json") {
		t.Fatalf("Pending error = %v, want a *PublishError naming ./missing-root.json", err)
	}
}

// buildOnce runs one build of the repository at mPath and returns its result.
func buildOnce(t *testing.T, mPath, keyDir string) Result {
	t.Helper()
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	r, err := b.Build(BuildOptions{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return r
}

// pendingReason reports `repo status`'s view of the repository at mPath.
func pendingReason(t *testing.T, mPath, keyDir string) (bool, string) {
	t.Helper()
	insp, err := NewInspector(mPath, keyDir)
	if err != nil {
		t.Fatal(err)
	}
	p, reason, err := insp.Pending()
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	return p, reason
}

// TestBuildRepublishesReorderedSigstoreRoots pins that root order is part of
// the published trust set: consumers take the first root whose window holds a
// bundle's time, so swapping two sigstore_roots entries whose roots share a
// start time changes which root verifies. Status must report it and the build
// must re-sign the new order at the next serial.
func TestBuildRepublishesReorderedSigstoreRoots(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	imports := filepath.Join(filepath.Dir(mPath), "imports")
	if err := os.MkdirAll(imports, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTrustedRootDoc(t, imports, "a.json", loadTrustedRootDoc(t, publicGoodTrustedRoot))
	// b.json keeps only the open-ended 2022 CA, now bounded: same start as
	// a.json's newest root, different window.
	b := loadTrustedRootDoc(t, publicGoodTrustedRoot)
	var kept []any
	for _, ca := range docList(t, b, "certificateAuthorities") {
		vf := ca["validFor"].(map[string]any)
		if _, bounded := vf["end"]; !bounded {
			vf["end"] = "2030-01-01T00:00:00Z"
			kept = append(kept, ca)
		}
	}
	b["certificateAuthorities"] = kept
	writeTrustedRootDoc(t, imports, "b.json", b)

	original := appendSigstoreRoots(t, mPath, "./imports/a.json", "./imports/b.json")
	pub := filepath.Join(filepath.Dir(mPath), "public")
	r1 := buildOnce(t, mPath, keyDir)
	first := readPublishedBundle(t, pub).SigstoreRoots
	if len(first) != 3 || first[0].ValidFrom != first[2].ValidFrom || first[0].ValidUntil == first[2].ValidUntil {
		t.Fatalf("published roots = %+v, want a.json's two roots then b.json's one, the first and last sharing a start", first)
	}

	if err := os.WriteFile(mPath, original, 0o644); err != nil {
		t.Fatal(err)
	}
	appendSigstoreRoots(t, mPath, "./imports/b.json", "./imports/a.json")
	if p, reason := pendingReason(t, mPath, keyDir); !p || !strings.Contains(reason, "trust bundle") {
		t.Fatalf("after reordering sigstore_roots: pending=%v reason=%q, want a pending trust-bundle change", p, reason)
	}
	r2 := buildOnce(t, mPath, keyDir)
	if !r2.Changed || r2.SerialAfter != r1.SerialAfter+1 {
		t.Fatalf("reordering sigstore_roots: changed=%v serial %d→%d, want a re-signed bump by one", r2.Changed, r1.SerialAfter, r2.SerialAfter)
	}
	want := []schema.SigstoreRoot{first[2], first[0], first[1]}
	if got := readPublishedBundle(t, pub).SigstoreRoots; !reflect.DeepEqual(got, want) {
		t.Fatalf("published roots after reorder = %+v\nwant %+v", got, want)
	}
}

// TestSigstoreRootsChangeBumpsSerialByOne pins that on an already-built
// repository a change to the root set alone — adding a sigstore_roots entry,
// editing the file it names, withdrawing it — re-signs at exactly the next
// serial.
func TestSigstoreRootsChangeBumpsSerialByOne(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	serial := buildOnce(t, mPath, keyDir).SerialAfter
	step := func(what string) {
		t.Helper()
		r := buildOnce(t, mPath, keyDir)
		if !r.Changed || r.SerialAfter != serial+1 {
			t.Fatalf("%s: changed=%v serial %d→%d, want exactly %d", what, r.Changed, serial, r.SerialAfter, serial+1)
		}
		serial = r.SerialAfter
	}

	original := stageTrustedRoot(t, mPath)
	step("adding sigstore_roots")

	staged := filepath.Join(filepath.Dir(mPath), "imports", "trusted_root.json")
	doc := loadTrustedRootDoc(t, staged)
	var kept []any
	for _, ca := range docList(t, doc, "certificateAuthorities") {
		if _, bounded := ca["validFor"].(map[string]any)["end"]; !bounded {
			kept = append(kept, ca)
		}
	}
	doc["certificateAuthorities"] = kept
	writeTrustedRootDoc(t, filepath.Dir(staged), filepath.Base(staged), doc)
	step("editing the named trusted root")

	if err := os.WriteFile(mPath, original, 0o644); err != nil {
		t.Fatal(err)
	}
	step("withdrawing sigstore_roots")
}

// TestSigstoreRootsEntryPathResolution pins how an entry resolves: an absolute
// path is used as is, any other path is relative to the manifest's directory,
// including one that climbs out of it.
func TestSigstoreRootsEntryPathResolution(t *testing.T) {
	raw, err := os.ReadFile(publicGoodTrustedRoot)
	if err != nil {
		t.Fatal(err)
	}
	for name, entry := range map[string]func(t *testing.T, mPath string) string{
		"absolute": func(t *testing.T, _ string) string {
			p := filepath.Join(t.TempDir(), "trusted_root.json")
			if err := os.WriteFile(p, raw, 0o644); err != nil {
				t.Fatal(err)
			}
			return p
		},
		"parent-relative": func(t *testing.T, mPath string) string {
			dir := filepath.Join(filepath.Dir(filepath.Dir(mPath)), "x")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "trusted_root.json"), raw, 0o644); err != nil {
				t.Fatal(err)
			}
			return "../x/trusted_root.json"
		},
	} {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			mPath, keyDir := newTestRepo(t)
			// Move the repository one level down so ../x stays inside this test's
			// temporary directory.
			repoDir := filepath.Join(parent, "repo")
			if err := os.Rename(filepath.Dir(mPath), repoDir); err != nil {
				t.Fatal(err)
			}
			mPath = filepath.Join(repoDir, filepath.Base(mPath))
			appendSigstoreRoots(t, mPath, entry(t, mPath))
			buildOnce(t, mPath, keyDir)
			if got, want := readPublishedBundle(t, filepath.Join(repoDir, "public")).SigstoreRoots, publicGoodRoots(t); !reflect.DeepEqual(got, want) {
				t.Fatalf("published roots = %+v\nwant %+v", got, want)
			}
		})
	}
}

// The public-good fixture's two Fulcio roots, in the order the conversion
// publishes them (newest CA first): the SHA-256 of each root certificate's
// DER.
const (
	publicGoodFulcioRoot2022 = "3ba7b6cc4e95469d4d334b49cb257ad8537076fa84b0ca87ff4ecfe6a54680c1"
	publicGoodFulcioRoot2021 = "03a38ffb1f450100c2596d1d10b900ac4d504058006dda58199576bbeb9c73d0"
)

func TestBuildAndInspectorReportTheTrustBundleChange(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	build := func() Result {
		t.Helper()
		b, err := NewBuilder(mPath, keyDir, "pw")
		if err != nil {
			t.Fatal(err)
		}
		r, err := b.Build(BuildOptions{})
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		return r
	}
	pending := func() *TrustBundleChange {
		t.Helper()
		insp, err := NewInspector(mPath, keyDir)
		if err != nil {
			t.Fatal(err)
		}
		c, err := insp.TrustBundleChange()
		if err != nil {
			t.Fatalf("TrustBundleChange: %v", err)
		}
		return c
	}

	if r := build(); r.TrustBundle != nil {
		t.Fatalf("a build with no sigstore_roots reported a trust bundle change: %+v", r.TrustBundle)
	}

	before := stageTrustedRoot(t, mPath)
	published := &TrustBundleChange{Roots: []SigstoreRootSummary{
		{FulcioRootSHA256: publicGoodFulcioRoot2022, ValidFrom: "2022-04-13T20:06:15Z"},
		{FulcioRootSHA256: publicGoodFulcioRoot2021, ValidFrom: "2021-03-07T03:20:29Z", ValidUntil: "2022-12-31T23:59:59.999Z"},
	}}
	if got := pending(); !reflect.DeepEqual(got, published) {
		t.Fatalf("pending change = %+v\nwant %+v", got, published)
	}
	if r := build(); !reflect.DeepEqual(r.TrustBundle, published) {
		t.Fatalf("build reported %+v\nwant %+v", r.TrustBundle, published)
	}
	if got := pending(); got != nil {
		t.Fatalf("after the build published the bundle, a change is still pending: %+v", got)
	}
	if r := build(); r.TrustBundle != nil {
		t.Fatalf("an unchanged rebuild reported a trust bundle change: %+v", r.TrustBundle)
	}

	if err := os.WriteFile(mPath, before, 0o644); err != nil {
		t.Fatal(err)
	}
	withdrawn := &TrustBundleChange{Withdrawn: true}
	if got := pending(); !reflect.DeepEqual(got, withdrawn) {
		t.Fatalf("pending change after dropping sigstore_roots = %+v, want %+v", got, withdrawn)
	}
	if r := build(); !reflect.DeepEqual(r.TrustBundle, withdrawn) {
		t.Fatalf("build after dropping sigstore_roots reported %+v, want %+v", r.TrustBundle, withdrawn)
	}
}

func TestTrustBundleSummaryListsBuilderKeysInPublishedOrder(t *testing.T) {
	s := trustBundleSet{
		keys: map[string]schema.BuilderKey{
			"k2": {KeyID: "k2", ValidFrom: "2025-01-01T00:00:00Z"},
			"k1": {KeyID: "k1", ValidFrom: "2024-01-01T00:00:00Z", ValidUntil: "2025-01-01T00:00:00Z"},
		},
		order: []string{"k2", "k1"},
	}
	got, err := s.summary(true, false)
	if err != nil {
		t.Fatal(err)
	}
	want := &TrustBundleChange{BuilderKeys: []BuilderKeySummary{
		{KeyID: "k2", ValidFrom: "2025-01-01T00:00:00Z"},
		{KeyID: "k1", ValidFrom: "2024-01-01T00:00:00Z", ValidUntil: "2025-01-01T00:00:00Z"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("summary = %+v\nwant %+v", got, want)
	}
}

func TestTrustBundleSummaryRefusesAFulcioChainWithNoUsableRoot(t *testing.T) {
	intermediateOnly := publicGoodRoots(t)[0]
	intermediateOnly.FulcioCA = intermediateOnly.FulcioCA[1:]
	for _, tc := range []struct {
		name string
		root schema.SigstoreRoot
	}{
		{"a certificate that is not base64", schema.SigstoreRoot{ValidFrom: "2024-01-01T00:00:00Z", FulcioCA: []string{"%%%"}, RekorKeys: []string{"k"}}},
		{"a chain with no self-signed certificate", intermediateOnly},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := trustBundleSet{roots: []schema.SigstoreRoot{tc.root}}
			_, err := s.summary(true, false)
			var pe *PublishError
			if !errors.As(err, &pe) {
				t.Fatalf("want a *PublishError, got %T: %v", err, err)
			}
			if !strings.Contains(pe.Msg, "has no usable Fulcio root certificate") {
				t.Fatalf("Msg = %q", pe.Msg)
			}
		})
	}
}

// A carried bundle keeps its upstream's chain order, which may list an
// intermediate first: the fingerprint is of the self-signed root wherever it
// sits in the chain.
func TestTrustBundleSummaryFingerprintsTheSelfSignedRootInAnyChainOrder(t *testing.T) {
	r := publicGoodRoots(t)[0]
	if len(r.FulcioCA) < 2 {
		t.Fatalf("the fixture's first root has %d certificates; the test needs a chain", len(r.FulcioCA))
	}
	r.FulcioCA = append(slices.Clone(r.FulcioCA[1:]), r.FulcioCA[0])
	got, err := trustBundleSet{roots: []schema.SigstoreRoot{r}}.summary(true, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Roots[0].FulcioRootSHA256 != publicGoodFulcioRoot2022 {
		t.Fatalf("fingerprint = %s, want the self-signed root %s", got.Roots[0].FulcioRootSHA256, publicGoodFulcioRoot2022)
	}
}

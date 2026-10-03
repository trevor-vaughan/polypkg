package repo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writePublishedIndex drops a minimal index.json with the given expires into
// dir so publishedExpires/computeExpires can probe it like real Build output.
func writePublishedIndex(t *testing.T, dir, expires string) {
	t.Helper()
	body := `{"schema":"polypkg.index/v2","expires":"` + expires + `","packages":{}}`
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestComputeExpiresFreshWhenNoPublishedIndex(t *testing.T) {
	dir := t.TempDir()
	validFor := 720 * time.Hour

	got, reused := computeExpires(time.Now(), dir, false, validFor, validFor)
	if reused {
		t.Fatal("no published index to reuse")
	}
	ts, err := time.Parse(time.RFC3339, got)
	if err != nil {
		t.Fatalf("expires %q is not RFC3339: %v", got, err)
	}
	want := time.Now().UTC().Add(validFor)
	if d := ts.Sub(want); d < -time.Minute || d > time.Minute {
		t.Fatalf("expires %s not within a minute of now+validFor (%s)", ts, want)
	}
}

func TestComputeExpiresReusesPublishedWhenUnchangedAndFresh(t *testing.T) {
	dir := t.TempDir()
	validFor := 720 * time.Hour
	// Well over half the window remains.
	published := time.Now().UTC().Add(700 * time.Hour).Format(time.RFC3339)
	writePublishedIndex(t, dir, published)

	got, reused := computeExpires(time.Now(), dir, false, validFor, validFor)
	if got != published || !reused {
		t.Fatalf("computeExpires = (%q, reused=%v), want (%q, true)", got, reused, published)
	}
}

func TestComputeExpiresRestampsWhenContentChanged(t *testing.T) {
	dir := t.TempDir()
	validFor := 720 * time.Hour
	published := time.Now().UTC().Add(700 * time.Hour).Format(time.RFC3339)
	writePublishedIndex(t, dir, published)

	got, reused := computeExpires(time.Now(), dir, true, validFor, validFor)
	if got == published || reused {
		t.Fatalf("computeExpires reused %q despite content change", got)
	}
}

func TestComputeExpiresRestampsWhenUnderHalfWindow(t *testing.T) {
	dir := t.TempDir()
	validFor := 720 * time.Hour
	// Under half the window remains → renewal even without content change.
	published := time.Now().UTC().Add(100 * time.Hour).Format(time.RFC3339)
	writePublishedIndex(t, dir, published)

	got, reused := computeExpires(time.Now(), dir, false, validFor, validFor)
	if got == published || reused {
		t.Fatalf("computeExpires reused %q with under half the window left", got)
	}
	ts, err := time.Parse(time.RFC3339, got)
	if err != nil {
		t.Fatalf("expires %q is not RFC3339: %v", got, err)
	}
	want := time.Now().UTC().Add(validFor)
	if d := ts.Sub(want); d < -time.Minute || d > time.Minute {
		t.Fatalf("restamped expires %s not within a minute of now+validFor (%s)", ts, want)
	}
}

func TestBuildStampsSharedExpiresIntoIndexAndTrust(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	pub := filepath.Join(filepath.Dir(mPath), "public")

	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(BuildOptions{}); err != nil {
		t.Fatal(err)
	}

	var idx struct {
		Schema  string `json:"schema"`
		Expires string `json:"expires"`
	}
	raw, err := os.ReadFile(filepath.Join(pub, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatal(err)
	}
	var td struct {
		Schema  string `json:"schema"`
		Expires string `json:"expires"`
	}
	raw, err = os.ReadFile(filepath.Join(pub, "trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &td); err != nil {
		t.Fatal(err)
	}

	if idx.Schema != "polypkg.index/v2" || td.Schema != "polypkg.trust/v2" {
		t.Fatalf("schemas = %q / %q, want v2 pair", idx.Schema, td.Schema)
	}
	if idx.Expires == "" {
		t.Fatal("index has no expires")
	}
	if idx.Expires != td.Expires {
		t.Fatalf("index expires %q != trust expires %q (must share one value)", idx.Expires, td.Expires)
	}
	if _, err := time.Parse(time.RFC3339, idx.Expires); err != nil {
		t.Fatalf("expires %q is not RFC3339: %v", idx.Expires, err)
	}
}

func TestComputeExpiresRestampsWhenPublishedUnparseable(t *testing.T) {
	dir := t.TempDir()
	validFor := 720 * time.Hour
	writePublishedIndex(t, dir, "not-a-timestamp")

	got, reused := computeExpires(time.Now(), dir, false, validFor, validFor)
	if reused {
		t.Fatalf("computeExpires reused the unparseable published expiry %q", got)
	}
	if _, err := time.Parse(time.RFC3339, got); err != nil {
		t.Fatalf("expires %q is not RFC3339: %v", got, err)
	}
}

func TestPendingReportsExpiryRefresh(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	pub := filepath.Join(filepath.Dir(mPath), "public")

	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(BuildOptions{}); err != nil {
		t.Fatal(err)
	}

	// Freshly built with the default window → nothing pending.
	insp, err := NewInspector(mPath, keyDir)
	if err != nil {
		t.Fatal(err)
	}
	pending, reason, err := insp.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if pending {
		t.Fatalf("fresh build must not be pending, got reason %q", reason)
	}

	// Rewrite the published index's expires to now+1h — below the 360h
	// half-life of the default window. Pending only READS the JSON (it never
	// verifies signatures), so the resulting stale signature is irrelevant
	// here; Build would restamp and re-sign, so status must say pending.
	idxPath := filepath.Join(pub, "index.json")
	raw, err := os.ReadFile(idxPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["expires"] = time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	edited, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(idxPath, edited, 0o644); err != nil {
		t.Fatal(err)
	}

	pending, reason, err = insp.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if !pending {
		t.Fatal("near-expiry published window must be pending")
	}
	if reason != "metadata expiry refresh due" {
		t.Fatalf("reason = %q, want %q", reason, "metadata expiry refresh due")
	}
}

func TestPendingReportsExpiryRefreshWhenExpiresAbsent(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	pub := filepath.Join(filepath.Dir(mPath), "public")

	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(BuildOptions{}); err != nil {
		t.Fatal(err)
	}

	// Strip expires entirely (unparseable/absent path): Build would restamp,
	// so status must report pending.
	idxPath := filepath.Join(pub, "index.json")
	raw, err := os.ReadFile(idxPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc, "expires")
	edited, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(idxPath, edited, 0o644); err != nil {
		t.Fatal(err)
	}

	insp, err := NewInspector(mPath, keyDir)
	if err != nil {
		t.Fatal(err)
	}
	pending, reason, err := insp.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if !pending || reason != "metadata expiry refresh due" {
		t.Fatalf("missing expires must be pending with the expiry reason, got pending=%v reason=%q", pending, reason)
	}
}

// loadCacheFor reads the build cache a Builder/Inspector for mPath would use.
func loadCacheFor(t *testing.T, mPath, keyDir string) *BuildCache {
	t.Helper()
	lay, err := loadLayout(mPath, keyDir)
	if err != nil {
		t.Fatal(err)
	}
	c, err := LoadBuildCache(lay.cachePath)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestBuildRecordsValidForInCache pins the mechanism the half-life rule now
// rests on: the published documents do not say what window produced their
// expiry (index.json has no issued_at, and trust.json's is pinned to the epoch
// for deterministic signatures), so Build records it in the cache.
func TestBuildRecordsValidForInCache(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(BuildOptions{ValidFor: 24 * time.Hour}); err != nil {
		t.Fatal(err)
	}
	if got := loadCacheFor(t, mPath, keyDir).ValidFor; got != 24*time.Hour {
		t.Fatalf("cache valid_for = %s, want 24h", got)
	}

	// A rebuild that reuses the published expiry must NOT overwrite the recorded
	// window with the one it asked for: the recorded window has to keep
	// describing the document that is actually published.
	if _, err := b.Build(BuildOptions{ValidFor: DefaultValidFor}); err != nil {
		t.Fatal(err)
	}
	if got := loadCacheFor(t, mPath, keyDir).ValidFor; got != 24*time.Hour {
		t.Fatalf("cache valid_for = %s after a reusing rebuild, want the published 24h", got)
	}
}

// TestPendingUsesRecordedWindowNotDefault is the regression test for `repo
// status` reporting "metadata expiry refresh due" the instant a build with a
// window under 720h finished. Pending hardcoded DefaultValidFor/2 (360h) as the
// half-life, so a 24h window was below it from the moment it was stamped.
func TestPendingUsesRecordedWindowNotDefault(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	b.insp.now = func() time.Time { return base }
	if _, err := b.Build(BuildOptions{ValidFor: 24 * time.Hour}); err != nil {
		t.Fatal(err)
	}

	insp, err := NewInspector(mPath, keyDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name        string
		at          time.Duration
		wantPending bool
	}{
		{"immediately after the build", 0, false},
		{"just under the 12h half-life", 11 * time.Hour, false},
		{"just past the 12h half-life", 13 * time.Hour, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			insp.now = func() time.Time { return base.Add(tc.at) }
			pending, reason, perr := insp.Pending()
			if perr != nil {
				t.Fatal(perr)
			}
			if pending != tc.wantPending {
				t.Fatalf("Pending at +%s = %v (%q), want %v", tc.at, pending, reason, tc.wantPending)
			}
			if pending && reason != "metadata expiry refresh due" {
				t.Fatalf("reason = %q, want %q", reason, "metadata expiry refresh due")
			}
		})
	}
}

// TestPendingDefaultWindowUnchanged holds the 720h path exactly where it was:
// pending only once under 360h remains.
func TestPendingDefaultWindowUnchanged(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	b.insp.now = func() time.Time { return base }
	if _, err := b.Build(BuildOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := loadCacheFor(t, mPath, keyDir).ValidFor; got != DefaultValidFor {
		t.Fatalf("cache valid_for = %s, want the %s default", got, DefaultValidFor)
	}

	insp, err := NewInspector(mPath, keyDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		at          time.Duration
		wantPending bool
	}{
		{0, false},
		{359 * time.Hour, false},
		{361 * time.Hour, true},
	} {
		insp.now = func() time.Time { return base.Add(tc.at) }
		pending, reason, perr := insp.Pending()
		if perr != nil {
			t.Fatal(perr)
		}
		if pending != tc.wantPending {
			t.Fatalf("Pending at +%s = %v (%q), want %v", tc.at, pending, reason, tc.wantPending)
		}
	}
}

// TestPendingFallsBackToDefaultWindowForUnrecordedCache covers a build cache
// written before the window was recorded: with nothing to read, the half-life
// rule must keep its previous 720h assumption rather than treat the window as
// zero (which would report pending forever).
func TestPendingFallsBackToDefaultWindowForUnrecordedCache(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	b.insp.now = func() time.Time { return base }
	if _, err := b.Build(BuildOptions{}); err != nil {
		t.Fatal(err)
	}

	// Strip the recorded window, leaving the rest of the cache intact.
	lay, err := loadLayout(mPath, keyDir)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := LoadBuildCache(lay.cachePath)
	if err != nil {
		t.Fatal(err)
	}
	cache.ValidFor = 0
	if err := cache.Save(lay.cachePath); err != nil {
		t.Fatal(err)
	}

	insp, err := NewInspector(mPath, keyDir)
	if err != nil {
		t.Fatal(err)
	}
	insp.now = func() time.Time { return base.Add(359 * time.Hour) }
	if pending, reason, perr := insp.Pending(); perr != nil || pending {
		t.Fatalf("unrecorded window must fall back to %s: pending=%v reason=%q err=%v", DefaultValidFor, pending, reason, perr)
	}
	insp.now = func() time.Time { return base.Add(361 * time.Hour) }
	if pending, _, perr := insp.Pending(); perr != nil || !pending {
		t.Fatalf("past the 360h fallback half-life must be pending: pending=%v err=%v", pending, perr)
	}
}

// TestBuildAndPendingAgreeOnShortWindow is the anti-drift test: Build's reuse
// decision and Pending's prediction of it are two readings of one rule, so they
// must flip together. Before and after the half-life of a 24h window, `repo
// status` and `repo build` must say the same thing.
func TestBuildAndPendingAgreeOnShortWindow(t *testing.T) {
	mPath, keyDir := newTestRepo(t)
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now()
	b.insp.now = func() time.Time { return base }
	if _, err := b.Build(BuildOptions{ValidFor: 24 * time.Hour}); err != nil {
		t.Fatal(err)
	}

	insp, err := NewInspector(mPath, keyDir)
	if err != nil {
		t.Fatal(err)
	}

	// Before the half-life: nothing pending, and a rebuild with the DEFAULT
	// window is still a no-op — the published 24h document has not aged out, and
	// a bare `repo build` must not quietly widen it.
	insp.now = func() time.Time { return base.Add(11 * time.Hour) }
	pending, reason, err := insp.Pending()
	if err != nil {
		t.Fatal(err)
	}
	b.insp.now = func() time.Time { return base.Add(11 * time.Hour) }
	res, err := b.Build(BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if pending || res.Changed {
		t.Fatalf("before the half-life: Pending=%v (%q), Build.Changed=%v; want both false", pending, reason, res.Changed)
	}

	// After it: both must report a refresh.
	insp.now = func() time.Time { return base.Add(13 * time.Hour) }
	pending, reason, err = insp.Pending()
	if err != nil {
		t.Fatal(err)
	}
	b.insp.now = func() time.Time { return base.Add(13 * time.Hour) }
	res, err = b.Build(BuildOptions{ValidFor: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if !pending || !res.Changed {
		t.Fatalf("after the half-life: Pending=%v (%q), Build.Changed=%v; want both true", pending, reason, res.Changed)
	}
	if !res.ValidForApplied {
		t.Fatal("a restamping build must report the window as applied")
	}
}

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

	got := computeExpires(dir, false, validFor)
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

	if got := computeExpires(dir, false, validFor); got != published {
		t.Fatalf("computeExpires = %q, want reused %q", got, published)
	}
}

func TestComputeExpiresRestampsWhenContentChanged(t *testing.T) {
	dir := t.TempDir()
	validFor := 720 * time.Hour
	published := time.Now().UTC().Add(700 * time.Hour).Format(time.RFC3339)
	writePublishedIndex(t, dir, published)

	if got := computeExpires(dir, true, validFor); got == published {
		t.Fatalf("computeExpires reused %q despite content change", got)
	}
}

func TestComputeExpiresRestampsWhenUnderHalfWindow(t *testing.T) {
	dir := t.TempDir()
	validFor := 720 * time.Hour
	// Under half the window remains → renewal even without content change.
	published := time.Now().UTC().Add(100 * time.Hour).Format(time.RFC3339)
	writePublishedIndex(t, dir, published)

	got := computeExpires(dir, false, validFor)
	if got == published {
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

	got := computeExpires(dir, false, validFor)
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

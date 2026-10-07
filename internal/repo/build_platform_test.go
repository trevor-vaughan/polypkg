package repo

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

// writePlatformPkgSrc writes a hello 1.0.0 package source under dir whose
// polypkg.yaml declares plat (the key is omitted when plat is ""). body goes
// into content/bin/hello so sources that differ only in body pack to distinct
// artifacts.
func writePlatformPkgSrc(t *testing.T, dir, plat, body string) {
	t.Helper()
	manifest := "schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\n"
	if plat != "" {
		manifest += "platform: " + plat + "\n"
	}
	manifest += "actions: []\n"
	if err := os.MkdirAll(filepath.Join(dir, "content", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "content", "bin", "hello"),
		[]byte("#!/bin/sh\necho "+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// stagePlatformPrebuilt packs a hello 1.0.0 source declaring plat and stages it
// as a prebuilt input under root/staging/<sub>: the artifact at
// <sub>/hello.tar.zst plus a carried SLSA attestation bound to content/bin/hello.
// It returns the YAML list-item body for writeHelloRepo.
func stagePlatformPrebuilt(t *testing.T, root, sub, plat string) string {
	t.Helper()
	srcDir := filepath.Join(root, "origin", sub)
	writePlatformPkgSrc(t, srcDir, plat, sub)
	artifact, _, err := PackArtifact(srcDir)
	if err != nil {
		t.Fatalf("pack %s: %v", sub, err)
	}
	stg := filepath.Join(root, "staging", sub)
	attDir := filepath.Join(stg, "atts")
	if err := os.MkdirAll(attDir, 0o755); err != nil {
		t.Fatal(err)
	}
	artPath := filepath.Join(stg, "hello.tar.zst")
	if err := os.WriteFile(artPath, artifact, 0o644); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(srcDir, "content", "bin", "hello"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attDir, "slsa.json"), dsseSLSA(t, "bin/hello", sha256Bare(body)), 0o644); err != nil {
		t.Fatal(err)
	}
	return "prebuilt:\n        artifact: " + artPath + "\n        attestations: " + attDir
}

// writeHelloRepo (re)writes root/polypkg-repo.yaml with a single package
// "hello" whose entries are items, in order (each the body of one YAML list
// item, e.g. "source: ./pkgs/a"), signed by the key at keyPath. Rewriting with
// the same keyPath keeps the build cache, which lives beside the key.
func writeHelloRepo(t *testing.T, root, keyPath string, items ...string) string {
	t.Helper()
	var sb strings.Builder
	sb.WriteString("schema: polypkg.repo/v1\nsource: repo\noutput: ./public\n")
	sb.WriteString("key:\n  path: " + keyPath + "\n  kdf: scrypt\n")
	sb.WriteString("packages:\n  hello:\n")
	for _, it := range items {
		sb.WriteString("    - " + it + "\n")
	}
	mPath := filepath.Join(root, "polypkg-repo.yaml")
	if err := os.WriteFile(mPath, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return mPath
}

// buildHello runs one Build of the manifest at mPath with a fresh Builder.
// Attestations are skipped: these tests exercise the platform build rules,
// which must hold without lint (the --skip-attestations path never lints).
func buildHello(t *testing.T, mPath, keyDir string) (Result, error) {
	t.Helper()
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	return b.Build(BuildOptions{SkipAttestations: true})
}

// helloEntry returns the single published hello entry for plat ("" for
// platform-agnostic), failing t unless exactly one exists.
func helloEntry(t *testing.T, pub, plat string) schema.IndexEntry {
	t.Helper()
	var found []schema.IndexEntry
	for _, e := range readIndex(t, pub).Packages["hello"] {
		if e.Platform == plat {
			found = append(found, e)
		}
	}
	if len(found) != 1 {
		t.Fatalf("published hello entries for platform %q = %d, want 1", plat, len(found))
	}
	return found[0]
}

// TestBuildPublishesSourcePlatform pins that a source entry's platform comes
// from its polypkg.yaml, reaches the index and the build cache, and survives a
// no-op rebuild that republishes from the cache.
func TestBuildPublishesSourcePlatform(t *testing.T) {
	root := t.TempDir()
	keyDir := t.TempDir()
	keyPath := writeDupVersionKey(t, keyDir)
	writePlatformPkgSrc(t, filepath.Join(root, "pkgs", "a"), "linux/amd64", "a")
	mPath := writeHelloRepo(t, root, keyPath, "source: ./pkgs/a")
	pub := filepath.Join(root, "public")

	if _, err := buildHello(t, mPath, keyDir); err != nil {
		t.Fatalf("build: %v", err)
	}
	if rev := helloEntry(t, pub, "linux/amd64").Revision; rev != 1 {
		t.Fatalf("revision = %d, want 1", rev)
	}
	if got := loadCacheFor(t, mPath, keyDir).Entries["./pkgs/a"].Platform; got != "linux/amd64" {
		t.Fatalf("cached platform = %q, want linux/amd64", got)
	}

	res, err := buildHello(t, mPath, keyDir)
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if res.Changed {
		t.Fatal("no-op rebuild reported Changed=true")
	}
	helloEntry(t, pub, "linux/amd64")
}

// TestBuildPrebuiltPlatformComesFromArtifact pins that a prebuilt entry's
// platform is read from the extracted artifact's polypkg.yaml (the manifest
// entry declares none) and survives a cache-hit rebuild.
func TestBuildPrebuiltPlatformComesFromArtifact(t *testing.T) {
	root := t.TempDir()
	keyDir := t.TempDir()
	keyPath := writeDupVersionKey(t, keyDir)
	mPath := writeHelloRepo(t, root, keyPath, stagePlatformPrebuilt(t, root, "a", "darwin/arm64"))
	pub := filepath.Join(root, "public")

	if _, err := buildHello(t, mPath, keyDir); err != nil {
		t.Fatalf("build: %v", err)
	}
	e := helloEntry(t, pub, "darwin/arm64")
	if got := loadCacheFor(t, mPath, keyDir).Entries[e.ContentHash].Platform; got != "darwin/arm64" {
		t.Fatalf("cached platform = %q, want darwin/arm64", got)
	}

	res, err := buildHello(t, mPath, keyDir)
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if res.Changed {
		t.Fatal("no-op prebuilt rebuild reported Changed=true")
	}
	helloEntry(t, pub, "darwin/arm64")
}

// TestNextRevisionKeysOnPlatform pins that the revision ordinal belongs to one
// (name, version, platform): each platform's artifact is republished on its
// own, so neither the cache nor the published index may hand one platform's
// ordinal to another.
func TestNextRevisionKeysOnPlatform(t *testing.T) {
	pub := &schema.Index{Packages: map[string][]schema.IndexEntry{"hello": {
		{Version: "1.0.0", Platform: "linux/amd64", ContentHash: "blake3:aa", Revision: 3},
		{Version: "1.0.0", Platform: "darwin/arm64", ContentHash: "blake3:bb", Revision: 1},
	}}}
	cold := NewBuildCache()
	warm := NewBuildCache()
	warm.Put("./pkgs/a", CacheEntry{Version: "1.0.0", Platform: "linux/amd64", ContentHash: "blake3:aa", Revision: 5})

	cases := []struct {
		name  string
		cache *BuildCache
		pub   *schema.Index
		plat  string
		ch    string
		want  int
	}{
		{"published entry, same platform and hash, keeps its revision", cold, pub, "linux/amd64", "blake3:aa", 3},
		{"published entry, same platform, new hash, bumps", cold, pub, "linux/amd64", "blake3:cc", 4},
		{"another platform's published revision is not inherited", cold, pub, "darwin/arm64", "blake3:cc", 2},
		{"a platform never published starts at 1", cold, pub, "freebsd/amd64", "blake3:cc", 1},
		{"platform-agnostic does not inherit a platform's revision", cold, pub, "", "blake3:aa", 1},
		{"cache entry for the same platform wins", warm, pub, "linux/amd64", "blake3:dd", 6},
		{"cache entry for another platform is ignored", warm, nil, "darwin/arm64", "blake3:dd", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nextRevision(tc.cache, tc.pub, "./pkgs/a", "hello", "1.0.0", tc.plat, tc.ch); got != tc.want {
				t.Fatalf("nextRevision(platform %q, %s) = %d, want %d", tc.plat, tc.ch, got, tc.want)
			}
		})
	}
}

// artifactClaimPlatform verifies entry's published artifact signature through
// the consumer's own trust path (the published trust.json anchored by the repo
// key, then the artifact-role keyring) and returns the platform the signature
// claims ("" for platform-agnostic). It fails t unless the claim also binds
// hello, the entry's version, and its content hash.
func artifactClaimPlatform(t *testing.T, mPath, keyDir, pub string, entry schema.IndexEntry) string {
	t.Helper()
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) []byte {
		raw, rerr := os.ReadFile(filepath.Join(pub, name))
		if rerr != nil {
			t.Fatal(rerr)
		}
		return raw
	}
	v, err := trust.NewVerifier("polypkg-native", b.key.PublicKeyFile("anchor"), "repo")
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	keyring, _, _, err := v.LoadTrust(read("trust.json"), string(read("trust.json.minisig")), 0, "")
	if err != nil {
		t.Fatalf("LoadTrust: %v", err)
	}
	claims, err := keyring.Verify(trust.RoleArtifact, read(entry.Artifact), string(read(entry.Artifact+".minisig")))
	if err != nil {
		t.Fatalf("artifact signature does not verify: %v", err)
	}
	name, version, plat, hash, err := claims.Artifact()
	if err != nil {
		t.Fatalf("artifact claims: %v", err)
	}
	if name != "hello" || version != entry.Version || hash != entry.ContentHash {
		t.Fatalf("claims name=%s version=%s hash=%s, want hello %s %s", name, version, hash, entry.Version, entry.ContentHash)
	}
	return plat
}

// TestBuildSignsEntryPlatform pins that the artifact signature binds the
// platform the entry publishes, for both entry kinds, and that a cache-hit
// rebuild (which republishes from the cache without re-signing) keeps the
// entry's platform and its signature's claim in agreement.
func TestBuildSignsEntryPlatform(t *testing.T) {
	for _, tc := range []struct {
		name string
		plat string
		item func(t *testing.T, root, plat string) string
	}{
		{"source", "linux/amd64", func(t *testing.T, root, plat string) string {
			writePlatformPkgSrc(t, filepath.Join(root, "pkgs", "a"), plat, "a")
			return "source: ./pkgs/a"
		}},
		{"source platform-agnostic", "", func(t *testing.T, root, plat string) string {
			writePlatformPkgSrc(t, filepath.Join(root, "pkgs", "a"), plat, "a")
			return "source: ./pkgs/a"
		}},
		{"prebuilt", "darwin/arm64", func(t *testing.T, root, plat string) string {
			return stagePlatformPrebuilt(t, root, "a", plat)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			keyDir := t.TempDir()
			keyPath := writeDupVersionKey(t, keyDir)
			mPath := writeHelloRepo(t, root, keyPath, tc.item(t, root, tc.plat))
			pub := filepath.Join(root, "public")

			if _, err := buildHello(t, mPath, keyDir); err != nil {
				t.Fatalf("build: %v", err)
			}
			first := helloEntry(t, pub, tc.plat)
			if got := artifactClaimPlatform(t, mPath, keyDir, pub, first); got != tc.plat {
				t.Fatalf("signature claims platform %q, entry publishes %q", got, tc.plat)
			}

			res, err := buildHello(t, mPath, keyDir)
			if err != nil {
				t.Fatalf("rebuild: %v", err)
			}
			if res.Changed {
				t.Fatal("no-op rebuild reported Changed=true")
			}
			again := helloEntry(t, pub, tc.plat)
			if again.ContentHash != first.ContentHash || again.Artifact != first.Artifact || again.Revision != first.Revision {
				t.Fatalf("cache-hit rebuild changed the entry: %+v -> %+v", first, again)
			}
			if got := artifactClaimPlatform(t, mPath, keyDir, pub, again); got != tc.plat {
				t.Fatalf("after a cache-hit rebuild the signature claims platform %q, entry publishes %q", got, tc.plat)
			}
		})
	}
}

// TestBuildPublishesOneEntryPerPlatform pins that two platforms of one version
// both publish, and that each keeps its own revision: republishing the linux
// artifact bumps only the linux revision.
func TestBuildPublishesOneEntryPerPlatform(t *testing.T) {
	root := t.TempDir()
	keyDir := t.TempDir()
	keyPath := writeDupVersionKey(t, keyDir)
	writePlatformPkgSrc(t, filepath.Join(root, "pkgs", "a"), "linux/amd64", "a")
	writePlatformPkgSrc(t, filepath.Join(root, "pkgs", "b"), "darwin/arm64", "b")
	mPath := writeHelloRepo(t, root, keyPath, "source: ./pkgs/a", "source: ./pkgs/b")
	pub := filepath.Join(root, "public")

	if _, err := buildHello(t, mPath, keyDir); err != nil {
		t.Fatalf("build: %v", err)
	}
	linux1 := helloEntry(t, pub, "linux/amd64")
	darwin1 := helloEntry(t, pub, "darwin/arm64")
	if linux1.Revision != 1 || darwin1.Revision != 1 {
		t.Fatalf("revisions = linux %d, darwin %d; want 1 and 1", linux1.Revision, darwin1.Revision)
	}
	if linux1.ContentHash == darwin1.ContentHash {
		t.Fatal("both platforms published the same artifact")
	}

	mutatePkgSrc(t, filepath.Join(root, "pkgs", "a"))
	if _, err := buildHello(t, mPath, keyDir); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	linux2 := helloEntry(t, pub, "linux/amd64")
	darwin2 := helloEntry(t, pub, "darwin/arm64")
	if linux2.Revision != 2 {
		t.Fatalf("linux revision after republish = %d, want 2", linux2.Revision)
	}
	if darwin2.Revision != 1 || darwin2.ContentHash != darwin1.ContentHash {
		t.Fatalf("darwin entry changed on a linux-only republish: %+v", darwin2)
	}
}

// TestBuildPublishesOnePrebuiltPerPlatform covers the same rule for prebuilt
// entries, whose platform is read from inside each artifact.
func TestBuildPublishesOnePrebuiltPerPlatform(t *testing.T) {
	root := t.TempDir()
	keyDir := t.TempDir()
	keyPath := writeDupVersionKey(t, keyDir)
	mPath := writeHelloRepo(t, root, keyPath,
		stagePlatformPrebuilt(t, root, "a", "linux/amd64"),
		stagePlatformPrebuilt(t, root, "b", "darwin/arm64"))
	pub := filepath.Join(root, "public")

	if _, err := buildHello(t, mPath, keyDir); err != nil {
		t.Fatalf("build: %v", err)
	}
	helloEntry(t, pub, "linux/amd64")
	helloEntry(t, pub, "darwin/arm64")
}

// TestBuildRefusesMixedPlatformAgnosticVersion pins the mixed
// agnostic/platform rule: a host matching the linux entry would otherwise see
// two candidates for hello 1.0.0.
func TestBuildRefusesMixedPlatformAgnosticVersion(t *testing.T) {
	root := t.TempDir()
	keyDir := t.TempDir()
	keyPath := writeDupVersionKey(t, keyDir)
	writePlatformPkgSrc(t, filepath.Join(root, "pkgs", "a"), "", "a")
	writePlatformPkgSrc(t, filepath.Join(root, "pkgs", "b"), "linux/amd64", "b")
	mPath := writeHelloRepo(t, root, keyPath, "source: ./pkgs/a", "source: ./pkgs/b")

	_, err := buildHello(t, mPath, keyDir)
	if err == nil {
		t.Fatal("Build accepted a platform-agnostic and a linux/amd64 entry for hello 1.0.0")
	}
	for _, want := range []string{"1.0.0", "platform-agnostic entry (./pkgs/a)", "linux/amd64 entry (./pkgs/b)"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
	// The remedy must also fit a prebuilt entry, whose polypkg.yaml is
	// sealed inside a signed artifact.
	var pe *PublishError
	if !errors.As(err, &pe) || !strings.Contains(pe.Hint, "rebuild a prebuilt artifact") {
		t.Fatalf("error %v carries no remedy for a prebuilt entry", err)
	}
}

// TestBuildRefusesDuplicatePlatformOnCacheHit pins the one entry per
// (version, platform) rule on the source cache-hit path: ./pkgs/a is cached by
// the first build, so only the cache-hit check can see it when ./pkgs/b (same
// version, same platform) is added.
func TestBuildRefusesDuplicatePlatformOnCacheHit(t *testing.T) {
	root := t.TempDir()
	keyDir := t.TempDir()
	keyPath := writeDupVersionKey(t, keyDir)
	writePlatformPkgSrc(t, filepath.Join(root, "pkgs", "a"), "linux/amd64", "a")
	writePlatformPkgSrc(t, filepath.Join(root, "pkgs", "b"), "linux/amd64", "b")

	mPath := writeHelloRepo(t, root, keyPath, "source: ./pkgs/a")
	if _, err := buildHello(t, mPath, keyDir); err != nil {
		t.Fatalf("first build: %v", err)
	}
	writeHelloRepo(t, root, keyPath, "source: ./pkgs/a", "source: ./pkgs/b")
	_, err := buildHello(t, mPath, keyDir)
	if err == nil {
		t.Fatal("Build accepted two linux/amd64 entries for hello 1.0.0")
	}
	for _, want := range []string{"1.0.0", "linux/amd64", "declared twice", "./pkgs/a", "./pkgs/b"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

// TestBuildRefusesDuplicatePrebuiltPlatform pins the one entry per
// (version, platform) rule on the prebuilt path: two distinct artifacts both
// self-describe as hello 1.0.0 for linux/amd64.
func TestBuildRefusesDuplicatePrebuiltPlatform(t *testing.T) {
	root := t.TempDir()
	keyDir := t.TempDir()
	keyPath := writeDupVersionKey(t, keyDir)
	mPath := writeHelloRepo(t, root, keyPath,
		stagePlatformPrebuilt(t, root, "a", "linux/amd64"),
		stagePlatformPrebuilt(t, root, "b", "linux/amd64"))

	_, err := buildHello(t, mPath, keyDir)
	if err == nil {
		t.Fatal("Build accepted two prebuilt linux/amd64 artifacts for hello 1.0.0")
	}
	for _, want := range []string{
		"linux/amd64", "declared twice",
		filepath.Join(root, "staging", "a", "hello.tar.zst"),
		filepath.Join(root, "staging", "b", "hello.tar.zst"),
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

// TestBuildRefusesUnpublishablePlatform pins the producer-validation rule on
// both entry kinds: a well-formed platform outside the producer allow-list
// fails the build before anything is published (no index.json is written).
func TestBuildRefusesUnpublishablePlatform(t *testing.T) {
	for _, tc := range []struct {
		name string
		item func(t *testing.T, root string) string
		// hint holds substrings the refusal's hint must carry: a source's
		// polypkg.yaml can be edited, a signed prebuilt artifact cannot.
		hint    []string
		notHint string
	}{
		{"source", func(t *testing.T, root string) string {
			writePlatformPkgSrc(t, filepath.Join(root, "pkgs", "a"), "linux/amd46", "a")
			return "source: ./pkgs/a"
		}, []string{"set platform: in the package's polypkg.yaml (./pkgs/a)"}, "rebuild"},
		{"prebuilt", func(t *testing.T, root string) string {
			return stagePlatformPrebuilt(t, root, "a", "linux/amd46")
		}, []string{"cannot be edited", "rebuild it from a source", "delete its entry from polypkg-repo.yaml"},
			"set platform: in the package's polypkg.yaml"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			keyDir := t.TempDir()
			keyPath := writeDupVersionKey(t, keyDir)
			mPath := writeHelloRepo(t, root, keyPath, tc.item(t, root))

			_, err := buildHello(t, mPath, keyDir)
			var pe *PublishError
			if !errors.As(err, &pe) {
				t.Fatalf("Build = %v (%T), want a *PublishError refusing linux/amd46", err, err)
			}
			if !strings.Contains(err.Error(), `declares platform "linux/amd46"`) {
				t.Fatalf("error %q does not name the platform", err)
			}
			for _, want := range tc.hint {
				if !strings.Contains(pe.Hint, want) {
					t.Fatalf("hint %q does not mention %q", pe.Hint, want)
				}
			}
			if strings.Contains(pe.Hint, tc.notHint) {
				t.Fatalf("hint %q tells a %s entry to %q", pe.Hint, tc.name, tc.notHint)
			}
			if _, statErr := os.Stat(filepath.Join(root, "public", "index.json")); !errors.Is(statErr, fs.ErrNotExist) {
				t.Fatalf("index.json exists after a refused build (stat err %v)", statErr)
			}
		})
	}
}

// editRecipeKeepingFingerprint replaces old with new (which must be the same
// length) in dir's polypkg.yaml and restores the file's mtime, so the edit
// changes the recipe while SourceFingerprint, which hashes sizes and mtimes,
// stays the same.
func editRecipeKeepingFingerprint(t *testing.T, dir, old, replacement string) {
	t.Helper()
	recipe := filepath.Join(dir, "polypkg.yaml")
	fi, err := os.Stat(recipe)
	if err != nil {
		t.Fatal(err)
	}
	fpBefore, err := SourceFingerprint(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(recipe)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(raw), old, replacement, 1)
	if edited == string(raw) || len(edited) != len(raw) {
		t.Fatalf("test premise: replacing %q with %q must change the recipe and keep the file size", old, replacement)
	}
	if err := os.WriteFile(recipe, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(recipe, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}
	fpAfter, err := SourceFingerprint(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fpAfter != fpBefore {
		t.Fatal("test premise: the fingerprint must not change")
	}
}

// assertPendingAfterRecipeEdit fails t unless repo status reports pending work
// for the manifest at mPath; what describes the edit for the failure message.
func assertPendingAfterRecipeEdit(t *testing.T, mPath, keyDir, what string) {
	t.Helper()
	b, err := NewBuilder(mPath, keyDir, "pw")
	if err != nil {
		t.Fatal(err)
	}
	pending, reason, err := b.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if !pending || reason == "" {
		t.Fatalf("repo status missed a %s change a build would publish: pending=%v reason=%q", what, pending, reason)
	}
}

// TestBuildSourceCacheHitCannotCrossPlatforms edits polypkg.yaml's platform
// while keeping its size and mtime, so SourceFingerprint is unchanged. Neither
// repo status nor repo build may treat that as a cache hit: the cached artifact
// is for the old platform.
func TestBuildSourceCacheHitCannotCrossPlatforms(t *testing.T) {
	root := t.TempDir()
	keyDir := t.TempDir()
	keyPath := writeDupVersionKey(t, keyDir)
	dir := filepath.Join(root, "pkgs", "a")
	writePlatformPkgSrc(t, dir, "linux/amd64", "a")
	mPath := writeHelloRepo(t, root, keyPath, "source: ./pkgs/a")
	pub := filepath.Join(root, "public")

	if _, err := buildHello(t, mPath, keyDir); err != nil {
		t.Fatalf("build: %v", err)
	}
	editRecipeKeepingFingerprint(t, dir, "platform: linux/amd64", "platform: linux/arm64")
	assertPendingAfterRecipeEdit(t, mPath, keyDir, "platform")

	if _, err := buildHello(t, mPath, keyDir); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if rev := helloEntry(t, pub, "linux/arm64").Revision; rev != 1 {
		t.Fatalf("linux/arm64 revision = %d, want 1 (a new platform does not inherit linux/amd64's)", rev)
	}
	for _, e := range readIndex(t, pub).Packages["hello"] {
		if e.Platform == "linux/amd64" {
			t.Fatal("the stale linux/amd64 entry was republished from the cache")
		}
	}
}

// TestBuildSourceCacheHitCannotKeepStaleVersion is the version counterpart:
// an equal-length, mtime-preserving edit of version: must not republish the
// cached artifact, which is the old version.
func TestBuildSourceCacheHitCannotKeepStaleVersion(t *testing.T) {
	root := t.TempDir()
	keyDir := t.TempDir()
	keyPath := writeDupVersionKey(t, keyDir)
	dir := filepath.Join(root, "pkgs", "a")
	writePlatformPkgSrc(t, dir, "linux/amd64", "a")
	mPath := writeHelloRepo(t, root, keyPath, "source: ./pkgs/a")
	pub := filepath.Join(root, "public")

	if _, err := buildHello(t, mPath, keyDir); err != nil {
		t.Fatalf("build: %v", err)
	}
	editRecipeKeepingFingerprint(t, dir, "version: 1.0.0", "version: 1.0.1")
	assertPendingAfterRecipeEdit(t, mPath, keyDir, "version")

	if _, err := buildHello(t, mPath, keyDir); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if v := helloEntry(t, pub, "linux/amd64").Version; v != "1.0.1" {
		t.Fatalf("published version = %s, want 1.0.1 (the cached 1.0.0 artifact was republished)", v)
	}
}

// TestBuildSourceCacheHitCannotKeepStaleName pins the name half of the same
// rule: renaming the package in polypkg.yaml so it no longer matches its
// manifest key must reach the build's name check, not be masked by the cache.
func TestBuildSourceCacheHitCannotKeepStaleName(t *testing.T) {
	root := t.TempDir()
	keyDir := t.TempDir()
	keyPath := writeDupVersionKey(t, keyDir)
	dir := filepath.Join(root, "pkgs", "a")
	writePlatformPkgSrc(t, dir, "linux/amd64", "a")
	mPath := writeHelloRepo(t, root, keyPath, "source: ./pkgs/a")

	if _, err := buildHello(t, mPath, keyDir); err != nil {
		t.Fatalf("build: %v", err)
	}
	editRecipeKeepingFingerprint(t, dir, "name: hello", "name: hellp")
	assertPendingAfterRecipeEdit(t, mPath, keyDir, "name")

	_, err := buildHello(t, mPath, keyDir)
	if err == nil || !strings.Contains(err.Error(), `does not match package name "hellp"`) {
		t.Fatalf("rebuild = %v, want the manifest-key/name mismatch refusal", err)
	}
}

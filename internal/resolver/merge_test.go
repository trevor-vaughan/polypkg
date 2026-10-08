package resolver_test

import (
	"errors"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/resolver"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// mergeHost is the host platform the merge tests build catalogs for.
const mergeHost = "linux/amd64"

func cat(t *testing.T, source string, pkgs map[string]string) *resolver.Catalog {
	t.Helper()
	idx := &schema.Index{Schema: "polypkg.index/v3", Expires: "2099-01-01T00:00:00Z", Packages: map[string][]schema.IndexEntry{}}
	for name, ver := range pkgs {
		idx.Packages[name] = []schema.IndexEntry{{Version: ver, ContentHash: "blake3:aa", Artifact: name + "-" + ver + ".tar.zst"}}
	}
	c, err := resolver.BuildCatalog(idx, source, mergeHost)
	if err != nil {
		t.Fatalf("BuildCatalog(%s): %v", source, err)
	}
	return c
}

func TestMergeOverlayFirstSourceWins(t *testing.T) {
	a := cat(t, "a", map[string]string{"hello": "1.0.0"})
	b := cat(t, "b", map[string]string{"hello": "2.0.0"})
	m, err := resolver.MergeCatalogs(map[string]*resolver.Catalog{"a": a, "b": b}, []string{"a", "b"}, nil)
	if err != nil {
		t.Fatalf("MergeCatalogs: %v", err)
	}
	c, err := m.Newest("hello", "")
	if err != nil {
		t.Fatalf("Newest: %v", err)
	}
	if c.Source != "a" || c.Version != "1.0.0" {
		t.Fatalf("got %s/%s, want a/1.0.0 (higher-priority source shadows b)", c.Source, c.Version)
	}
}

func TestMergeNameOnlyInLowerSource(t *testing.T) {
	a := cat(t, "a", map[string]string{"hello": "1.0.0"})
	b := cat(t, "b", map[string]string{"world": "3.0.0"})
	m, err := resolver.MergeCatalogs(map[string]*resolver.Catalog{"a": a, "b": b}, []string{"a", "b"}, nil)
	if err != nil {
		t.Fatalf("MergeCatalogs: %v", err)
	}
	c, err := m.Newest("world", "")
	if err != nil {
		t.Fatalf("Newest world: %v", err)
	}
	if c.Source != "b" {
		t.Fatalf("world Source = %q, want b", c.Source)
	}
}

func TestMergePinOverridesOrder(t *testing.T) {
	a := cat(t, "a", map[string]string{"hello": "1.0.0"})
	b := cat(t, "b", map[string]string{"hello": "2.0.0"})
	m, err := resolver.MergeCatalogs(map[string]*resolver.Catalog{"a": a, "b": b}, []string{"a", "b"}, map[string]string{"hello": "b"})
	if err != nil {
		t.Fatalf("MergeCatalogs: %v", err)
	}
	c, _ := m.Newest("hello", "")
	if c.Source != "b" || c.Version != "2.0.0" {
		t.Fatalf("got %s/%s, want b/2.0.0 (pin overrides order)", c.Source, c.Version)
	}
}

func TestMergePinToUndefinedSource(t *testing.T) {
	a := cat(t, "a", map[string]string{"hello": "1.0.0"})
	_, err := resolver.MergeCatalogs(map[string]*resolver.Catalog{"a": a}, []string{"a"}, map[string]string{"hello": "ghost"})
	if err == nil {
		t.Fatal("expected error pinning to an unconfigured source")
	}
}

func TestMergePinToSourceMissingPackage(t *testing.T) {
	a := cat(t, "a", map[string]string{"hello": "1.0.0"})
	b := cat(t, "b", map[string]string{"world": "3.0.0"})
	_, err := resolver.MergeCatalogs(map[string]*resolver.Catalog{"a": a, "b": b}, []string{"a", "b"}, map[string]string{"hello": "b"})
	if err == nil {
		t.Fatal("expected error: source b has no package hello")
	}
}

func TestMergeVirtualProvidesFollowSource(t *testing.T) {
	idxA := &schema.Index{Schema: "polypkg.index/v3", Expires: "2099-01-01T00:00:00Z", Packages: map[string][]schema.IndexEntry{
		"vim": {{Version: "9.0.0", ContentHash: "blake3:aa", Artifact: "vim-9.0.0.tar.zst",
			Provides: []schema.Relation{{Name: "editor"}}}},
	}}
	a, err := resolver.BuildCatalog(idxA, "a", mergeHost)
	if err != nil {
		t.Fatalf("BuildCatalog a: %v", err)
	}
	b := cat(t, "b", map[string]string{"world": "1.0.0"})
	m, err := resolver.MergeCatalogs(map[string]*resolver.Catalog{"a": a, "b": b}, []string{"a", "b"}, nil)
	if err != nil {
		t.Fatalf("MergeCatalogs: %v", err)
	}
	c, err := m.Newest("editor", "")
	if err != nil {
		t.Fatalf("virtual editor must resolve via vim's Provides: %v", err)
	}
	if c.Source != "a" || c.Name != "vim" {
		t.Fatalf("editor resolved to %s/%s, want a/vim", c.Source, c.Name)
	}
}

// platCat builds a catalog for mergeHost from explicit index entries, so a
// test can publish a package for platforms other than the host.
func platCat(t *testing.T, source string, pkgs map[string][]schema.IndexEntry) *resolver.Catalog {
	t.Helper()
	c, err := resolver.BuildCatalog(&schema.Index{Schema: "polypkg.index/v3", Expires: "2099-01-01T00:00:00Z", Packages: pkgs}, source, mergeHost)
	if err != nil {
		t.Fatalf("BuildCatalog(%s): %v", source, err)
	}
	return c
}

func TestMergeKeepsDroppedPlatformsOfTheWinningSource(t *testing.T) {
	a := platCat(t, "a", map[string][]schema.IndexEntry{"hello": {
		{Version: "1.0.0", Platform: mergeHost, ContentHash: "blake3:a1", Artifact: "a1"},
		{Version: "1.0.0", Platform: "darwin/arm64", ContentHash: "blake3:a2", Artifact: "a2"},
	}})
	b := platCat(t, "b", map[string][]schema.IndexEntry{"hello": {
		{Version: "3.0.0", Platform: "windows/amd64", ContentHash: "blake3:b1", Artifact: "b1"},
	}})
	m, err := resolver.MergeCatalogs(map[string]*resolver.Catalog{"a": a, "b": b}, []string{"a", "b"}, nil)
	if err != nil {
		t.Fatalf("MergeCatalogs: %v", err)
	}
	if got := m.OtherPlatforms("hello", "1.0.0"); len(got) != 1 || got[0] != "darwin/arm64" {
		t.Fatalf("OtherPlatforms(hello, 1.0.0) = %v, want [darwin/arm64] from the winning source a", got)
	}
	if got := m.OtherPlatforms("hello", "3.0.0"); got != nil {
		t.Fatalf("OtherPlatforms(hello, 3.0.0) = %v, want nil: source b is shadowed by a for hello", got)
	}
}

func TestMergeKeepsHostlessNameFromFirstSourceThatPublishesIt(t *testing.T) {
	a := platCat(t, "a", map[string][]schema.IndexEntry{"rg": {
		{Version: "14.1.1", Platform: "darwin/arm64", ContentHash: "blake3:a1", Artifact: "a1"},
	}})
	b := platCat(t, "b", map[string][]schema.IndexEntry{"rg": {
		{Version: "15.0.0", Platform: "windows/amd64", ContentHash: "blake3:b1", Artifact: "b1"},
	}})
	m, err := resolver.MergeCatalogs(map[string]*resolver.Catalog{"a": a, "b": b}, []string{"a", "b"}, nil)
	if err != nil {
		t.Fatalf("MergeCatalogs: %v", err)
	}
	version, platforms, ok := m.NewestUnavailable("rg")
	if !ok || version != "14.1.1" || len(platforms) != 1 || platforms[0] != "darwin/arm64" {
		t.Fatalf("NewestUnavailable(rg) = %q %v %v, want 14.1.1 [darwin/arm64] true (first source in order)", version, platforms, ok)
	}
}

func TestMergeHigherSourceOwnsNameEvenWithoutHostBuild(t *testing.T) {
	a := platCat(t, "a", map[string][]schema.IndexEntry{"rg": {
		{Version: "14.1.1", Platform: "darwin/arm64", ContentHash: "blake3:a1", Artifact: "a1"},
	}})
	b := cat(t, "b", map[string]string{"rg": "13.0.0"})
	m, err := resolver.MergeCatalogs(map[string]*resolver.Catalog{"a": a, "b": b}, []string{"a", "b"}, nil)
	if err != nil {
		t.Fatalf("MergeCatalogs: %v", err)
	}
	if v := m.Versions("rg"); len(v) != 0 {
		t.Fatalf("Versions(rg) = %v, want none: a owns rg and has no build for this host, so b's must not substitute", v)
	}
	_, err = m.Newest("rg", "")
	var re *resolver.ResolveError
	if !errors.As(err, &re) || re.Kind != resolver.KindWrongPlatform {
		t.Fatalf("Newest(rg) err = %v, want a KindWrongPlatform *resolver.ResolveError", err)
	}
	if want := "rg 14.1.1 is published for darwin/arm64; this host is " + mergeHost; err.Error() != want {
		t.Fatalf("err = %q, want %q", err.Error(), want)
	}
}

func TestMergePinToLowerSourceUsesItsHostBuild(t *testing.T) {
	a := platCat(t, "a", map[string][]schema.IndexEntry{"rg": {
		{Version: "14.1.1", Platform: "darwin/arm64", ContentHash: "blake3:a1", Artifact: "a1"},
	}})
	b := cat(t, "b", map[string]string{"rg": "13.0.0"})
	m, err := resolver.MergeCatalogs(map[string]*resolver.Catalog{"a": a, "b": b}, []string{"a", "b"}, map[string]string{"rg": "b"})
	if err != nil {
		t.Fatalf("MergeCatalogs: %v", err)
	}
	c, err := m.Newest("rg", "")
	if err != nil {
		t.Fatalf("Newest: %v", err)
	}
	if c.Source != "b" || c.Version != "13.0.0" {
		t.Fatalf("got %s/%s, want b/13.0.0 (the pin names b)", c.Source, c.Version)
	}
}

func TestMergePinToSourceWithOnlyForeignPlatformsIsWrongPlatform(t *testing.T) {
	a := platCat(t, "a", map[string][]schema.IndexEntry{"rg": {
		{Version: "14.1.1", Platform: "darwin/arm64", ContentHash: "blake3:a1", Artifact: "a1"},
	}})
	_, err := resolver.MergeCatalogs(map[string]*resolver.Catalog{"a": a}, []string{"a"}, map[string]string{"rg": "a"})
	var re *resolver.ResolveError
	if !errors.As(err, &re) || re.Kind != resolver.KindWrongPlatform {
		t.Fatalf("err = %v, want a KindWrongPlatform *resolver.ResolveError", err)
	}
	if want := "rg 14.1.1 is published for darwin/arm64; this host is " + mergeHost; err.Error() != want {
		t.Fatalf("err = %q, want %q", err.Error(), want)
	}
}

func TestMergeReportsTheFirstFailingPinInNameOrder(t *testing.T) {
	a := cat(t, "a", map[string]string{"other": "1.0.0"})
	pins := map[string]string{"zzz": "missing", "mmm": "missing", "aaa": "missing"}
	// Map iteration order varies per run; repeat so a name-order dependence
	// cannot pass by luck.
	for range 50 {
		_, err := resolver.MergeCatalogs(map[string]*resolver.Catalog{"a": a}, []string{"a"}, pins)
		if want := `package "aaa" pins source "missing", which is not configured`; err == nil || err.Error() != want {
			t.Fatalf("err = %v, want %q (the first failing name in sorted order)", err, want)
		}
	}
}

// shadowCatalogs returns a merged catalog where source a publishes rg only for
// darwin/arm64 and lower-priority source b offers evil (a host build) that
// provides rg, plus app (depends on rg) and extras (recommends rg).
func shadowCatalogs(t *testing.T) *resolver.Catalog {
	t.Helper()
	a := platCat(t, "a", map[string][]schema.IndexEntry{"rg": {
		{Version: "14.1.1", Platform: "darwin/arm64", ContentHash: "blake3:a1", Artifact: "a1"},
	}})
	b := platCat(t, "b", map[string][]schema.IndexEntry{
		"evil":   {{Version: "1.0.0", Platform: mergeHost, ContentHash: "blake3:e", Artifact: "e", Provides: []schema.Relation{{Name: "rg"}}}},
		"app":    {{Version: "1.0.0", ContentHash: "blake3:p", Artifact: "p", Depends: []schema.Relation{{Name: "rg"}}}},
		"extras": {{Version: "1.0.0", ContentHash: "blake3:x", Artifact: "x", Recommends: []schema.Relation{{Name: "rg"}}}},
	})
	m, err := resolver.MergeCatalogs(map[string]*resolver.Catalog{"a": a, "b": b}, []string{"a", "b"}, nil)
	if err != nil {
		t.Fatalf("MergeCatalogs: %v", err)
	}
	return m
}

func wantWrongPlatform(t *testing.T, what string, err error, wantMsg string) {
	t.Helper()
	var re *resolver.ResolveError
	if !errors.As(err, &re) || re.Kind != resolver.KindWrongPlatform {
		t.Fatalf("%s: err = %v, want a KindWrongPlatform *resolver.ResolveError", what, err)
	}
	if err.Error() != wantMsg {
		t.Fatalf("%s: err = %q, want %q", what, err.Error(), wantMsg)
	}
}

func TestMergeProviderCannotStandInForOwnedNameWithoutHostBuild(t *testing.T) {
	m := shadowCatalogs(t)
	const msg = "rg 14.1.1 is published for darwin/arm64; this host is " + mergeHost

	_, err := m.Newest("rg", "")
	wantWrongPlatform(t, "Newest(rg)", err, msg)

	_, err = resolver.Resolve([]resolver.Requirement{{Name: "rg"}}, m)
	wantWrongPlatform(t, "Resolve(rg)", err, msg)

	_, err = resolver.Resolve([]resolver.Requirement{{Name: "app"}}, m)
	wantWrongPlatform(t, "Resolve(app)", err, msg+" (required via app -> rg)")

	res, err := resolver.ResolveWithWeak([]resolver.Requirement{{Name: "extras"}}, m, resolver.WeakOn)
	if err != nil {
		t.Fatalf("ResolveWithWeak(extras): %v", err)
	}
	if len(res.Installed) != 1 || res.Installed[0].Name != "extras" {
		t.Fatalf("Installed = %+v, want only extras (evil must not be pulled in for rg)", res.Installed)
	}
	if len(res.Skipped) != 1 || res.Skipped[0].Name != "rg" || res.Skipped[0].Reason != "not published for this host ("+mergeHost+")" {
		t.Fatalf("Skipped = %+v, want rg skipped as not published for this host", res.Skipped)
	}
}

func TestMergeProviderStillSatisfiesNameNoSourcePublishes(t *testing.T) {
	b := platCat(t, "b", map[string][]schema.IndexEntry{
		"evil": {{Version: "1.0.0", Platform: mergeHost, ContentHash: "blake3:e", Artifact: "e", Provides: []schema.Relation{{Name: "rg"}}}},
	})
	m, err := resolver.MergeCatalogs(map[string]*resolver.Catalog{"b": b}, []string{"b"}, nil)
	if err != nil {
		t.Fatalf("MergeCatalogs: %v", err)
	}
	c, err := m.Newest("rg", "")
	if err != nil || c.Name != "evil" {
		t.Fatalf("Newest(rg) = %v, %v; want the virtual provider evil", c, err)
	}
}

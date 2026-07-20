package resolver_test

import (
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/resolver"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func cat(t *testing.T, source string, pkgs map[string]string) *resolver.Catalog {
	t.Helper()
	idx := &schema.Index{Schema: "polypkg.index/v2", Expires: "2099-01-01T00:00:00Z", Packages: map[string][]schema.IndexEntry{}}
	for name, ver := range pkgs {
		idx.Packages[name] = []schema.IndexEntry{{Version: ver, ContentHash: "blake3:aa", Artifact: name + "-" + ver + ".tar.zst"}}
	}
	c, err := resolver.BuildCatalog(idx, source)
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
	idxA := &schema.Index{Schema: "polypkg.index/v2", Expires: "2099-01-01T00:00:00Z", Packages: map[string][]schema.IndexEntry{
		"vim": {{Version: "9.0.0", ContentHash: "blake3:aa", Artifact: "vim-9.0.0.tar.zst",
			Provides: []schema.Relation{{Name: "editor"}}}},
	}}
	a, err := resolver.BuildCatalog(idxA, "a")
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

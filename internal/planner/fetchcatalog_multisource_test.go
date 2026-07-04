package planner_test

import (
	"context"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/planner"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func TestFetchCatalogEmptyOrderWithPackages(t *testing.T) {
	p := &schema.Profile{
		Schema:   "polypkg.spec/v1",
		Name:     "t",
		Scopes:   map[string]schema.ScopeSpec{"user": {Substrate: "store"}},
		Sources:  schema.SourcesSpec{Order: nil, Sources: map[string]schema.SourceBackend{}},
		Packages: map[string]map[string]schema.PackageRef{"user": {"hello": {Version: "=1.0.0"}}},
	}
	_, err := planner.FetchCatalog(context.Background(), p, planner.Options{Scope: "user", StateHome: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "sources.order is empty") {
		t.Fatalf("want empty-order error, got %v", err)
	}
}

func TestFetchCatalogUndefinedOrderSource(t *testing.T) {
	p := &schema.Profile{
		Schema:   "polypkg.spec/v1",
		Name:     "t",
		Scopes:   map[string]schema.ScopeSpec{"user": {Substrate: "store"}},
		Sources:  schema.SourcesSpec{Order: []string{"ghost"}, Sources: map[string]schema.SourceBackend{}},
		Packages: map[string]map[string]schema.PackageRef{"user": {"hello": {Version: "=1.0.0"}}},
	}
	_, err := planner.FetchCatalog(context.Background(), p, planner.Options{Scope: "user", StateHome: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "undefined source") {
		t.Fatalf("want undefined-source error, got %v", err)
	}
}

func TestFetchCatalogUndefinedPinSource(t *testing.T) {
	p := &schema.Profile{
		Schema: "polypkg.spec/v1",
		Name:   "t",
		Scopes: map[string]schema.ScopeSpec{"user": {Substrate: "store"}},
		Sources: schema.SourcesSpec{
			Order: []string{"a"},
			Sources: map[string]schema.SourceBackend{
				"a": {Type: "polypkg-native", URL: "http://127.0.0.1:1", TrustRoot: "/nonexistent"},
			},
		},
		Packages: map[string]map[string]schema.PackageRef{
			"user": {"hello": {Version: "=1.0.0", Source: "ghost"}},
		},
	}
	_, err := planner.FetchCatalog(context.Background(), p, planner.Options{Scope: "user", StateHome: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "pins undefined source") {
		t.Fatalf("want pin-undefined-source error, got %v", err)
	}
}

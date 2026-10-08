package planner_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/planner"
	"github.com/trevor-vaughan/polypkg/internal/repo"
	"github.com/trevor-vaughan/polypkg/internal/source"
)

// With several sources in a profile, a fetch failure must say which one
// failed: the FetchError carries the profile's name for the source, not the
// backend type.
func TestFetchCatalogNamesTheFailingSource(t *testing.T) {
	_, trustRoot := buildSignedLocalRepo(t, "zeta", repo.BuildOptions{})
	for _, tc := range []struct {
		name    string
		url     string
		network bool
	}{
		{"an unreachable http source", "http://127.0.0.1:1", true},
		{"a missing local directory", filepath.Join(t.TempDir(), "absent"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := profileForLocalSource("zeta", tc.url, trustRoot)
			_, err := planner.FetchCatalog(context.Background(), p, planner.Options{Scope: "user", StateHome: t.TempDir()})
			var fe *source.FetchError
			if !errors.As(err, &fe) {
				t.Fatalf("want a *source.FetchError, got %T: %v", err, err)
			}
			if fe.Source != "zeta" {
				t.Fatalf("FetchError.Source = %q, want the profile's name for the source, zeta", fe.Source)
			}
			if fe.Network != tc.network {
				t.Fatalf("FetchError.Network = %v, want %v", fe.Network, tc.network)
			}
			if !tc.network && !fe.NotFound() {
				t.Fatalf("a missing local directory must read as not found: %v", fe)
			}
		})
	}
}

package ghrelease_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/ghrelease"
)

// matchFixture is one release's asset names and the Match outcome expected
// for each set of overrides. A case expects either chosen and skipped, or
// ambiguity.
type matchFixture struct {
	Note   string   `json:"note"`
	Assets []string `json:"assets"`
	Cases  []struct {
		Name      string            `json:"name"`
		Overrides map[string]string `json:"overrides"`
		Chosen    map[string]string `json:"chosen"`
		Skipped   map[string]string `json:"skipped"`
		Ambiguity *struct {
			Platform   string   `json:"platform"`
			Candidates []string `json:"candidates"`
		} `json:"ambiguity"`
	} `json:"cases"`
}

func TestMatchRealWorldReleases(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("testdata", "match", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	found := make([]string, 0, len(paths))
	for _, p := range paths {
		found = append(found, strings.TrimSuffix(filepath.Base(p), ".json"))
	}
	for _, want := range []string{"bat", "fd", "gh", "hugo", "jq", "ripgrep", "yq", "zoxide"} {
		if !slices.Contains(found, want) {
			t.Fatalf("testdata/match/%s.json is missing; found %v", want, found)
		}
	}

	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var fx matchFixture
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&fx); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if !strings.HasPrefix(fx.Note, "Representative fixture") || len(fx.Assets) == 0 || len(fx.Cases) == 0 {
			t.Fatalf("%s: needs a \"Representative fixture\" note, assets and cases", p)
		}
		for _, c := range fx.Cases {
			t.Run(filepath.Base(p)+"/"+c.Name, func(t *testing.T) {
				r, err := ghrelease.Match(assetsNamed(fx.Assets...), c.Overrides)
				if c.Ambiguity != nil {
					var ae *ghrelease.AmbiguityError
					if !errors.As(err, &ae) {
						t.Fatalf("Match = (%v, %v), want an *AmbiguityError", r, err)
					}
					if ae.Platform != c.Ambiguity.Platform || !slices.Equal(ae.Candidates, c.Ambiguity.Candidates) {
						t.Fatalf("AmbiguityError = %+v, want %+v", *ae, *c.Ambiguity)
					}
					return
				}
				if err != nil {
					t.Fatalf("Match: %v", err)
				}
				if got := chosenNames(r); !maps.Equal(got, c.Chosen) {
					t.Fatalf("chosen:\n got %v\nwant %v", got, c.Chosen)
				}
				if got := skippedReasons(t, r); !maps.Equal(got, c.Skipped) {
					t.Fatalf("skipped:\n got %v\nwant %v", got, c.Skipped)
				}
				if !slices.IsSortedFunc(r.Skipped, func(x, y ghrelease.Skip) int { return strings.Compare(x.Name, y.Name) }) {
					t.Fatalf("Skipped is not sorted by name: %v", r.Skipped)
				}
				accounted := map[string]bool{}
				for _, a := range r.Chosen {
					accounted[a.Name] = true
				}
				for _, s := range r.Skipped {
					if accounted[s.Name] {
						t.Fatalf("%s is both chosen and skipped", s.Name)
					}
					accounted[s.Name] = true
				}
				for _, n := range fx.Assets {
					if !accounted[n] {
						t.Fatalf("%s is neither chosen nor skipped", n)
					}
				}
			})
		}
	}
}

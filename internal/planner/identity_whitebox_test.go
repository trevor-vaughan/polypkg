package planner

import (
	"errors"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/resolver"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func TestCheckArtifactIdentity(t *testing.T) {
	entry := func(plat string) resolver.Resolved {
		return resolver.Resolved{Name: "hello", Version: "1.0.0", Platform: plat, Source: "native"}
	}
	recipe := func(name, version, plat string) *schema.Package {
		return &schema.Package{Schema: "polypkg.package/v1", Name: name, Version: version, Platform: plat}
	}
	cases := []struct {
		desc      string
		pkg       *schema.Package
		entry     resolver.Resolved
		wantField string // "" means the artifact is accepted
		wantGot   string
		wantWant  string
	}{
		{"agnostic artifact for an agnostic entry", recipe("hello", "1.0.0", ""), entry(""), "", "", ""},
		{"platform artifact for its own platform's entry", recipe("hello", "1.0.0", "linux/amd64"), entry("linux/amd64"), "", "", ""},
		{"name differs", recipe("other", "1.0.0", ""), entry(""), "name", "other", "hello"},
		{"name differs only by case", recipe("Hello", "1.0.0", ""), entry(""), "name", "Hello", "hello"},
		{"version differs", recipe("hello", "1.0.1", ""), entry(""), "version", "1.0.1", "1.0.0"},
		{"version differs only by a v prefix", recipe("hello", "v1.0.0", ""), entry(""), "version", "v1.0.0", "1.0.0"},
		{"platform artifact for an agnostic entry", recipe("hello", "1.0.0", "linux/amd64"), entry(""), "platform", "linux/amd64", "any"},
		{"agnostic artifact for a platform entry", recipe("hello", "1.0.0", ""), entry("linux/amd64"), "platform", "any", "linux/amd64"},
		{"another platform's artifact", recipe("hello", "1.0.0", "darwin/arm64"), entry("linux/amd64"), "platform", "darwin/arm64", "linux/amd64"},
		{"name is reported before version and platform", recipe("other", "2.0.0", "darwin/arm64"), entry("linux/amd64"), "name", "other", "hello"},
		{"version is reported before platform", recipe("hello", "2.0.0", "darwin/arm64"), entry("linux/amd64"), "version", "2.0.0", "1.0.0"},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			err := checkArtifactIdentity(tc.pkg, tc.entry)
			if tc.wantField == "" {
				if err != nil {
					t.Fatalf("want the artifact accepted, got %v", err)
				}
				return
			}
			var aie *ArtifactIdentityError
			if !errors.As(err, &aie) {
				t.Fatalf("want *ArtifactIdentityError, got %T: %v", err, err)
			}
			if aie.Field != tc.wantField || aie.Got != tc.wantGot || aie.Want != tc.wantWant {
				t.Fatalf("got field=%q got=%q want=%q; expected field=%q got=%q want=%q",
					aie.Field, aie.Got, aie.Want, tc.wantField, tc.wantGot, tc.wantWant)
			}
			if aie.Name != "hello" || aie.Version != "1.0.0" || aie.Source != "native" {
				t.Fatalf("error must identify the index entry, got name=%q version=%q source=%q",
					aie.Name, aie.Version, aie.Source)
			}
		})
	}
}

func TestArtifactIdentityErrorMessage(t *testing.T) {
	e := &ArtifactIdentityError{
		Name: "hello", Version: "1.0.0", Source: "native",
		Field: "platform", Got: "linux/amd64", Want: "any",
	}
	want := `artifact for hello 1.0.0 from source "native" declares platform "linux/amd64", but the index lists "any"`
	if got := e.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

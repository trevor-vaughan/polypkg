package schema

import (
	"errors"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestParsePackageNamesAnUnknownKeyWithoutTheGoType(t *testing.T) {
	src := "schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\ndependencies: []\nactions: []\n"
	_, err := ParsePackage(strings.NewReader(src), "polypkg.yaml")
	if err == nil {
		t.Fatal("want an error for the unknown key dependencies")
	}
	if !strings.Contains(err.Error(), `line 4: unknown field "dependencies"`) {
		t.Fatalf("error = %q, want it to name the key and its line", err)
	}
	if strings.Contains(err.Error(), "schema.Package") {
		t.Fatalf("error = %q names a Go type", err)
	}
	var te *yaml.TypeError
	if !errors.As(err, &te) {
		t.Fatalf("the *yaml.TypeError must stay in the chain: %T", err)
	}
}

func TestParseRepoManifestNamesAnUnknownKeyWithoutTheGoType(t *testing.T) {
	const in = "schema: polypkg.repo/v1\nsource: example\noutput: ./public\npackges: {}\n"
	_, err := ParseRepoManifest(strings.NewReader(in))
	if err == nil {
		t.Fatal("want an error for the unknown key packges")
	}
	if !strings.Contains(err.Error(), `line 4: unknown field "packges"`) {
		t.Fatalf("error = %q, want it to name the key and its line", err)
	}
	if strings.Contains(err.Error(), "schema.RepoManifest") {
		t.Fatalf("error = %q names a Go type", err)
	}
}

func TestPlainYAMLDecodeErrorLeavesOtherErrorsAlone(t *testing.T) {
	other := errors.New("yaml: line 2: did not find expected key")
	if got := plainYAMLDecodeError(other); !errors.Is(got, other) {
		t.Fatalf("plainYAMLDecodeError(%v) = %v, want it unchanged", other, got)
	}
	te := &yaml.TypeError{Errors: []string{"line 3: cannot unmarshal !!str `x` into int"}}
	if got := plainYAMLDecodeError(te); got.Error() != te.Error() {
		t.Fatalf("a type mismatch was rewritten: %q", got)
	}
}

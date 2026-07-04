package schema

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ParseProfile (JSONC)", func() {
	const minimalProfile = `{
  // a single-line comment
  "schema": "polypkg.spec/v1",
  "name": "minimal",
  "scopes": {
    "user": {"substrate": "store"}
  },
  /* block comment */
  "sources": {
    "order": ["native"],
    "native": {
      "type": "polypkg-native",
      "url": "https://example.invalid/repo",
      "trust_root": "/tmp/key.pub"
    },
  }, // trailing comma above
}
`

	It("parses a JSONC profile with comments and trailing commas", func() {
		p, err := ParseProfile(strings.NewReader(minimalProfile), "profile.jsonc")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Schema).To(Equal("polypkg.spec/v1"))
		Expect(p.Name).To(Equal("minimal"))
		Expect(p.Scopes).To(HaveKey("user"))
	})

	It("rejects unknown top-level fields in JSONC", func() {
		src := `{
  "schema": "polypkg.spec/v1",
  "name": "x",
  "scopes": {"user": {"substrate": "store"}},
  "sources": {"order": ["native"], "native": {"type": "polypkg-native", "url": "https://e.invalid", "trust_root": "/k"}},
  "bogus": 42
}`
		_, err := ParseProfile(strings.NewReader(src), "profile.jsonc")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("bogus"))
	})

	It("rejects trailing data after the root value", func() {
		src := `{
  "schema": "polypkg.spec/v1",
  "name": "x",
  "scopes": {"user": {"substrate": "store"}},
  "sources": {"order": ["native"], "native": {"type": "polypkg-native", "url": "https://e.invalid", "trust_root": "/k"}}
} garbage`
		_, err := ParseProfile(strings.NewReader(src), "profile.jsonc")
		Expect(err).To(MatchError(ContainSubstring("unexpected data after root value")))
	})

	It("accepts an empty JSONC file (schema validation supplies the verdict)", func() {
		_, err := ParseProfile(strings.NewReader(""), "profile.jsonc")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Or(ContainSubstring("schema"), ContainSubstring("required")))
		Expect(err.Error()).NotTo(ContainSubstring("EOF"))
	})

	It("accepts a comment-only JSONC file (schema validation supplies the verdict)", func() {
		src := `// just a comment
/* and another */
`
		_, err := ParseProfile(strings.NewReader(src), "profile.jsonc")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Or(ContainSubstring("schema"), ContainSubstring("required")))
		Expect(err.Error()).NotTo(ContainSubstring("EOF"))
	})

	It("rejects unsupported file extensions", func() {
		_, err := ParseProfile(strings.NewReader(""), "config.txt")
		Expect(err).To(MatchError(ContainSubstring("unsupported format")))
		Expect(err).To(MatchError(ContainSubstring(".txt")))
	})
})

var _ = Describe("ParsePackage (JSONC) — starlark envelope", func() {
	const pkgWithStarlark = `{
  "schema": "polypkg.package/v1",
  "name": "hello",
  "version": "1.0.0",
  "actions": [
    {
      "phase": "post-place",
      "action": "install",
      "params": {
        "src": "$PKG/bin/hi",
        "dest": {"!starlark": "host.arch"},
        "policy": "symlink"
      }
    }
  ]
}
`

	It("decodes {\"!starlark\":\"expr\"} into a StarlarkExpr", func() {
		p, err := ParsePackage(strings.NewReader(pkgWithStarlark), "polypkg.jsonc")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Actions).To(HaveLen(1))
		params := p.Actions[0].Params
		Expect(params["src"]).To(Equal("$PKG/bin/hi"))
		expr, ok := params["dest"].(StarlarkExpr)
		Expect(ok).To(BeTrue(), "dest should be a StarlarkExpr, got %T", params["dest"])
		Expect(expr.Source).To(Equal("host.arch"))
	})

	It("rejects a malformed !starlark envelope (multiple keys)", func() {
		src := `{
  "schema": "polypkg.package/v1",
  "name": "x",
  "version": "1.0.0",
  "actions": [
    {"phase": "post-place", "action": "dir", "params": {"path": {"!starlark": "x", "extra": 1}}}
  ]
}`
		_, err := ParsePackage(strings.NewReader(src), "polypkg.jsonc")
		Expect(err).To(MatchError(ContainSubstring("starlark envelope")))
	})

	It("rejects a !starlark value that is not a string", func() {
		src := `{
  "schema": "polypkg.package/v1",
  "name": "x",
  "version": "1.0.0",
  "actions": [
    {"phase": "post-place", "action": "dir", "params": {"path": {"!starlark": 42}}}
  ]
}`
		_, err := ParsePackage(strings.NewReader(src), "polypkg.jsonc")
		Expect(err).To(MatchError(ContainSubstring("starlark envelope")))
	})

	It("normalizes action-param numbers to the same Go types YAML produces", func() {
		// yaml.v3 decodes integers in interface{}-typed contexts as `int`,
		// not `int64`. The JSONC path mirrors this: small integers become
		// `int`, non-integers become `float64`. Preserving this parity is
		// what lets the format-equivalence matrix tests (below) compare
		// structs under reflect.DeepEqual.
		src := `{
  "schema": "polypkg.package/v1",
  "name": "x",
  "version": "1.0.0",
  "actions": [
    {"phase": "post-place", "action": "dir", "params": {"n": 42, "f": 3.5}}
  ]
}`
		p, err := ParsePackage(strings.NewReader(src), "polypkg.jsonc")
		Expect(err).NotTo(HaveOccurred())
		params := p.Actions[0].Params
		Expect(params["n"]).To(BeAssignableToTypeOf(int(0)),
			"integer JSON number must decode to int (parity with YAML), got %T", params["n"])
		Expect(params["n"]).To(Equal(42))
		Expect(params["f"]).To(BeAssignableToTypeOf(float64(0)),
			"non-integer JSON number must decode to float64, got %T", params["f"])
		Expect(params["f"]).To(Equal(3.5))
	})
})

var _ = Describe("JSONC review follow-ups", func() {
	It("reports a parse error for a truncated JSONC document (not a schema error)", func() {
		_, err := ParseProfile(strings.NewReader("{"), "profile.jsonc")
		Expect(err).To(HaveOccurred())
		// The user has a syntax bug, so the error must mention parsing / EOF /
		// JSONC, NOT route through schema validation which would confusingly
		// complain about "missing required property schema".
		Expect(err.Error()).To(Or(
			ContainSubstring("jsonc parse"),
			ContainSubstring("unexpected EOF"),
		), "truncated JSONC must surface as a parse error, got %q", err.Error())
		Expect(err.Error()).NotTo(ContainSubstring("schema validation"))
	})

	It("rejects `params: null` in JSONC for parity with YAML", func() {
		// YAML's ParsePackage rejects `params: ~` with "action params must be a
		// mapping". The JSONC path must reject the equivalent `"params": null`.
		src := `{
  "schema": "polypkg.package/v1",
  "name": "x",
  "version": "1.0.0",
  "actions": [
    {"phase": "post-place", "action": "install", "params": null}
  ]
}`
		_, err := ParsePackage(strings.NewReader(src), "polypkg.jsonc")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("action params must be a mapping"))
	})

	It("accepts a nested map action-param for parity with YAML", func() {
		// An action param whose value is an object without a !starlark key must
		// decode as a literal map[string]any (matching YAML's behavior).
		// Previously the JSONC path rejected any object that wasn't a
		// !starlark envelope; this asymmetry violated format equivalence.
		src := `{
  "schema": "polypkg.package/v1",
  "name": "x",
  "version": "1.0.0",
  "actions": [
    {"phase": "post-place", "action": "install", "params": {"opts": {"a": 1, "b": "two"}}}
  ]
}`
		p, err := ParsePackage(strings.NewReader(src), "polypkg.jsonc")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Actions).To(HaveLen(1))
		opts, ok := p.Actions[0].Params["opts"].(map[string]any)
		Expect(ok).To(BeTrue(), "opts must decode to map[string]any, got %T", p.Actions[0].Params["opts"])
		Expect(opts["a"]).To(Equal(1)) // int parity with YAML
		Expect(opts["b"]).To(Equal("two"))
	})

	It("still rejects a malformed !starlark envelope when the object DOES carry a !starlark key", func() {
		// Regression: the relaxation for nested literal maps must NOT
		// silently accept malformed envelopes. An object with a !starlark
		// key but the wrong shape (multi-key, non-string value) must still
		// fail.
		src := `{
  "schema": "polypkg.package/v1",
  "name": "x",
  "version": "1.0.0",
  "actions": [
    {"phase": "post-place", "action": "install", "params": {"p": {"!starlark": "x", "extra": 1}}}
  ]
}`
		_, err := ParsePackage(strings.NewReader(src), "polypkg.jsonc")
		Expect(err).To(MatchError(ContainSubstring("starlark envelope")))
	})

	It("emits a clear error for a name with no extension", func() {
		// `parseFormat("foo")` previously produced "unsupported format:  (want ...)"
		// with an awkward double space and no extension shown. Make the error
		// readable.
		_, err := ParseProfile(strings.NewReader(""), "noext")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unsupported format"))
		// Either the name or a "no extension" phrase should be present.
		Expect(err.Error()).To(Or(
			ContainSubstring("noext"),
			ContainSubstring("no extension"),
		))
	})
})

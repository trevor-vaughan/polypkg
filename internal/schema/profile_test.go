package schema

import (
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ParseProfile", func() {
	It("rejects path-traversal package names", func() {
		// A package name is a map key that flows into filesystem paths during apply
		// (extraction dir, RemoveAll target). The schema must reject names that
		// could escape their intended directory, at the parse boundary.
		src := `
schema: polypkg.spec/v1
name: evil
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: polypkg-native
    url: https://example.invalid/repo
    trust_root: /tmp/key.pub
packages:
  user:
    "../../../etc/cron.d/pwn":
      version: "=1.0.0"
`
		_, err := ParseProfile(strings.NewReader(src), "")
		Expect(err).To(HaveOccurred(), "package names containing path separators must be rejected")
	})

	It("parses a minimal valid profile", func() {
		src := `
schema: polypkg.spec/v1
name: minimal
scopes:
  user:
    substrate: store
    prefix: $XDG_DATA_HOME/polypkg
sources:
  order: [native]
  native:
    type: polypkg-native
    url: https://example.com/repo
    trust_root: /tmp/key.pub
packages:
  user:
    hello:
      version: "^1.0"
`
		p, err := ParseProfile(strings.NewReader(src), "")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Schema).To(Equal("polypkg.spec/v1"))
		Expect(p.Name).To(Equal("minimal"))
		Expect(p.Scopes).To(HaveKey("user"))
		Expect(p.Scopes["user"].Substrate).To(Equal("store"))
		Expect(p.Packages).To(HaveKey("user"))
		Expect(p.Packages["user"]).To(HaveKey("hello"))
		Expect(p.Packages["user"]["hello"].Version).To(Equal("^1.0"))
	})

	It("rejects invalid YAML", func() {
		src := "not: valid: yaml: at all"
		_, err := ParseProfile(strings.NewReader(src), "")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("yaml"))
	})

	It("rejects a profile missing the required name field", func() {
		src := `
schema: polypkg.spec/v1
# missing 'name'
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: polypkg-native
    url: https://example.com/repo
    trust_root: /tmp/key.pub
`
		_, err := ParseProfile(strings.NewReader(src), "")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("name"))
	})

	It("rejects YAML anchors", func() {
		src := `
schema: polypkg.spec/v1
name: anchor-test
defaults: &defaults
  substrate: store
scopes:
  user: *defaults
sources:
  order: [native]
  native:
    type: polypkg-native
    url: https://example.com/repo
    trust_root: /tmp/key.pub
`
		_, err := ParseProfile(strings.NewReader(src), "")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("anchor"))
	})

	It("does not evaluate Starlark expressions in package fields", func() {
		// M1 does not support Starlark; expressions in package fields should
		// be parsed as raw strings, not evaluated.
		src := `
schema: polypkg.spec/v1
name: starlark-test
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: polypkg-native
    url: https://example.com/repo
    trust_root: /tmp/key.pub
packages:
  user:
    hello:
      version: "!starlark return '1.0'"
`
		p, err := ParseProfile(strings.NewReader(src), "")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Packages["user"]["hello"].Version).To(Equal("!starlark return '1.0'"))
	})

	It("rejects a source backend missing trust_root", func() {
		// trust_root is security-critical: a source backend without it must be
		// rejected by schema validation, not silently accepted.
		src := `
schema: polypkg.spec/v1
name: no-trust-root
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: polypkg-native
    url: https://example.com/repo
`
		_, err := ParseProfile(strings.NewReader(src), "")
		Expect(err).To(HaveOccurred())
	})

	It("rejects a source url that is not a URI", func() {
		// url is a package download endpoint; format: "uri" in the schema must be
		// enforced so that a non-URI value is rejected.
		src := `
schema: polypkg.spec/v1
name: bad-url
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: polypkg-native
    url: "not a uri"
    trust_root: /tmp/key.pub
`
		_, err := ParseProfile(strings.NewReader(src), "")
		Expect(err).To(HaveOccurred())
	})

	It("rejects an empty sources.order array", func() {
		// sources.order must have at least one entry (minItems: 1).
		src := `
schema: polypkg.spec/v1
name: empty-order
scopes:
  user:
    substrate: store
sources:
  order: []
  native:
    type: polypkg-native
    url: https://example.com/repo
    trust_root: /tmp/key.pub
`
		_, err := ParseProfile(strings.NewReader(src), "")
		Expect(err).To(HaveOccurred())
	})

	It("accepts an optional trust_doc on a source", func() {
		withDoc := `schema: polypkg.spec/v1
name: t
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: polypkg-native
    url: https://example.com/repo
    trust_root: /etc/polypkg/anchor.pub
    trust_doc: /etc/polypkg/native.trust
packages:
  user:
    hello:
      version: "=1.0.0"
`
		p, err := ParseProfile(strings.NewReader(withDoc), "")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Sources.Sources["native"].TrustDoc).To(Equal("/etc/polypkg/native.trust"))
	})

	It("parses a starlark limits block", func() {
		src := `schema: polypkg.spec/v1
name: t
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: polypkg-native
    url: https://example.com/repo
    trust_root: /etc/polypkg/anchor.pub
starlark:
  max_steps: 500
  timeout: 750ms
  max_memory_bytes: 33554432
  max_output_bytes: 1024
`
		p, err := ParseProfile(strings.NewReader(src), "")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Starlark).NotTo(BeNil())
		Expect(p.Starlark.MaxSteps).To(Equal(uint64(500)))
		Expect(time.Duration(p.Starlark.Timeout)).To(Equal(750 * time.Millisecond))
	})

	It("rejects an invalid starlark timeout duration", func() {
		src := `schema: polypkg.spec/v1
name: t
scopes: {user: {substrate: store}}
sources: {order: [native], native: {type: polypkg-native, url: https://e.com/r, trust_root: /k}}
starlark: {timeout: "not-a-duration"}
`
		_, err := ParseProfile(strings.NewReader(src), "")
		Expect(err).To(HaveOccurred())
	})

	It("parses a retention block", func() {
		y := `schema: polypkg.spec/v1
name: test
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: native
    url: https://example.invalid
    trust_root: /dev/null
retention:
  count: 7
  age: 14d
`
		p, err := ParseProfile(strings.NewReader(y), "")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Retention).NotTo(BeNil())
		Expect(p.Retention.Count).To(Equal(7))
		Expect(p.Retention.Age).To(Equal("14d"))
	})

	It("leaves Retention nil when the block is omitted", func() {
		y := `schema: polypkg.spec/v1
name: test
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: native
    url: https://example.invalid
    trust_root: /dev/null
`
		p, err := ParseProfile(strings.NewReader(y), "")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Retention).To(BeNil(), "absent retention block should leave Retention nil")
	})

	It("leaves Recommends nil when the block is omitted", func() {
		y := `schema: polypkg.spec/v1
name: test
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: native
    url: https://example.invalid
    trust_root: /dev/null
`
		p, err := ParseProfile(strings.NewReader(y), "")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Recommends).To(BeNil(), "absent recommends block should leave Recommends nil")
	})

	It("rejects a recommends block without install (empty block)", func() {
		// The JSON Schema requires 'install' when the recommends block is present
		// so that a false zero-value cannot silently mean "off" for an empty block.
		// This is the guard that makes effectiveWeakPolicy's nil-check reliable.
		y := `schema: polypkg.spec/v1
name: test
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: native
    url: https://example.invalid
    trust_root: /dev/null
recommends: {}
`
		_, err := ParseProfile(strings.NewReader(y), "")
		Expect(err).To(HaveOccurred(), "recommends block without 'install' must be rejected by schema")
	})

	It("parses recommends block with install: false", func() {
		y := `schema: polypkg.spec/v1
name: test
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: native
    url: https://example.invalid
    trust_root: /dev/null
recommends:
  install: false
`
		p, err := ParseProfile(strings.NewReader(y), "")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Recommends).NotTo(BeNil())
		Expect(p.Recommends.Install).To(BeFalse())
	})

	It("parses recommends block with install: true", func() {
		y := `schema: polypkg.spec/v1
name: test
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: native
    url: https://example.invalid
    trust_root: /dev/null
recommends:
  install: true
`
		p, err := ParseProfile(strings.NewReader(y), "")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Recommends).NotTo(BeNil())
		Expect(p.Recommends.Install).To(BeTrue())
	})

	It("returns a plain 'is empty' error for an empty YAML file", func() {
		_, err := ParseProfile(strings.NewReader(""), "myprofile.yaml")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("is empty"))
		Expect(err.Error()).To(ContainSubstring("myprofile.yaml"))
		Expect(err.Error()).NotTo(ContainSubstring("EOF"))
		Expect(err.Error()).NotTo(ContainSubstring("is invalid"))
	})

	It("returns a plain 'is empty' error for a comment-only YAML file", func() {
		src := `# only a comment
# nothing else here
`
		_, err := ParseProfile(strings.NewReader(src), "myprofile.yaml")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("is empty"))
		Expect(err.Error()).To(ContainSubstring("myprofile.yaml"))
		Expect(err.Error()).NotTo(ContainSubstring("EOF"))
		Expect(err.Error()).NotTo(ContainSubstring("is invalid"))
	})
})

var _ = Describe("ParseProfile format independence", func() {
	const minimalYAML = `
schema: polypkg.spec/v1
name: minimal
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: polypkg-native
    url: https://example.invalid/repo
    trust_root: /tmp/key.pub
`
	const minimalJSONC = `{
  // a minimal profile
  "schema": "polypkg.spec/v1",
  "name": "minimal",
  "scopes": { "user": { "substrate": "store" } },
  "sources": {
    "order": ["native"],
    "native": {
      "type": "polypkg-native",
      "url": "https://example.invalid/repo",
      "trust_root": "/tmp/key.pub",
    }, // trailing comma allowed
  }
}
`

	const richYAML = `
schema: polypkg.spec/v1
name: rich-profile
description: exercises optional blocks, multiple scopes, and per-source trust_doc
scopes:
  user:
    substrate: store
    prefix: $XDG_DATA_HOME/polypkg
  system:
    substrate: store
sources:
  order: [primary, secondary]
  primary:
    type: polypkg-native
    url: https://primary.invalid/repo
    trust_root: /etc/polypkg/primary.pub
  secondary:
    type: polypkg-native
    url: https://secondary.invalid/repo
    trust_root: /etc/polypkg/secondary.pub
    trust_doc: /etc/polypkg/secondary.trust.json
variants:
  arch: amd64
  variant: minimal
packages:
  user:
    hello:
      version: "=1.0.0"
    world:
      version: ">=2.0.0,<3.0.0"
      source: primary
  system:
    base:
      version: "=1.2.3"
starlark:
  max_steps: 5000000
  timeout: 3s
  max_memory_bytes: 33554432
  max_output_bytes: 32768
retention:
  count: 10
  age: 14d
`
	const richJSONC = `{
  // rich-profile JSONC equivalent — covers every optional block
  "schema": "polypkg.spec/v1",
  "name": "rich-profile",
  "description": "exercises optional blocks, multiple scopes, and per-source trust_doc",
  "scopes": {
    "user":   { "substrate": "store", "prefix": "$XDG_DATA_HOME/polypkg" },
    "system": { "substrate": "store" },
  },
  "sources": {
    "order": ["primary", "secondary"],
    "primary": {
      "type": "polypkg-native",
      "url": "https://primary.invalid/repo",
      "trust_root": "/etc/polypkg/primary.pub",
    },
    "secondary": {
      "type": "polypkg-native",
      "url": "https://secondary.invalid/repo",
      "trust_root": "/etc/polypkg/secondary.pub",
      "trust_doc": "/etc/polypkg/secondary.trust.json",
    },
  },
  "variants": {
    "arch": "amd64",
    "variant": "minimal",
  },
  "packages": {
    "user": {
      "hello": { "version": "=1.0.0" },
      "world": { "version": ">=2.0.0,<3.0.0", "source": "primary" },
    },
    "system": {
      "base": { "version": "=1.2.3" },
    },
  },
  "starlark": {
    "max_steps": 5000000,
    "timeout": "3s",
    "max_memory_bytes": 33554432,
    "max_output_bytes": 32768,
  },
  "retention": {
    "count": 10,
    "age": "14d",
  },
}
`

	DescribeTable("yields equal structs from equivalent YAML and JSONC",
		func(yamlSrc, jsoncSrc string) {
			py, errY := ParseProfile(strings.NewReader(yamlSrc), "p.yaml")
			Expect(errY).NotTo(HaveOccurred())
			pj, errJ := ParseProfile(strings.NewReader(jsoncSrc), "p.jsonc")
			Expect(errJ).NotTo(HaveOccurred())
			Expect(pj).To(Equal(py))
		},
		Entry("minimal", minimalYAML, minimalJSONC),
		Entry("rich (all optional blocks)", richYAML, richJSONC),
	)
})

var _ = Describe("profile parse errors", func() {
	It("reports a field-level message for structurally wrong YAML, without Go type names", func() {
		_, err := ParseProfile(strings.NewReader("packages:\n  - hello\n"), "p.yaml")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).NotTo(ContainSubstring("!!seq"))
		Expect(err.Error()).NotTo(ContainSubstring("schema.PackageRef"))
		Expect(err.Error()).To(ContainSubstring("p.yaml"))
		Expect(err.Error()).To(ContainSubstring("/packages"))
	})

	It("names the file in YAML syntax errors and keeps line info", func() {
		_, err := ParseProfile(strings.NewReader("a: [unclosed"), "syn.yaml")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("syn.yaml"))
		Expect(err.Error()).To(ContainSubstring("line 1"))
	})

	It("names the file in JSONC syntax errors", func() {
		_, err := ParseProfile(strings.NewReader("{\"unclosed\": "), "syn.jsonc")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("syn.jsonc"))
	})

	It("names the user's file, not a file:// URL, for schema violations", func() {
		const minimal = "schema: polypkg.spec/v1\nname: t\nscopes:\n  user:\n    substrate: store\npackages:\n  user:\n    hello:\n      version: \"=1.0.0\"\n"
		_, err := ParseProfile(strings.NewReader(minimal), "p.yaml")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).NotTo(ContainSubstring("file://"))
		Expect(err.Error()).To(ContainSubstring("p.yaml"))
		// jsonschema reports a missing required property at the parent object's
		// InstanceLocation (root), so the pointer is not /sources — but the field
		// name must still appear in the message.
		Expect(err.Error()).To(ContainSubstring("sources"))
	})

	It("gives a plain-English message for tab indentation (Finding E)", func() {
		// YAML does not allow tabs; the parse error should say so in plain words.
		// "key:\n\tvalue" produces "found character that cannot start any token".
		src := "schema: polypkg.spec/v1\nname:\n\tt\n"
		_, err := ParseProfile(strings.NewReader(src), "tabs.yaml")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("tabs.yaml"))
		Expect(err.Error()).To(ContainSubstring("tab indentation"))
		Expect(err.Error()).To(ContainSubstring("line 3"))
		Expect(err.Error()).NotTo(ContainSubstring("found character that cannot start any token"))
	})

	It("keeps original yaml error for non-tab token errors (Finding E negative)", func() {
		// A non-tab token error (e.g. unclosed bracket) must retain yaml's
		// original diagnostic, not be silenced by the tab-detection path.
		src := "a: [unclosed"
		_, err := ParseProfile(strings.NewReader(src), "syn.yaml")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("syn.yaml"))
		Expect(err.Error()).To(ContainSubstring("line 1"))
		// Must NOT produce the tab message.
		Expect(err.Error()).NotTo(ContainSubstring("tab indentation"))
	})

	It("returns a plain 'is empty' error for an empty JSONC file (Finding F)", func() {
		_, err := ParseProfile(strings.NewReader(""), "profile.jsonc")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("is empty"))
		Expect(err.Error()).To(ContainSubstring("profile.jsonc"))
		Expect(err.Error()).NotTo(ContainSubstring("is invalid"))
	})

	It("returns full validation output for an explicit empty JSONC object (Finding F negative)", func() {
		// {} is not empty — it is an explicit object that just fails schema validation.
		_, err := ParseProfile(strings.NewReader("{}"), "profile.jsonc")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("is invalid"))
		Expect(err.Error()).NotTo(ContainSubstring("is empty"))
	})
})

var _ = Describe("ResolveStarlarkLimits", func() {
	It("returns full defaults when given nil", func() {
		d := ResolveStarlarkLimits(nil)
		Expect(d.MaxSteps).To(Equal(uint64(10_000_000)))
		Expect(time.Duration(d.Timeout)).To(Equal(2 * time.Second))
		Expect(d.MaxMemoryBytes).To(Equal(uint64(64 << 20)))
		Expect(d.MaxOutputBytes).To(Equal(64 << 10))
	})

	It("keeps non-zero overrides and fills defaults for zero fields", func() {
		got := ResolveStarlarkLimits(&StarlarkLimits{MaxSteps: 5})
		Expect(got.MaxSteps).To(Equal(uint64(5)))
		Expect(time.Duration(got.Timeout)).To(Equal(2 * time.Second))
	})
})

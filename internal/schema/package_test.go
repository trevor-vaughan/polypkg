package schema

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ParsePackage", func() {
	It("parses a minimal package with two actions", func() {
		src := `
schema: polypkg.package/v1
name: hello
version: 1.0.0
actions:
  - phase: post-place
    action: dir
    params:
      path: $ACTIVE/hello/bin
      mode: "0o755"
  - phase: post-place
    action: install
    params:
      src: content/bin/hi
      dest: $ACTIVE/hello/bin/hi
      policy: symlink
`
		p, err := ParsePackage(strings.NewReader(src), "")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Name).To(Equal("hello"))
		Expect(p.Version).To(Equal("1.0.0"))
		Expect(p.Actions).To(HaveLen(2))
		Expect(p.Actions[0].Action).To(Equal("dir"))
		Expect(p.Actions[1].Action).To(Equal("install"))
	})

	It("rejects an unknown action name", func() {
		src := `
schema: polypkg.package/v1
name: hello
version: 1.0.0
actions:
  - phase: post-place
    action: nonexistent
    params: {}
`
		_, err := ParsePackage(strings.NewReader(src), "")
		Expect(err).To(HaveOccurred())
	})

	It("preserves a UTF-8 title verbatim", func() {
		src := `schema: polypkg.package/v1
name: hello
title: "Hello · こんにちは"
version: 1.0.0
actions:
  - phase: post-place
    action: dir
    params: { path: "$ACTIVE/hello" }
`
		p, err := ParsePackage(strings.NewReader(src), "polypkg.yaml")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Title).To(Equal("Hello · こんにちは"))
	})

	It("leaves title empty when the field is absent", func() {
		src := `schema: polypkg.package/v1
name: hello
version: 1.0.0
actions:
  - phase: post-place
    action: dir
    params: { path: "$ACTIVE/hello" }
`
		p, err := ParsePackage(strings.NewReader(src), "polypkg.yaml")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Title).To(BeEmpty())
	})

	It("captures depends, provides, conflicts, and obsoletes relations", func() {
		src := `
schema: polypkg.package/v1
name: python-utils
version: 1.2.4
depends:
  - name: libyaml
    version: "^0.2"
  - name: python3
provides:
  - name: yaml-parser
    version: 1.2.4
conflicts:
  - name: python-utils-legacy
obsoletes:
  - name: pyyaml-shim
    version: "<2.0"
actions:
  - phase: post-place
    action: dir
    params: {path: lib, mode: "0o755"}
`
		p, err := ParsePackage(strings.NewReader(src), "")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Depends).To(HaveLen(2))
		Expect(p.Depends[0].Name).To(Equal("libyaml"))
		Expect(p.Depends[0].Version).To(Equal("^0.2"))
		Expect(p.Depends[1].Name).To(Equal("python3"))
		Expect(p.Depends[1].Version).To(BeEmpty())
		Expect(p.Provides).To(HaveLen(1))
		Expect(p.Provides[0].Name).To(Equal("yaml-parser"))
		Expect(p.Conflicts).To(HaveLen(1))
		Expect(p.Conflicts[0].Name).To(Equal("python-utils-legacy"))
		Expect(p.Obsoletes).To(HaveLen(1))
		Expect(p.Obsoletes[0].Version).To(Equal("<2.0"))
	})

	It("captures recommends and suggests relations", func() {
		src := `
schema: polypkg.package/v1
name: foo
version: 1.2.3
depends:
  - name: libc
recommends:
  - name: foo-extras
    version: ">=1.0.0"
suggests:
  - name: foo-docs
actions:
  - phase: post-place
    action: path
    params:
      name: foo
      source: $ACTIVE/foo/bin/foo
`
		p, err := ParsePackage(strings.NewReader(src), "polypkg.yaml")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Recommends).To(HaveLen(1))
		Expect(p.Recommends[0].Name).To(Equal("foo-extras"))
		Expect(p.Recommends[0].Version).To(Equal(">=1.0.0"))
		Expect(p.Suggests).To(HaveLen(1))
		Expect(p.Suggests[0].Name).To(Equal("foo-docs"))
	})

	It("accepts a package with no relations declared", func() {
		src := `
schema: polypkg.package/v1
name: bare
version: 1.0.0
actions:
  - phase: post-place
    action: dir
    params: {path: lib, mode: "0o755"}
`
		p, err := ParsePackage(strings.NewReader(src), "")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Depends).To(BeNil())
		Expect(p.Provides).To(BeNil())
		Expect(p.Conflicts).To(BeNil())
		Expect(p.Obsoletes).To(BeNil())
		Expect(p.Recommends).To(BeNil())
		Expect(p.Suggests).To(BeNil())
	})

	It("captures !starlark expressions as StarlarkExpr values", func() {
		src := `schema: polypkg.package/v1
name: hello
version: 1.0.0
actions:
  - phase: post-place
    action: install
    params:
      src: $PKG/bin/hi
      dest: !starlark |
        return "$ACTIVE/hello/" + host.arch + "/hi"
      policy: symlink
`
		p, err := ParsePackage(strings.NewReader(src), "")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Actions).To(HaveLen(1))
		expr, ok := p.Actions[0].Params["dest"].(StarlarkExpr)
		Expect(ok).To(BeTrue(), "dest should be a StarlarkExpr, got %T", p.Actions[0].Params["dest"])
		Expect(expr.Source).To(ContainSubstring("host.arch"))
		Expect(p.Actions[0].Params["src"]).To(Equal("$PKG/bin/hi"))
		Expect(p.Actions[0].Params["policy"]).To(Equal("symlink"))
	})

	It("leaves literal params untouched", func() {
		src := `schema: polypkg.package/v1
name: hello
version: 1.0.0
actions:
  - phase: post-place
    action: dir
    params:
      path: $ACTIVE/hello
      mode: "0o755"
`
		p, err := ParsePackage(strings.NewReader(src), "")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Actions[0].Params["path"]).To(Equal("$ACTIVE/hello"))
		Expect(p.Actions[0].Params["mode"]).To(Equal("0o755"))
	})

	It("rejects unknown keys at the action level", func() {
		src := `schema: polypkg.package/v1
name: hello
version: 1.0.0
actions:
  - phase: post-place
    action: dir
    params: {path: $ACTIVE/x}
    bogus: nope
`
		_, err := ParsePackage(strings.NewReader(src), "")
		Expect(err).To(HaveOccurred())
	})

	It("rejects YAML anchors and aliases", func() {
		src := `
schema: polypkg.package/v1
name: hello
version: 1.0.0
base: &b
  phase: post-place
actions:
  - <<: *b
    action: dir
    params: {path: /x, mode: "0o755"}
`
		_, err := ParsePackage(strings.NewReader(src), "")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("anchor"))
	})

	It("captures a per-action drift override", func() {
		src := `schema: polypkg.package/v1
name: hello
version: 1.0.0
actions:
  - phase: post-place
    action: install
    drift: refuse
    params:
      src: $PKG/bin/hi
      dest: $ACTIVE/hello/bin/hi
`
		p, err := ParsePackage(strings.NewReader(src), "")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Actions).To(HaveLen(1))
		Expect(p.Actions[0].Drift).To(Equal("refuse"))
	})

	It("leaves drift empty when the field is absent", func() {
		src := `schema: polypkg.package/v1
name: hello
version: 1.0.0
actions:
  - phase: post-place
    action: dir
    params:
      path: $ACTIVE/hello/bin
`
		p, err := ParsePackage(strings.NewReader(src), "")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Actions[0].Drift).To(BeEmpty())
	})

	It("rejects an invalid drift value", func() {
		src := `schema: polypkg.package/v1
name: hello
version: 1.0.0
actions:
  - phase: post-place
    action: dir
    drift: explode
    params:
      path: $ACTIVE/hello/bin
`
		_, err := ParsePackage(strings.NewReader(src), "")
		Expect(err).To(HaveOccurred())
	})

	It("accepts an empty YAML file (schema validation supplies the verdict)", func() {
		_, err := ParsePackage(strings.NewReader(""), "")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Or(ContainSubstring("schema"), ContainSubstring("required")))
		Expect(err.Error()).NotTo(ContainSubstring("EOF"))
	})

	It("accepts a comment-only YAML file (schema validation supplies the verdict)", func() {
		src := `# only a comment
# nothing else here
`
		_, err := ParsePackage(strings.NewReader(src), "")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(Or(ContainSubstring("schema"), ContainSubstring("required")))
		Expect(err.Error()).NotTo(ContainSubstring("EOF"))
	})
})

var _ = Describe("Package config action", func() {
	It("accepts a config action with a policy param", func() {
		doc := `schema: polypkg.package/v1
name: hello
version: 1.0.0
actions:
  - phase: post-place
    action: config
    drift: notify_preserve
    params:
      src: $PKG/app.conf
      dest: $ACTIVE/hello/etc/app.conf
      policy: preserve
`
		p, err := ParsePackage(strings.NewReader(doc), "")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Actions[0].Action).To(Equal("config"))
	})
})

var _ = Describe("unmanaged and state actions schema", func() {
	It("accepts unmanaged and state actions in a package", func() {
		doc := `schema: polypkg.package/v1
name: hello
version: 1.0.0
actions:
  - phase: post-place
    action: unmanaged
    params: {path: $ACTIVE/hello/var/run/app.sock}
  - phase: post-place
    action: state
    params: {path: $ACTIVE/hello/var/lib/app}
`
		p, err := ParsePackage(strings.NewReader(doc), "")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Actions).To(HaveLen(2))
	})

	It("round-trips ghost and state ownership entries", func() {
		doc := `{
  "schema": "polypkg.ownership/v1", "scope": "user",
  "entries": [
    {"path":"hello/var/run/app.sock","package":"hello","version":"1.0.0","action":"unmanaged",
     "expected":{"file_type":"ghost"},"drift_policy":"unmanaged","stat":{"size":0,"mtime_ns":0,"inode":0}},
    {"path":"hello/var/lib/app","package":"hello","version":"1.0.0","action":"state",
     "expected":{"file_type":"state","target":"/data/state/hello/var/lib/app"},"drift_policy":"state",
     "stat":{"size":0,"mtime_ns":0,"inode":0}}
  ]
}`
		own, err := ParseOwnership(strings.NewReader(doc))
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries).To(HaveLen(2))
		Expect(own.Entries[0].Expected.FileType).To(Equal("ghost"))
		Expect(own.Entries[1].Expected.FileType).To(Equal("state"))
	})
})

var _ = Describe("path action schema", func() {
	It("accepts the path action in a package", func() {
		doc := `schema: polypkg.package/v1
name: hello
version: 1.0.0
actions:
  - phase: post-place
    action: path
    params: {name: hello, source: $ACTIVE/hello/bin/hello}
`
		p, err := ParsePackage(strings.NewReader(doc), "polypkg.yaml")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Actions).To(HaveLen(1))
		Expect(p.Actions[0].Action).To(Equal("path"))
	})

	It("round-trips a path ownership entry", func() {
		doc := `{
  "schema": "polypkg.ownership/v1", "scope": "user",
  "entries": [
    {"path":"bin/hello","package":"hello","version":"1.0.0","action":"path",
     "expected":{"file_type":"symlink","target":"/x/active/hello/bin/hello"},
     "drift_policy":"notify_heal","stat":{"size":0,"mtime_ns":0,"inode":0}}
  ]
}`
		own, err := ParseOwnership(strings.NewReader(doc))
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries).To(HaveLen(1))
		Expect(own.Entries[0].Action).To(Equal("path"))
	})
})

var _ = Describe("alternatives action schema", func() {
	It("accepts the alternatives action in a package", func() {
		doc := `schema: polypkg.package/v1
name: neovim
version: 1.0.0
actions:
  - phase: post-place
    action: alternatives
    params: {name: editor, source: $ACTIVE/neovim/bin/nvim, priority: 30}
`
		p, err := ParsePackage(strings.NewReader(doc), "polypkg.yaml")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Actions).To(HaveLen(1))
		Expect(p.Actions[0].Action).To(Equal("alternatives"))
	})

	It("round-trips an alternatives ownership entry with priority", func() {
		doc := `{
  "schema": "polypkg.ownership/v1", "scope": "user",
  "entries": [
    {"path":"bin/editor","package":"neovim","version":"1.0.0","action":"alternatives",
     "expected":{"file_type":"symlink","target":"/x/active/neovim/bin/nvim","priority":30},
     "drift_policy":"notify_heal","stat":{"size":0,"mtime_ns":0,"inode":0}}
  ]
}`
		own, err := ParseOwnership(strings.NewReader(doc))
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Entries).To(HaveLen(1))
		Expect(own.Entries[0].Action).To(Equal("alternatives"))
		Expect(own.Entries[0].Expected.Priority).To(Equal(30))
	})
})

var _ = Describe("ParsePackage format independence", func() {
	const minimalYAML = `
schema: polypkg.package/v1
name: hello
version: 1.0.0
actions:
  - phase: post-place
    action: dir
    params:
      path: /tmp/hello
      mode: "0o755"
`
	const minimalJSONC = `{
  // a minimal package
  "schema": "polypkg.package/v1",
  "name": "hello",
  "version": "1.0.0",
  "actions": [
    {
      "phase": "post-place",
      "action": "dir",
      "params": {
        "path": "/tmp/hello",
        "mode": "0o755",
      },
    },
  ],
}
`

	const richYAML = `
schema: polypkg.package/v1
name: rich-pkg
version: 2.1.0
description: exercises relations, multi-phase actions, drift, and varied param types
depends:
  - name: libfoo
  - name: libbar
    version: ">=2.0.0"
provides:
  - name: rich-pkg-alias
conflicts:
  - name: old-rich-pkg
obsoletes:
  - name: legacy-rich
    version: "<1.0.0"
actions:
  - phase: post-place
    action: dir
    params:
      path: $ACTIVE/rich/bin
      mode: "0o755"
  - phase: post-place
    action: install
    drift: refuse
    params:
      src: $PKG/content/bin/rich
      dest: $ACTIVE/rich/bin/rich
      policy: symlink
      count: 3
      threshold: 1.5
      enabled: true
      tags: [primary, fast, signed]
      opts:
        retries: 2
        host: $HOSTNAME
      arch_lookup: !starlark "host.arch"
  - phase: post-activate
    action: perms
    drift: silent_heal
    params:
      path: $ACTIVE/rich/bin/rich
      mode: "0o755"
`
	const richJSONC = `{
  // rich-pkg recipe in JSONC: same logical content as the YAML form.
  "schema": "polypkg.package/v1",
  "name": "rich-pkg",
  "version": "2.1.0",
  "description": "exercises relations, multi-phase actions, drift, and varied param types",
  "depends": [
    { "name": "libfoo" },
    { "name": "libbar", "version": ">=2.0.0" },
  ],
  "provides": [
    { "name": "rich-pkg-alias" },
  ],
  "conflicts": [
    { "name": "old-rich-pkg" },
  ],
  "obsoletes": [
    { "name": "legacy-rich", "version": "<1.0.0" },
  ],
  "actions": [
    {
      "phase": "post-place",
      "action": "dir",
      "params": {
        "path": "$ACTIVE/rich/bin",
        "mode": "0o755",
      },
    },
    {
      "phase": "post-place",
      "action": "install",
      "drift": "refuse",
      "params": {
        "src": "$PKG/content/bin/rich",
        "dest": "$ACTIVE/rich/bin/rich",
        "policy": "symlink",
        "count": 3,
        "threshold": 1.5,
        "enabled": true,
        "tags": ["primary", "fast", "signed"],
        "opts": {
          "retries": 2,
          "host": "$HOSTNAME",
        },
        "arch_lookup": { "!starlark": "host.arch" },
      },
    },
    {
      "phase": "post-activate",
      "action": "perms",
      "drift": "silent_heal",
      "params": {
        "path": "$ACTIVE/rich/bin/rich",
        "mode": "0o755",
      },
    },
  ],
}
`

	DescribeTable("yields equal structs from equivalent YAML and JSONC",
		func(yamlSrc, jsoncSrc string) {
			py, errY := ParsePackage(strings.NewReader(yamlSrc), "polypkg.yaml")
			Expect(errY).NotTo(HaveOccurred())
			pj, errJ := ParsePackage(strings.NewReader(jsoncSrc), "polypkg.jsonc")
			Expect(errJ).NotTo(HaveOccurred())
			Expect(pj).To(Equal(py))
		},
		Entry("minimal with string action params", minimalYAML, minimalJSONC),
		Entry("rich (relations + multi-phase actions + varied params + starlark envelope)", richYAML, richJSONC),
	)
})

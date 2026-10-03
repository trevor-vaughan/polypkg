package schema

import (
	"encoding/json"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// profileWithSource renders a minimal valid profile whose sources map carries a
// single backend under the given key.
func profileWithSource(sourceName string) string {
	return `
schema: polypkg.spec/v1
name: sourcename
scopes:
  user:
    substrate: store
sources:
  order: ["` + sourceName + `"]
  "` + sourceName + `":
    type: polypkg-native
    url: https://example.invalid/repo
    trust_root: /tmp/key.pub
`
}

var _ = Describe("ParseProfile source-name validation", func() {
	// A source name is a map key that reaches the filesystem: trust state is
	// stored per source at <state>/trust/<source>.json, and producers derive
	// signing-key paths from the same name. `polypkg source add` already
	// enforces the slug grammar, but a hand-edited profile bypasses the CLI, so
	// the schema has to refuse a bad name at the parse boundary.
	DescribeTable("rejects a source name that is not a slug",
		func(sourceName string) {
			_, err := ParseProfile(strings.NewReader(profileWithSource(sourceName)), "profile.yaml")
			Expect(err).To(HaveOccurred(),
				"source name %q must be rejected at parse time", sourceName)
			Expect(err.Error()).To(ContainSubstring(sourceName),
				"the error must name the offending key")
		},
		Entry("parent-directory traversal", "../acme"),
		Entry("embedded separator", "a/b"),
		Entry("bare parent directory", ".."),
		Entry("current directory", "."),
		Entry("absolute path", "/etc/acme"),
		Entry("empty name", ""),
	)

	It("accepts ordinary slug source names", func() {
		for _, name := range []string{"acme", "acme-prod", "acme_prod", "ACME2"} {
			p, err := ParseProfile(strings.NewReader(profileWithSource(name)), "profile.yaml")
			Expect(err).NotTo(HaveOccurred(), "source name %q must be accepted", name)
			Expect(p.Sources.Sources).To(HaveKey(name))
		}
	})

	It("still accepts the reserved `order` key alongside a source", func() {
		// `order` lives in the same map as the source backends
		// (profileedit.ReservedSourceName). A propertyNames constraint applies to
		// every key in the object, so it must admit `order` too.
		src := `
schema: polypkg.spec/v1
name: sourcename
scopes:
  user:
    substrate: store
sources:
  order: [acme, backup]
  acme:
    type: polypkg-native
    url: https://example.invalid/repo
    trust_root: /tmp/key.pub
  backup:
    type: polypkg-native
    url: https://example.invalid/backup
    trust_root: /tmp/key.pub
`
		p, err := ParseProfile(strings.NewReader(src), "profile.yaml")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Sources.Order).To(Equal([]string{"acme", "backup"}))
		Expect(p.Sources.Sources).To(HaveKey("acme"))
		Expect(p.Sources.Sources).To(HaveKey("backup"))
	})

	It("constrains sources keys with the shared source-name grammar", func() {
		// One grammar, one place. If SourceNamePattern changes, the schema must
		// change with it rather than drifting into a second definition.
		var doc struct {
			Properties struct {
				Sources struct {
					PropertyNames struct {
						Pattern string `json:"pattern"`
					} `json:"propertyNames"`
				} `json:"sources"`
			} `json:"properties"`
		}
		Expect(json.Unmarshal(profileSchemaV1, &doc)).To(Succeed())
		Expect(doc.Properties.Sources.PropertyNames.Pattern).To(Equal(SourceNamePattern))
	})
})

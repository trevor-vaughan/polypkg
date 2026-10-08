package schema

import (
	"encoding/json"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/platform"
)

// recipeWithPlatform renders a minimal valid recipe; platformLine is inserted
// verbatim (empty for none).
func recipeWithPlatform(platformLine string) string {
	return "schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\n" + platformLine +
		"actions:\n  - phase: post-place\n    action: dir\n    params: { path: $ACTIVE/hello }\n"
}

var _ = Describe("Package platform", func() {
	It("parses platform from YAML", func() {
		p, err := ParsePackage(strings.NewReader(recipeWithPlatform("platform: linux/amd64\n")), "polypkg.yaml")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Platform).To(Equal("linux/amd64"))
	})

	It("parses platform from JSONC", func() {
		src := `{
  "schema": "polypkg.package/v1", "name": "hello", "version": "1.0.0",
  "platform": "darwin/arm64", // per-platform artifact
  "actions": [{"phase": "post-place", "action": "dir", "params": {"path": "$ACTIVE/hello"}}],
}`
		p, err := ParsePackage(strings.NewReader(src), "polypkg.jsonc")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Platform).To(Equal("darwin/arm64"))
	})

	It("leaves platform empty (platform-agnostic) when omitted", func() {
		p, err := ParsePackage(strings.NewReader(recipeWithPlatform("")), "polypkg.yaml")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Platform).To(BeEmpty())
	})

	It("treats an explicit empty platform as omitted", func() {
		p, err := ParsePackage(strings.NewReader(recipeWithPlatform("platform: \"\"\n")), "polypkg.yaml")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Platform).To(BeEmpty())
	})

	It("accepts a well-formed variant: producer strictness is pkg lint's job, not the parser's", func() {
		p, err := ParsePackage(strings.NewReader(recipeWithPlatform("platform: linux/arm/v7\n")), "polypkg.yaml")
		Expect(err).NotTo(HaveOccurred())
		Expect(p.Platform).To(Equal("linux/arm/v7"))
	})

	DescribeTable("refuses a malformed platform at parse time",
		func(value string) {
			_, err := ParsePackage(strings.NewReader(recipeWithPlatform("platform: "+value+"\n")), "polypkg.yaml")
			Expect(err).To(HaveOccurred())
		},
		Entry("upper case", "Linux/amd64"),
		Entry("the reserved agnostic token", "any"),
		Entry("one segment", "linux"),
		Entry("four segments", "linux/arm/v7/x"),
		Entry("traversal", "../amd64"),
	)

	It("uses platform.Pattern, the grammar platform.ValidateConsumer enforces", func() {
		var doc struct {
			Properties struct {
				Platform struct {
					Pattern string `json:"pattern"`
				} `json:"platform"`
			} `json:"properties"`
		}
		Expect(json.Unmarshal(packageSchemaV1, &doc)).To(Succeed())
		Expect(doc.Properties.Platform.Pattern).To(Equal(platform.Pattern))
	})
})

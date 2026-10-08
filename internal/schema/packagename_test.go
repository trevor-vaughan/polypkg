package schema

import (
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ValidatePackageName", func() {
	DescribeTable("accepts an ASCII slug",
		func(name string) { Expect(ValidatePackageName(name)).To(Succeed()) },
		Entry("lower case", "hello"),
		Entry("mixed case, digits, underscore and hyphen", "Hello_World-2"),
		Entry("one character", "x"),
	)

	DescribeTable("refuses a name that could steer a path or a YAML key",
		func(name string) {
			err := ValidatePackageName(name)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("%q", name))
			Expect(err.Error()).To(ContainSubstring(PackageNamePattern))
		},
		Entry("empty", ""),
		Entry("traversal", "../../etc/x"),
		Entry("dot-dot", ".."),
		Entry("path separator", "a/b"),
		Entry("backslash", `a\b`),
		Entry("dot", "py3.11"),
		Entry("space", "foo bar"),
		Entry("YAML metacharacters", "a:b"),
		Entry("newline", "hello\noutput: /tmp/x"),
		Entry("non-ASCII", "hełło"),
	)

	It("is the pattern package-v1.json enforces on a package name", func() {
		var doc struct {
			Properties struct {
				Name struct {
					Pattern string `json:"pattern"`
				} `json:"name"`
			} `json:"properties"`
		}
		Expect(json.Unmarshal(packageSchemaV1, &doc)).To(Succeed())
		Expect(doc.Properties.Name.Pattern).To(Equal(PackageNamePattern))
	})
})

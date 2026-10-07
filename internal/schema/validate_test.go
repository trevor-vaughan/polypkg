package schema

import (
	"os"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("schema validation errors", func() {
	It("do not leak the working directory as a file:// URL", func() {
		cwd, err := os.Getwd()
		Expect(err).NotTo(HaveOccurred())

		_, err = ParseOwnership(strings.NewReader(
			`{"schema":"polypkg.ownership/v1","scope":"user","entries":[],"newfield":1}`))

		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("additional properties 'newfield' not allowed"))
		Expect(err.Error()).NotTo(ContainSubstring("file://"))
		Expect(err.Error()).NotTo(ContainSubstring(cwd))
	})

	It("resolve a schema whose $id is relative under the same base", func() {
		// repo-v1.json declares "$id": "repo-v1.json"; it must still compile
		// and validate once registered under an absolute URL.
		_, err := ParseRepoManifest(strings.NewReader("schema: polypkg.repo/v2\n"))
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).NotTo(ContainSubstring("file://"))
	})
})

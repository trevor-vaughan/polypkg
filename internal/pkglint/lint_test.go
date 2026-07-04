package pkglint_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/pkglint"
)

var _ = Describe("Lint", func() {
	It("returns no findings for a clean package", func() {
		res, err := pkglint.Lint("testdata/clean")
		Expect(err).ToNot(HaveOccurred())
		Expect(res.HasErrors()).To(BeFalse())
		Expect(res.Findings).To(BeEmpty())
	})

	It("reports PKG000 for malformed YAML with a line", func() {
		res, err := pkglint.Lint("testdata/badyaml")
		Expect(err).ToNot(HaveOccurred())
		Expect(res.Findings).To(HaveLen(1))
		Expect(res.Findings[0].RuleID).To(Equal("PKG000"))
		Expect(res.Findings[0].Severity).To(Equal(pkglint.SeverityError))
		Expect(res.Findings[0].Loc.Line).To(BeNumerically(">", 0))
	})
})

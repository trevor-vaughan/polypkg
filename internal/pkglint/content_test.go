package pkglint_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/pkglint"
)

var _ = Describe("content layer", func() {
	It("PKG006 reports a dangling content reference", func() {
		f := findRule(pkglintMust("testdata/danglingref"), "PKG006")
		Expect(f.Severity).To(Equal(pkglint.SeverityError))
		Expect(f.Message).To(ContainSubstring("missing"))
		Expect(f.Loc.Line).To(BeNumerically(">", 0))
	})

	It("does not report PKG006 when the referenced content file exists (clean)", func() {
		Expect(findRule0(pkglintMust("testdata/clean"), "PKG006")).To(BeZero())
	})
})

package pkglint_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/pkglint"
)

var _ = Describe("identity layer", func() {
	It("PKG007 reports a non-ASCII relation name", func() {
		f := findRule(pkglintMust("testdata/badrelname"), "PKG007")
		Expect(f.Severity).To(Equal(pkglint.SeverityError))
		Expect(f.Message).To(ContainSubstring("hełło"))
		Expect(f.Loc.Line).To(BeNumerically(">", 0))
	})

	It("does not report PKG007 for the clean package's relations", func() {
		Expect(findRule0(pkglintMust("testdata/badrelname"), "PKG008")).To(BeZero())
	})

	It("PKG008 reports a case-fold collision between name and a provides entry", func() {
		f := findRule(pkglintMust("testdata/casefold"), "PKG008")
		Expect(f.Severity).To(Equal(pkglint.SeverityError))
		Expect(f.Message).To(ContainSubstring("Hello"))
		Expect(f.Message).To(ContainSubstring("hello"))
		Expect(f.Loc.Line).To(BeNumerically(">", 0))
	})

	It("does not report PKG007 for the case-fold fixture (Hello is a valid slug)", func() {
		Expect(findRule0(pkglintMust("testdata/casefold"), "PKG007")).To(BeZero())
	})
})

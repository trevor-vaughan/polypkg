package pkglint_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/pkglint"
)

var _ = Describe("params layer", func() {
	It("PKG002 reports a missing required param (install without dest)", func() {
		f := findRule(pkglintMust("testdata/missingparam"), "PKG002")
		Expect(f.Severity).To(Equal(pkglint.SeverityError))
		Expect(f.Message).To(ContainSubstring("dest"))
		Expect(f.Loc.Line).To(BeNumerically(">", 0))
	})

	It("PKG003 reports an unknown param", func() {
		f := findRule(pkglintMust("testdata/unknownparam"), "PKG003")
		Expect(f.Severity).To(Equal(pkglint.SeverityError))
		Expect(f.Message).To(ContainSubstring("bogus"))
		Expect(f.Loc.Line).To(BeNumerically(">", 0))
	})

	It("PKG010 reports a bad enum value (install policy=teleport)", func() {
		f := findRule(pkglintMust("testdata/badenum"), "PKG010")
		Expect(f.Severity).To(Equal(pkglint.SeverityError))
		Expect(f.Message).To(ContainSubstring("teleport"))
		Expect(f.Loc.Line).To(BeNumerically(">", 0))
	})

	It("PKG010 reports a bad mode value (dir mode=not-octal)", func() {
		f := findRule(pkglintMust("testdata/badmode"), "PKG010")
		Expect(f.Severity).To(Equal(pkglint.SeverityError))
		Expect(f.Loc.Line).To(BeNumerically(">", 0))
	})

	It("PKG005 reports a ForbiddenWith constraint (alternatives master with name)", func() {
		f := findRule(pkglintMust("testdata/altconflict"), "PKG005")
		Expect(f.Severity).To(Equal(pkglint.SeverityError))
		Expect(f.Loc.Line).To(BeNumerically(">", 0))
	})

	It("PKG005 reports an Unsupported constraint (perms owner)", func() {
		f := findRule(pkglintMust("testdata/permsowner"), "PKG005")
		Expect(f.Severity).To(Equal(pkglint.SeverityError))
		Expect(f.Message).To(ContainSubstring("owner"))
		Expect(f.Loc.Line).To(BeNumerically(">", 0))
	})

	It("does not also report PKG003 for an Unsupported-named param (perms owner)", func() {
		Expect(findRule0(pkglintMust("testdata/permsowner"), "PKG003")).To(BeZero())
	})

	It("PKG007 reports a non-slug name-like param value (path name='bad name')", func() {
		f := findRule(pkglintMust("testdata/badpathname"), "PKG007")
		Expect(f.Severity).To(Equal(pkglint.SeverityError))
		Expect(f.Loc.Line).To(BeNumerically(">", 0))
	})
})

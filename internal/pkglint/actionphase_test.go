package pkglint_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/pkglint"
)

var _ = Describe("action/phase layer through Lint", func() {
	It("reports PKG009 for a file-placing action in a valid non-pre-swap phase", func() {
		res, err := pkglint.Lint("testdata/wrongphase") // install in post-activate
		Expect(err).ToNot(HaveOccurred())
		f := findRule(res, "PKG009")
		Expect(f.Severity).To(Equal(pkglint.SeverityError))
		Expect(f.Loc.Line).To(BeNumerically(">", 0))
		Expect(f.Message).To(ContainSubstring("install"))
	})

	// Decision 6: action and phase are CLOSED enums bound to action.Registry by the
	// package JSON schema, so ParsePackage rejects an unknown action/phase as a
	// structural PKG000 before the action/phase layer runs. These fixtures document
	// that the schema is the first gate for closed sets; PKG001/PKG004 themselves
	// are covered by the layer-level unit tests.
	It("reports PKG000 (not PKG001) for an unknown action through Lint", func() {
		res, err := pkglint.Lint("testdata/unknownverb")
		Expect(err).ToNot(HaveOccurred())
		Expect(res.Findings).To(HaveLen(1))
		Expect(res.Findings[0].RuleID).To(Equal("PKG000"))
	})

	It("reports PKG000 (not PKG004) for an unknown phase through Lint", func() {
		res, err := pkglint.Lint("testdata/badphase")
		Expect(err).ToNot(HaveOccurred())
		Expect(res.Findings).To(HaveLen(1))
		Expect(res.Findings[0].RuleID).To(Equal("PKG000"))
	})
})

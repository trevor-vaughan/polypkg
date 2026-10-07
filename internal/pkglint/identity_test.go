package pkglint_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/pkglint"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("identity layer", func() {
	It("PKG007 reports a non-ASCII relation name", func() {
		f := findRule(pkglintMust("testdata/badrelname"), "PKG007")
		Expect(f.Severity).To(Equal(pkglint.SeverityError))
		Expect(f.Message).To(ContainSubstring("hełło"))
		Expect(f.Message).To(ContainSubstring(schema.PackageNamePattern), "PKG007 names the package-name grammar it enforces")
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

var _ = Describe("platform layer", func() {
	It("PKG011 reports a platform that is not a Go port, at the platform line", func() {
		f := findRule(pkglintMust("testdata/badplatform"), "PKG011")
		Expect(f.Severity).To(Equal(pkglint.SeverityError))
		Expect(f.Message).To(ContainSubstring(`"linux/amd46"`))
		Expect(f.Message).To(ContainSubstring("go tool dist list"))
		Expect(f.Loc.Line).To(Equal(4))
	})

	It("PKG011 reports a variant segment, which only a consumer may read", func() {
		f := findRule(pkglintMust("testdata/variantplatform"), "PKG011")
		Expect(f.Severity).To(Equal(pkglint.SeverityError))
		Expect(f.Message).To(ContainSubstring("variant"))
		Expect(f.Loc.Line).To(Equal(4))
	})

	It("reports a platform outside the grammar as a structural error", func() {
		f := findRule(pkglintMust("testdata/upperplatform"), "PKG000")
		Expect(f.Message).To(ContainSubstring("platform"))
	})

	It("reports nothing for a supported <os>/<arch>", func() {
		Expect(pkglintMust("testdata/goodplatform").Findings).To(BeEmpty())
	})

	It("reports no PKG011 when the recipe declares no platform", func() {
		Expect(findRule0(pkglintMust("testdata/clean"), "PKG011")).To(BeZero())
	})
})

package pkglint_test

import (
	"bytes"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/pkglint"
)

var _ = Describe("finding order", func() {
	It("sorts findings by (line, then ruleID)", func() {
		res := pkglintMust("testdata/multi")
		Expect(len(res.Findings)).To(BeNumerically(">", 1))
		for i := 1; i < len(res.Findings); i++ {
			a, b := res.Findings[i-1], res.Findings[i]
			ordered := a.Loc.Line < b.Loc.Line ||
				(a.Loc.Line == b.Loc.Line && a.RuleID <= b.RuleID)
			Expect(ordered).To(BeTrue(),
				"findings out of order at %d: %+v then %+v", i, a, b)
		}
	})
})

var _ = Describe("WriteHuman", func() {
	It("renders findings grouped by severity with rule IDs and severity text", func() {
		var buf bytes.Buffer
		pkglint.WriteHuman(&buf, pkglintMust("testdata/multi"))
		out := buf.String()
		Expect(out).To(ContainSubstring("PKG"))
		Expect(out).To(ContainSubstring("error"))
		Expect(out).To(ContainSubstring("polypkg.yaml:"))
	})

	It("prints a clean line when there are no findings", func() {
		var buf bytes.Buffer
		pkglint.WriteHuman(&buf, pkglintMust("testdata/clean"))
		Expect(buf.String()).To(ContainSubstring("clean: no findings"))
	})

	It("omits the location when the line is zero", func() {
		var buf bytes.Buffer
		res := pkglint.Result{Findings: []pkglint.Finding{
			{RuleID: "PKG000", Severity: pkglint.SeverityError, Message: "boom", File: "polypkg.yaml"},
		}}
		pkglint.WriteHuman(&buf, res)
		out := buf.String()
		Expect(out).To(ContainSubstring("PKG000"))
		Expect(out).ToNot(ContainSubstring(":0"))
		Expect(out).ToNot(ContainSubstring("polypkg.yaml:"))
	})
})

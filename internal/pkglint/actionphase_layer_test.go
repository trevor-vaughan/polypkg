package pkglint

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// layerFinding returns the first finding with the given rule ID, or a zero
// Finding when absent. It lets the layer unit tests assert on unexported
// checkActionsAndParams output directly (Decision 6: PKG001/PKG004 are
// unreachable through Lint because the registry-bound schema rejects an
// unknown action/phase as PKG000 first, so they are tested at the layer level).
func layerFinding(fs []Finding, ruleID string) Finding {
	for _, f := range fs {
		if f.RuleID == ruleID {
			return f
		}
	}
	return Finding{}
}

var _ = Describe("checkActionsAndParams (action/phase layer)", func() {
	It("reports PKG001 for an action absent from the registry", func() {
		pkg := &schema.Package{
			Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{
				{Phase: "post-place", Action: "frobnicate", Params: map[string]any{}},
			},
		}
		f := layerFinding(checkActionsAndParams(pkg, &docIndex{}), "PKG001")
		Expect(f.RuleID).To(Equal("PKG001"))
		Expect(f.Severity).To(Equal(SeverityError))
		Expect(f.Message).To(ContainSubstring("frobnicate"))
	})

	It("reports PKG004 for a phase outside the six lifecycle phases", func() {
		pkg := &schema.Package{
			Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{
				{Phase: "elsewhen", Action: "dir", Params: map[string]any{"path": "$ACTIVE/hello"}},
			},
		}
		f := layerFinding(checkActionsAndParams(pkg, &docIndex{}), "PKG004")
		Expect(f.RuleID).To(Equal("PKG004"))
		Expect(f.Severity).To(Equal(SeverityError))
		Expect(f.Message).To(ContainSubstring("elsewhen"))
	})
})

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

var _ = Describe("checkActionsAndParams mode rule (PKG010)", func() {
	modePkg := func(act, mode string) *schema.Package {
		return &schema.Package{
			Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{
				{Phase: "post-place", Action: act, Params: map[string]any{"path": "$ACTIVE/hello", "mode": mode}},
			},
		}
	}

	DescribeTable("reports a mode the dir and perms actions refuse at apply",
		func(act, mode, bits string) {
			f := layerFinding(checkActionsAndParams(modePkg(act, mode), &docIndex{}), "PKG010")
			Expect(f.RuleID).To(Equal("PKG010"))
			Expect(f.Severity).To(Equal(SeverityError))
			Expect(f.Message).To(ContainSubstring(`"` + mode + `"`))
			Expect(f.Message).To(ContainSubstring("sets " + bits + ";"))
		},
		Entry("dir 0o777", "dir", "0o777", "group-write, other-write"),
		Entry("dir 0o757", "dir", "0o757", "other-write"),
		Entry("dir 0o775", "dir", "0o775", "group-write"),
		Entry("dir 0o1755", "dir", "0o1755", "sticky"),
		Entry("perms 0o4755", "perms", "0o4755", "setuid"),
		Entry("perms 0o2755", "perms", "0o2755", "setgid"),
		Entry("perms 0666", "perms", "0666", "group-write, other-write"),
	)

	// An 11-digit literal (which apply refuses as "bits outside 0o7777") never
	// reaches the bit rule here: the octal-syntax check allows at most four
	// digits, so it is reported as PKG010 "not an octal mode" first.
	It("reports perms 0o40000755", func() {
		f := layerFinding(checkActionsAndParams(modePkg("perms", "0o40000755"), &docIndex{}), "PKG010")
		Expect(f.RuleID).To(Equal("PKG010"))
		Expect(f.Severity).To(Equal(SeverityError))
		Expect(f.Message).To(ContainSubstring("0o40000755 is not an octal mode"))
	})

	DescribeTable("accepts a mode within 0755",
		func(act, mode string) {
			Expect(checkActionsAndParams(modePkg(act, mode), &docIndex{})).To(BeEmpty())
		},
		Entry("dir 0o755", "dir", "0o755"),
		Entry("dir 0o750", "dir", "0o750"),
		Entry("perms 0o644", "perms", "0o644"),
		Entry("perms 0600", "perms", "0600"),
		Entry("perms 0o0755 (four digits)", "perms", "0o0755"),
	)
})

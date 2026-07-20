package pkglint_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/pkglint"
)

func TestPkglint(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Pkglint Suite")
}

// findRule returns the first finding with the given rule ID, failing the spec
// if none is present.
func findRule(res pkglint.Result, ruleID string) pkglint.Finding {
	GinkgoHelper()
	for _, f := range res.Findings {
		if f.RuleID == ruleID {
			return f
		}
	}
	Fail("expected a " + ruleID + " finding, found none")
	return pkglint.Finding{}
}

// findRule0 returns the first finding with the given rule ID, or a zero
// Finding if none is present (for asserting a rule is absent).
func findRule0(res pkglint.Result, ruleID string) pkglint.Finding {
	for _, f := range res.Findings {
		if f.RuleID == ruleID {
			return f
		}
	}
	return pkglint.Finding{}
}

// pkglintMust lints dir and fails the spec if Lint returns an I/O error.
func pkglintMust(dir string) pkglint.Result {
	GinkgoHelper()
	res, err := pkglint.Lint(dir)
	Expect(err).ToNot(HaveOccurred())
	return res
}

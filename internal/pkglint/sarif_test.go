package pkglint_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"

	"github.com/trevor-vaughan/polypkg/internal/pkglint"
)

var _ = Describe("SARIF", func() {
	It("produces byte-identical canonical SARIF across two runs", func() {
		res := pkglintMust("testdata/multi")
		a, err := pkglint.SARIF(res)
		Expect(err).ToNot(HaveOccurred())
		b, err := pkglint.SARIF(res)
		Expect(err).ToNot(HaveOccurred())
		Expect(a).To(Equal(b))
	})

	It("has no timestamps or run GUIDs and uses relative paths", func() {
		out, err := pkglint.SARIF(pkglintMust("testdata/multi"))
		Expect(err).ToNot(HaveOccurred())
		s := string(out)
		// No absolute host paths leak into the reproducible predicate.
		Expect(s).ToNot(ContainSubstring("/workspace"))
		// No GUID fields (baselineGuid, run automationDetails guid, result guid).
		Expect(s).ToNot(ContainSubstring("guid"))
		Expect(s).ToNot(ContainSubstring("Guid"))
		// No invocation timestamps (startTimeUtc/endTimeUtc) nor automation
		// details. The library emits a static, empty "invocations":[] with no
		// time values; the guard is on the volatile timestamp fields, not the
		// (harmless) empty container key.
		Expect(s).ToNot(ContainSubstring("TimeUtc"))
		Expect(s).ToNot(ContainSubstring("automationDetails"))
		// The relative artifact path is present.
		Expect(s).To(ContainSubstring("polypkg.yaml"))
	})

	It("parses back as a valid 2.1.0 report", func() {
		out, err := pkglint.SARIF(pkglintMust("testdata/multi"))
		Expect(err).ToNot(HaveOccurred())
		_, err = sarif.FromBytes(out)
		Expect(err).ToNot(HaveOccurred())
	})

	It("clean package yields a valid SARIF run with zero results", func() {
		out, err := pkglint.SARIF(pkglintMust("testdata/clean"))
		Expect(err).ToNot(HaveOccurred())
		Expect(out).ToNot(BeEmpty())
		report, err := sarif.FromBytes(out)
		Expect(err).ToNot(HaveOccurred())
		Expect(report.Runs).To(HaveLen(1))
		Expect(report.Runs[0].Results).To(BeEmpty())
	})

	It("pins the tool version independent of the binary version", func() {
		out, err := pkglint.SARIF(pkglintMust("testdata/multi"))
		Expect(err).ToNot(HaveOccurred())
		report, err := sarif.FromBytes(out)
		Expect(err).ToNot(HaveOccurred())
		Expect(report.Runs[0].Tool.Driver.Name).ToNot(BeNil())
		Expect(*report.Runs[0].Tool.Driver.Name).To(Equal("polypkg"))
		Expect(report.Runs[0].Tool.Driver.Version).ToNot(BeNil())
		Expect(*report.Runs[0].Tool.Driver.Version).To(Equal("1"))
	})
})

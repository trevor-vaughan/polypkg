package planner

import (
	"github.com/Masterminds/semver/v3"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/resolver"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = DescribeTable("isExactPin",
	func(constraint, version string, want bool) {
		Expect(isExactPin(constraint, version)).To(Equal(want))
	},
	Entry("bare version is a pin", "1.9.0", "1.9.0", true),
	Entry("= prefix is a pin", "=1.9.0", "1.9.0", true),
	Entry("== prefix is a pin", "==1.9.0", "1.9.0", true),
	Entry("surrounding whitespace still pins", " 1.9.0 ", "1.9.0", true),
	Entry("caret range is not a pin", "^1.0.0", "1.9.0", false),
	Entry(">= range is not a pin", ">=1.0", "1.9.0", false),
	Entry("empty constraint (resolver-chosen dep) is not a pin", "", "1.9.0", false),
	Entry("pin for a different version does not pin this one", "=1.8.0", "1.9.0", false),
)

var _ = Describe("sourceOffers", func() {
	// A multi-version index: the downgrade guard must distinguish "the source
	// still offers the HWM version (constraint resolution picked lower)" from
	// "the source withdrew it (a forced downgrade)".
	var cat *resolver.Catalog
	BeforeEach(func() {
		var err error
		cat, err = resolver.BuildCatalog(&schema.Index{Packages: map[string][]schema.IndexEntry{
			"lib": {{Version: "1.0.0"}, {Version: "2.0.0"}},
		}}, "repo")
		Expect(err).NotTo(HaveOccurred())
	})

	It("is true when the top version is still offered", func() {
		Expect(sourceOffers(cat, "lib", semver.MustParse("2.0.0"))).To(BeTrue())
	})
	It("is true when a version above the recorded top is offered", func() {
		Expect(sourceOffers(cat, "lib", semver.MustParse("1.5.0"))).To(BeTrue())
	})
	It("is false when every current offer is below the top (withdrawal)", func() {
		Expect(sourceOffers(cat, "lib", semver.MustParse("3.0.0"))).To(BeFalse())
	})
	It("is false for a package the index no longer carries at all", func() {
		Expect(sourceOffers(cat, "gone", semver.MustParse("1.0.0"))).To(BeFalse())
	})
})

var _ = Describe("pinFor", func() {
	p := &schema.Profile{Packages: map[string]map[string]schema.PackageRef{
		"user": {"hello": {Version: "=1.9.0"}},
	}}

	It("returns the profile constraint for a profile-listed package", func() {
		Expect(pinFor(p, "user", "hello")).To(Equal("=1.9.0"))
	})
	It("returns empty for a resolver-chosen dependency with no profile entry", func() {
		Expect(pinFor(p, "user", "lib")).To(Equal(""))
	})
	It("returns empty for an absent scope", func() {
		Expect(pinFor(p, "system", "hello")).To(Equal(""))
	})
})

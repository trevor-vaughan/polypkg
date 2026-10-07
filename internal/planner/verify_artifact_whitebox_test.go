package planner

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/resolver"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

var _ = Describe("verifyArtifact platform binding", func() {
	data := []byte("artifact-bytes")

	entry := func(plat string) resolver.Resolved {
		return resolver.Resolved{Name: "hello", Version: "1.0.0", Source: "native", ContentHash: blake3Hex(data), Platform: plat}
	}
	// claimed returns a keyring whose verified claims bind name/version/hash
	// to the entry and carry plat as the platform field; plat "" omits the
	// field entirely (an old-format comment).
	claimed := func(plat string) *fakeKeyring {
		v := map[string]string{"name": "hello", "version": "1.0.0", "hash": blake3Hex(data)}
		if plat != "" {
			v["platform"] = plat
		}
		return &fakeKeyring{claims: trust.Claims{Values: v}}
	}

	DescribeTable("accepts a claim naming the entry's platform",
		func(entryPlat, claimPlat string) {
			staleable, err := verifyArtifact(data, "sig", claimed(claimPlat), entry(entryPlat))
			Expect(err).NotTo(HaveOccurred())
			Expect(staleable).To(BeFalse())
		},
		Entry("agnostic entry, any claim", "", "any"),
		Entry("platform entry, same platform claim", "linux/amd64", "linux/amd64"),
	)

	DescribeTable("refuses a claim for another platform",
		func(entryPlat, claimPlat, wantSubstr string) {
			staleable, err := verifyArtifact(data, "sig", claimed(claimPlat), entry(entryPlat))
			Expect(err).To(MatchError(ContainSubstring(wantSubstr)))
			// The signature already verified over these bytes, so a refetch
			// cannot change what they claim: evicting would only waste a download.
			Expect(staleable).To(BeFalse(), "a platform mismatch is not explained by stale cached bytes")
		},
		Entry("agnostic entry, platform claim", "", "darwin/arm64",
			"artifact signature for hello-1.0.0 claims platform darwin/arm64, expected any"),
		Entry("platform entry, any claim", "linux/amd64", "any",
			"artifact signature for hello-1.0.0 claims platform any, expected linux/amd64"),
		Entry("platform entry, other platform claim", "linux/amd64", "darwin/arm64",
			"artifact signature for hello-1.0.0 claims platform darwin/arm64, expected linux/amd64"),
	)

	It("refuses a claim with no platform field as a non-staleable trust fault", func() {
		staleable, err := verifyArtifact(data, "sig", claimed(""), entry(""))
		Expect(err).To(MatchError(ContainSubstring("artifact signature comment missing platform")))
		Expect(staleable).To(BeFalse())
	})

	It("refuses a malformed platform claim as a non-staleable trust fault", func() {
		staleable, err := verifyArtifact(data, "sig", claimed("../etc"), entry(""))
		Expect(err).To(MatchError(ContainSubstring(`artifact signature comment: platform "../etc" is not <os>/<arch>`)))
		Expect(staleable).To(BeFalse())
	})
})

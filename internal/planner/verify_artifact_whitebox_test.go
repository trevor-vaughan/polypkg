package planner

import (
	"errors"
	"fmt"

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

var _ = Describe("verifyArtifact refetch classification", func() {
	data := []byte("artifact-bytes")
	entry := resolver.Resolved{Name: "hello", Version: "1.0.0", Source: "native", ContentHash: blake3Hex(data)}
	// claiming returns a keyring that verifies any bytes and claims name,
	// version and hash for an agnostic artifact.
	claiming := func(name, version, hash string) *fakeKeyring {
		return &fakeKeyring{claims: trust.Claims{Values: map[string]string{
			"name": name, "version": version, "hash": hash, "platform": "any",
		}}}
	}

	It("marks a cryptographic signature mismatch staleable, since cached bytes may predate a republish", func() {
		kr := &fakeKeyring{err: fmt.Errorf("%w: signature does not match data", trust.ErrSignatureMismatch)}
		staleable, err := verifyArtifact(data, "sig", kr, entry)
		var sigErr *ArtifactSignatureError
		Expect(errors.As(err, &sigErr)).To(BeTrue(), "got %v", err)
		Expect(staleable).To(BeTrue())
	})

	It("marks an authorization failure terminal", func() {
		kr := &fakeKeyring{err: errors.New("key 0000 lacks role artifact")}
		staleable, err := verifyArtifact(data, "sig", kr, entry)
		Expect(err).To(MatchError(ContainSubstring("signature verification failed for hello-1.0.0")))
		Expect(staleable).To(BeFalse())
	})

	// The signature verified over these bytes, so a refetch would have to serve
	// different bytes under the same signature, which cannot verify: evicting
	// and downloading again only wastes the download.
	DescribeTable("marks a signed claim that disagrees with the index entry terminal",
		func(kr *fakeKeyring, want string) {
			staleable, err := verifyArtifact(data, "sig", kr, entry)
			Expect(err).To(MatchError(ContainSubstring(want)))
			Expect(staleable).To(BeFalse())
		},
		Entry("another name", claiming("other", "1.0.0", blake3Hex(data)), "artifact signature for hello-1.0.0 claims other-1.0.0/"),
		Entry("another version", claiming("hello", "2.0.0", blake3Hex(data)), "artifact signature for hello-1.0.0 claims hello-2.0.0/"),
		Entry("another hash", claiming("hello", "1.0.0", blake3Hex([]byte("other-bytes"))), "artifact signature for hello-1.0.0 claims hello-1.0.0/"+blake3Hex([]byte("other-bytes"))),
	)

	It("marks signed bytes whose hash differs from the signed, indexed hash terminal", func() {
		other := blake3Hex([]byte("other-bytes"))
		e := entry
		e.ContentHash = other
		staleable, err := verifyArtifact(data, "sig", claiming("hello", "1.0.0", other), e)
		Expect(err).To(MatchError(ContainSubstring("hash mismatch for hello-1.0.0: index has " + other)))
		Expect(staleable).To(BeFalse())
	})
})

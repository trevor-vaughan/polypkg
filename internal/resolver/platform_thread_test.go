package resolver

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/platform"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("platform threading", func() {
	It("carries an index entry's platform through Candidate into Resolved", func() {
		// The platform-specific entry names this host so the test keeps
		// passing once BuildCatalog filters by host.
		host := platform.Host()
		cat := build(map[string][]schema.IndexEntry{
			"tool": {{Version: "1.0.0", ContentHash: "blake3:t1", Artifact: "pool/t1.tar.zst", Platform: host}},
			"lib":  {{Version: "1.0.0", ContentHash: "blake3:l1", Artifact: "pool/l1.tar.zst"}},
		})

		cand, err := cat.Newest("tool", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(cand.Platform).To(Equal(host))

		out, err := Resolve([]Requirement{{Name: "tool"}, {Name: "lib"}}, cat)
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(HaveLen(2))
		// chosenToResolved sorts by name: lib, then tool.
		Expect(out[0].Name).To(Equal("lib"))
		Expect(out[0].Platform).To(BeEmpty(), "a platform-agnostic entry resolves with an empty platform")
		Expect(out[1].Name).To(Equal("tool"))
		Expect(out[1].Platform).To(Equal(host))
	})
})

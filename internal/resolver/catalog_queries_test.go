package resolver

import (
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// helloIdx builds a catalog with hello 1.0.0 and 1.1.0 plus a virtual provider
// (py 3.11.0 provides python3) to exercise Names()'s real-vs-virtual split.
func helloIdx() *schema.Index {
	return &schema.Index{
		Schema:  "polypkg.index/v2",
		Expires: "2099-01-01T00:00:00Z",
		Packages: map[string][]schema.IndexEntry{
			"hello": {
				{Version: "1.0.0", ContentHash: "blake3:h1", Artifact: "hello-1.0.0.tar.zst"},
				{Version: "1.1.0", ContentHash: "blake3:h2", Artifact: "hello-1.1.0.tar.zst"},
			},
			"py": {
				{Version: "3.11.0", ContentHash: "blake3:p1", Artifact: "py-3.11.0.tar.zst",
					Provides: []schema.Relation{{Name: "python3"}}},
			},
		},
	}
}

var _ = Describe("Catalog queries", func() {
	It("lists versions newest-first and reports unknown names as empty", func() {
		c, err := BuildCatalog(helloIdx(), "native")
		Expect(err).NotTo(HaveOccurred())

		got := c.Versions("hello")
		Expect(got).To(Equal([]string{"1.1.0", "1.0.0"}))

		// Unknown name returns an empty (non-nil) slice.
		unknown := c.Versions("nope")
		Expect(unknown).NotTo(BeNil())
		Expect(unknown).To(BeEmpty())
	})

	It("finds the newest candidate satisfying a constraint", func() {
		c, err := BuildCatalog(helloIdx(), "native")
		Expect(err).NotTo(HaveOccurred())

		// Empty constraint → newest overall.
		cand, err := c.Newest("hello", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(cand.Version).To(Equal("1.1.0"))

		// Constraint satisfied by 1.1.0 (newest).
		cand, err = c.Newest("hello", ">=1.0.0")
		Expect(err).NotTo(HaveOccurred())
		Expect(cand.Version).To(Equal("1.1.0"))

		// Constraint that only 1.0.0 satisfies.
		cand, err = c.Newest("hello", "=1.0.0")
		Expect(err).NotTo(HaveOccurred())
		Expect(cand.Version).To(Equal("1.0.0"))

		// Constraint that no version satisfies → KindNoVersion with Available.
		_, err = c.Newest("hello", "=9.9.9")
		Expect(err).To(HaveOccurred())
		var rerr *ResolveError
		Expect(errors.As(err, &rerr)).To(BeTrue())
		Expect(rerr.Kind).To(Equal(KindNoVersion))
		Expect(rerr.Requirement.Name).To(Equal("hello"))
		Expect(rerr.Available).To(Equal([]string{"1.1.0", "1.0.0"}))

		// Unknown name → KindUnknownName.
		_, err = c.Newest("nope", "")
		Expect(err).To(HaveOccurred())
		Expect(errors.As(err, &rerr)).To(BeTrue())
		Expect(rerr.Kind).To(Equal(KindUnknownName))
		Expect(rerr.Requirement.Name).To(Equal("nope"))
	})

	It("enumerates real package names sorted, excluding virtual-only names", func() {
		c, err := BuildCatalog(helloIdx(), "native")
		Expect(err).NotTo(HaveOccurred())

		got := c.Names()
		// "hello" and "py" are real; "python3" is virtual-only and must not appear.
		Expect(got).To(Equal([]string{"hello", "py"}))
	})
})

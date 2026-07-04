package resolver

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func idx() *schema.Index {
	return &schema.Index{
		Schema:  "polypkg.index/v2",
		Expires: "2099-01-01T00:00:00Z",
		Packages: map[string][]schema.IndexEntry{
			"a": {
				{Version: "1.0.0", ContentHash: "blake3:a1", Artifact: "a-1.0.0.tar.zst"},
				{Version: "1.2.0", ContentHash: "blake3:a2", Artifact: "a-1.2.0.tar.zst"},
			},
			"py": {
				{Version: "3.11.0", ContentHash: "blake3:p1", Artifact: "py-3.11.0.tar.zst",
					Provides: []schema.Relation{{Name: "python3"}}},
			},
		},
	}
}

var _ = Describe("BuildCatalog weak relations", func() {
	It("carries recommends and suggests onto candidates", func() {
		idx := &schema.Index{
			Schema:  "polypkg.index/v2",
			Expires: "2099-01-01T00:00:00Z",
			Packages: map[string][]schema.IndexEntry{
				"foo": {{
					Version: "1.0.0", ContentHash: "blake3:aa", Artifact: "foo.tar.zst",
					Recommends: []schema.Relation{{Name: "foo-extras"}},
					Suggests:   []schema.Relation{{Name: "foo-docs"}},
				}},
			},
		}
		cat, err := BuildCatalog(idx, "native")
		Expect(err).NotTo(HaveOccurred())
		cand, err := cat.Newest("foo", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(cand.Recommends).To(HaveLen(1))
		Expect(cand.Recommends[0].Name).To(Equal("foo-extras"))
		Expect(cand.Suggests).To(HaveLen(1))
		Expect(cand.Suggests[0].Name).To(Equal("foo-docs"))
	})
})

var _ = Describe("BuildCatalog", func() {
	It("sorts candidates by version descending", func() {
		c, err := BuildCatalog(idx(), "native")
		Expect(err).NotTo(HaveOccurred())
		got := c.candidatesFor(Requirement{Name: "a", VersionRange: ">=1.0.0"})
		Expect(got).To(HaveLen(2))
		Expect(got[0].Version).To(Equal("1.2.0"))
		Expect(got[1].Version).To(Equal("1.0.0"))
	})

	It("resolves candidates through a virtual provider", func() {
		c, err := BuildCatalog(idx(), "native")
		Expect(err).NotTo(HaveOccurred())
		got := c.candidatesFor(Requirement{Name: "python3"})
		Expect(got).To(HaveLen(1))
		Expect(got[0].Name).To(Equal("py"))
	})

	It("rejects an invalid semver version", func() {
		bad := &schema.Index{Schema: "polypkg.index/v2", Expires: "2099-01-01T00:00:00Z", Packages: map[string][]schema.IndexEntry{
			"x": {{Version: "not-semver", ContentHash: "blake3:x", Artifact: "x.tar.zst"}},
		}}
		_, err := BuildCatalog(bad, "native")
		Expect(err).To(HaveOccurred())
	})

	It("tags every candidate with the source name", func() {
		c, err := BuildCatalog(&schema.Index{
			Schema:  "polypkg.index/v2",
			Expires: "2099-01-01T00:00:00Z",
			Packages: map[string][]schema.IndexEntry{
				"hello": {{Version: "1.0.0", ContentHash: "blake3:aa", Artifact: "hello-1.0.0.tar.zst"}},
			},
		}, "native")
		Expect(err).NotTo(HaveOccurred())
		cand, err := c.Newest("hello", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(cand.Source).To(Equal("native"))
	})
})

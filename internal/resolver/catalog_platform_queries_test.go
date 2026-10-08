package resolver

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// platformQueriesIdx publishes, for a linux/amd64 host: hello 1.0.0 for the
// host and darwin, hello 2.0.0 and 10.0.0 for other platforms only (10.0.0
// sorts before 2.0.0 by semver but after it as a string), an agnostic greet,
// and an rg with no host artifact at all.
func platformQueriesIdx() *schema.Index {
	return &schema.Index{
		Schema:  "polypkg.index/v3",
		Expires: "2099-01-01T00:00:00Z",
		Packages: map[string][]schema.IndexEntry{
			"hello": {
				{Version: "1.0.0", Platform: "linux/amd64", ContentHash: "blake3:h1", Artifact: "pool/h1.tar.zst"},
				{Version: "1.0.0", Platform: "darwin/arm64", ContentHash: "blake3:h2", Artifact: "pool/h2.tar.zst"},
				{Version: "2.0.0", Platform: "darwin/arm64", ContentHash: "blake3:h3", Artifact: "pool/h3.tar.zst"},
				{Version: "10.0.0", Platform: "windows/amd64", ContentHash: "blake3:h4", Artifact: "pool/h4.tar.zst"},
			},
			"greet": {
				{Version: "1.0.0", ContentHash: "blake3:g1", Artifact: "pool/g1.tar.zst"},
			},
			"rg": {
				{Version: "14.0.0", Platform: "freebsd/amd64", ContentHash: "blake3:r1", Artifact: "pool/r1.tar.zst"},
				{Version: "14.1.1", Platform: "darwin/arm64", ContentHash: "blake3:r2", Artifact: "pool/r2.tar.zst"},
			},
		},
	}
}

var _ = Describe("Catalog platform enumeration", func() {
	build := func() *Catalog {
		c, err := BuildCatalog(platformQueriesIdx(), "native", "linux/amd64")
		Expect(err).NotTo(HaveOccurred())
		return c
	}

	It("lists names published for any platform, including names with no host artifact", func() {
		c := build()
		Expect(c.Names()).To(Equal([]string{"greet", "hello"}), "Names stays host-only")
		Expect(c.PublishedNames()).To(Equal([]string{"greet", "hello", "rg"}))
	})

	It("lists versions published only for other platforms, newest first by semver", func() {
		c := build()
		Expect(c.UnavailableVersions("hello")).To(Equal([]string{"10.0.0", "2.0.0"}),
			"1.0.0 has a host artifact, so it is available and not listed")
		Expect(c.UnavailableVersions("rg")).To(Equal([]string{"14.1.1", "14.0.0"}))
	})

	It("returns an empty non-nil slice when every version is available or the name is unknown", func() {
		c := build()
		for _, name := range []string{"greet", "nope"} {
			got := c.UnavailableVersions(name)
			Expect(got).NotTo(BeNil(), name)
			Expect(got).To(BeEmpty(), name)
		}
	})

	It("keeps both answers on the merged catalog FetchCatalog hands to the CLI", func() {
		merged, err := MergeCatalogs(map[string]*Catalog{"native": build()}, []string{"native"}, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(merged.PublishedNames()).To(Equal([]string{"greet", "hello", "rg"}))
		Expect(merged.UnavailableVersions("rg")).To(Equal([]string{"14.1.1", "14.0.0"}))
	})
})

var _ = Describe("Catalog platform queries across semver-equal spellings", func() {
	// hello 1.0 is built for the host and 1.0.0 (the same semver) for darwin;
	// 2.0 and 2.0.0 are built only for darwin and windows respectively.
	build := func() *Catalog {
		c, err := BuildCatalog(&schema.Index{
			Schema:  "polypkg.index/v3",
			Expires: "2099-01-01T00:00:00Z",
			Packages: map[string][]schema.IndexEntry{
				"hello": {
					{Version: "1.0", Platform: "linux/amd64", ContentHash: "blake3:a1", Artifact: "pool/a1.tar.zst"},
					{Version: "1.0.0", Platform: "darwin/arm64", ContentHash: "blake3:a2", Artifact: "pool/a2.tar.zst"},
					{Version: "2.0", Platform: "darwin/arm64", ContentHash: "blake3:a3", Artifact: "pool/a3.tar.zst"},
					{Version: "2.0.0", Platform: "windows/amd64", ContentHash: "blake3:a4", Artifact: "pool/a4.tar.zst"},
				},
			},
		}, "native", "linux/amd64")
		Expect(err).NotTo(HaveOccurred())
		return c
	}

	It("treats a version as available when a host build is semver-equal to it", func() {
		Expect(build().UnavailableVersions("hello")).To(Equal([]string{"2.0", "2.0.0"}),
			"1.0.0 is semver-equal to the host's 1.0, so it is installable here")
	})

	It("unions the other platforms of every semver-equal spelling", func() {
		c := build()
		Expect(c.OtherPlatforms("hello", "1.0")).To(Equal([]string{"darwin/arm64"}))
		Expect(c.OtherPlatforms("hello", "2.0.0")).To(Equal([]string{"darwin/arm64", "windows/amd64"}))
	})
})

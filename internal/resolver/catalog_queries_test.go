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
		Schema:  "polypkg.index/v3",
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
		c, err := BuildCatalog(helloIdx(), "native", testHost)
		Expect(err).NotTo(HaveOccurred())

		got := c.Versions("hello")
		Expect(got).To(Equal([]string{"1.1.0", "1.0.0"}))

		// Unknown name returns an empty (non-nil) slice.
		unknown := c.Versions("nope")
		Expect(unknown).NotTo(BeNil())
		Expect(unknown).To(BeEmpty())
	})

	It("finds the newest candidate satisfying a constraint", func() {
		c, err := BuildCatalog(helloIdx(), "native", testHost)
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
		c, err := BuildCatalog(helloIdx(), "native", testHost)
		Expect(err).NotTo(HaveOccurred())

		got := c.Names()
		// "hello" and "py" are real; "python3" is virtual-only and must not appear.
		Expect(got).To(Equal([]string{"hello", "py"}))
	})
})

var _ = Describe("wrong-platform failures", func() {
	// rg is published for two foreign platforms only; app depends on it.
	wrongPlatformIdx := func() *schema.Index {
		return &schema.Index{
			Schema:  "polypkg.index/v3",
			Expires: "2099-01-01T00:00:00Z",
			Packages: map[string][]schema.IndexEntry{
				"rg": {
					{Version: "14.0.0", Platform: "darwin/arm64", ContentHash: "blake3:r0", Artifact: "pool/r0.tar.zst"},
					{Version: "14.1.1", Platform: "windows/amd64", ContentHash: "blake3:r1", Artifact: "pool/r1.tar.zst"},
					{Version: "14.1.1", Platform: "darwin/arm64", ContentHash: "blake3:r2", Artifact: "pool/r2.tar.zst"},
				},
				"app": {
					{Version: "1.0.0", ContentHash: "blake3:a1", Artifact: "pool/a1.tar.zst",
						Depends: []schema.Relation{{Name: "rg"}}},
				},
			},
		}
	}
	const wantMsg = "rg 14.1.1 is published for darwin/arm64, windows/amd64; this host is " + testHost

	It("Newest names the newest version, its platforms, and the host", func() {
		c, err := BuildCatalog(wrongPlatformIdx(), "native", testHost)
		Expect(err).NotTo(HaveOccurred())
		_, err = c.Newest("rg", "")
		var rerr *ResolveError
		Expect(errors.As(err, &rerr)).To(BeTrue(), "got %v", err)
		Expect(rerr.Kind).To(Equal(KindWrongPlatform))
		Expect(rerr.Version).To(Equal("14.1.1"))
		Expect(rerr.Platforms).To(Equal([]string{"darwin/arm64", "windows/amd64"}))
		Expect(rerr.Host).To(Equal(testHost))
		Expect(err).To(MatchError(wantMsg))
	})

	It("Resolve reports a direct requirement the same way", func() {
		c, err := BuildCatalog(wrongPlatformIdx(), "native", testHost)
		Expect(err).NotTo(HaveOccurred())
		_, err = Resolve([]Requirement{{Name: "rg", VersionRange: ">=14.0.0"}}, c)
		var rerr *ResolveError
		Expect(errors.As(err, &rerr)).To(BeTrue(), "got %v", err)
		Expect(rerr.Kind).To(Equal(KindWrongPlatform))
		Expect(err).To(MatchError(wantMsg))
	})

	It("Resolve keeps the provenance chain for a transitive requirement", func() {
		c, err := BuildCatalog(wrongPlatformIdx(), "native", testHost)
		Expect(err).NotTo(HaveOccurred())
		_, err = Resolve([]Requirement{{Name: "app"}}, c)
		var rerr *ResolveError
		Expect(errors.As(err, &rerr)).To(BeTrue(), "got %v", err)
		Expect(rerr.Kind).To(Equal(KindWrongPlatform))
		Expect(err).To(MatchError(wantMsg + " (required via app -> rg)"))
	})

	It("leaves a name with no entries at all as unknown", func() {
		c, err := BuildCatalog(wrongPlatformIdx(), "native", testHost)
		Expect(err).NotTo(HaveOccurred())
		_, err = c.Newest("nope", "")
		var rerr *ResolveError
		Expect(errors.As(err, &rerr)).To(BeTrue())
		Expect(rerr.Kind).To(Equal(KindUnknownName))
		Expect(err).To(MatchError(`package "nope" not found in any configured source`))
	})
})

var _ = Describe("version-level wrong-platform failures", func() {
	// rg has 14.0.0 for this host; 14.1.1 and 14.2.0 exist only for other
	// platforms. app depends on, and tools recommends, a version this host
	// cannot install.
	idx := func() *schema.Index {
		return &schema.Index{
			Schema:  "polypkg.index/v3",
			Expires: "2099-01-01T00:00:00Z",
			Packages: map[string][]schema.IndexEntry{
				"rg": {
					{Version: "14.0.0", Platform: testHost, ContentHash: "blake3:r0", Artifact: "pool/r0.tar.zst"},
					{Version: "14.1.1", Platform: "windows/amd64", ContentHash: "blake3:r1", Artifact: "pool/r1.tar.zst"},
					{Version: "14.1.1", Platform: "darwin/arm64", ContentHash: "blake3:r2", Artifact: "pool/r2.tar.zst"},
					{Version: "14.2.0", Platform: "darwin/arm64", ContentHash: "blake3:r3", Artifact: "pool/r3.tar.zst"},
				},
				"app": {
					{Version: "1.0.0", ContentHash: "blake3:a1", Artifact: "pool/a1.tar.zst",
						Depends: []schema.Relation{{Name: "rg", Version: "=14.1.1"}}},
				},
				"tools": {
					{Version: "1.0.0", ContentHash: "blake3:t1", Artifact: "pool/t1.tar.zst",
						Recommends: []schema.Relation{{Name: "rg", Version: "=14.1.1"}}},
				},
			},
		}
	}
	const wantMsg = "rg 14.1.1 is published for darwin/arm64, windows/amd64; this host is " + testHost

	expectWrongPlatform := func(err error) *ResolveError {
		GinkgoHelper()
		var rerr *ResolveError
		Expect(errors.As(err, &rerr)).To(BeTrue(), "got %v", err)
		Expect(rerr.Kind).To(Equal(KindWrongPlatform), "got %v", err)
		Expect(rerr.Host).To(Equal(testHost))
		return rerr
	}

	It("Newest names the constrained version's platforms instead of a version mismatch", func() {
		c, err := BuildCatalog(idx(), "native", testHost)
		Expect(err).NotTo(HaveOccurred())
		_, err = c.Newest("rg", "=14.1.1")
		rerr := expectWrongPlatform(err)
		Expect(rerr.Version).To(Equal("14.1.1"))
		Expect(rerr.Platforms).To(Equal([]string{"darwin/arm64", "windows/amd64"}))
		Expect(err).To(MatchError(wantMsg))
	})

	It("Newest names the newest satisfying version when several are foreign-only", func() {
		c, err := BuildCatalog(idx(), "native", testHost)
		Expect(err).NotTo(HaveOccurred())
		_, err = c.Newest("rg", ">=14.1.0")
		rerr := expectWrongPlatform(err)
		Expect(rerr.Version).To(Equal("14.2.0"))
		Expect(rerr.Platforms).To(Equal([]string{"darwin/arm64"}))
	})

	It("Resolve reports a root constraint the same way", func() {
		c, err := BuildCatalog(idx(), "native", testHost)
		Expect(err).NotTo(HaveOccurred())
		_, err = Resolve([]Requirement{{Name: "rg", VersionRange: "=14.1.1"}}, c)
		expectWrongPlatform(err)
		Expect(err).To(MatchError(wantMsg))
	})

	It("Resolve keeps the provenance chain for a transitive constraint", func() {
		c, err := BuildCatalog(idx(), "native", testHost)
		Expect(err).NotTo(HaveOccurred())
		_, err = Resolve([]Requirement{{Name: "app"}}, c)
		expectWrongPlatform(err)
		Expect(err).To(MatchError(wantMsg + " (required via app -> rg)"))
	})

	It("skips a weak dependency on a foreign-only version with the platform reason", func() {
		c, err := BuildCatalog(idx(), "native", testHost)
		Expect(err).NotTo(HaveOccurred())
		res, err := ResolveWithWeak([]Requirement{{Name: "tools"}}, c, WeakOn)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Skipped).To(HaveLen(1))
		Expect(res.Skipped[0].Name).To(Equal("rg"))
		Expect(res.Skipped[0].Reason).To(Equal("not published for this host (" + testHost + ")"))
	})

	It("keeps a version mismatch when no platform publishes a satisfying version", func() {
		c, err := BuildCatalog(idx(), "native", testHost)
		Expect(err).NotTo(HaveOccurred())
		const wantNoVersion = `package "rg" has no version matching ">=15.0.0" (available: 14.0.0)`

		_, err = c.Newest("rg", ">=15.0.0")
		var rerr *ResolveError
		Expect(errors.As(err, &rerr)).To(BeTrue(), "got %v", err)
		Expect(rerr.Kind).To(Equal(KindNoVersion))
		Expect(err).To(MatchError(wantNoVersion))

		_, err = Resolve([]Requirement{{Name: "rg", VersionRange: ">=15.0.0"}}, c)
		Expect(errors.As(err, &rerr)).To(BeTrue(), "got %v", err)
		Expect(rerr.Kind).To(Equal(KindNoVersion))
		Expect(err).To(MatchError(wantNoVersion))
	})
})

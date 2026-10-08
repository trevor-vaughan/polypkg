package resolver

import (
	"fmt"
	"math"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// testHost is the host platform the resolver unit tests build catalogs for.
// It is fixed (not platform.Host()) so filtering assertions do not depend on
// the machine running the tests.
const testHost = "linux/amd64"

func idx() *schema.Index {
	return &schema.Index{
		Schema:  "polypkg.index/v3",
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
			Schema:  "polypkg.index/v3",
			Expires: "2099-01-01T00:00:00Z",
			Packages: map[string][]schema.IndexEntry{
				"foo": {{
					Version: "1.0.0", ContentHash: "blake3:aa", Artifact: "foo.tar.zst",
					Recommends: []schema.Relation{{Name: "foo-extras"}},
					Suggests:   []schema.Relation{{Name: "foo-docs"}},
				}},
			},
		}
		cat, err := BuildCatalog(idx, "native", testHost)
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
		c, err := BuildCatalog(idx(), "native", testHost)
		Expect(err).NotTo(HaveOccurred())
		got := c.candidatesFor(Requirement{Name: "a", VersionRange: ">=1.0.0"})
		Expect(got).To(HaveLen(2))
		Expect(got[0].Version).To(Equal("1.2.0"))
		Expect(got[1].Version).To(Equal("1.0.0"))
	})

	It("resolves candidates through a virtual provider", func() {
		c, err := BuildCatalog(idx(), "native", testHost)
		Expect(err).NotTo(HaveOccurred())
		got := c.candidatesFor(Requirement{Name: "python3"})
		Expect(got).To(HaveLen(1))
		Expect(got[0].Name).To(Equal("py"))
	})

	It("rejects an invalid semver version", func() {
		bad := &schema.Index{Schema: "polypkg.index/v3", Expires: "2099-01-01T00:00:00Z", Packages: map[string][]schema.IndexEntry{
			"x": {{Version: "not-semver", ContentHash: "blake3:x", Artifact: "x.tar.zst"}},
		}}
		_, err := BuildCatalog(bad, "native", testHost)
		Expect(err).To(HaveOccurred())
	})

	It("tags every candidate with the source name", func() {
		c, err := BuildCatalog(&schema.Index{
			Schema:  "polypkg.index/v3",
			Expires: "2099-01-01T00:00:00Z",
			Packages: map[string][]schema.IndexEntry{
				"hello": {{Version: "1.0.0", ContentHash: "blake3:aa", Artifact: "hello-1.0.0.tar.zst"}},
			},
		}, "native", testHost)
		Expect(err).NotTo(HaveOccurred())
		cand, err := c.Newest("hello", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(cand.Source).To(Equal("native"))
	})
})

// slugIdx wraps one entry under key in an otherwise empty index.
func slugIdx(key string, e schema.IndexEntry) *schema.Index {
	return &schema.Index{Schema: "polypkg.index/v3", Expires: "2099-01-01T00:00:00Z", Packages: map[string][]schema.IndexEntry{key: {e}}}
}

var _ = Describe("BuildCatalog name validation", func() {
	plain := func() schema.IndexEntry {
		return schema.IndexEntry{Version: "1.0.0", ContentHash: "blake3:aa", Artifact: "pool/aa.tar.zst"}
	}

	DescribeTable("refuses a package key that is not a package-name slug",
		func(key string) {
			_, err := BuildCatalog(slugIdx(key, plain()), "native", testHost)
			Expect(err).To(MatchError(ContainSubstring("catalog: package name %q is not a valid slug", key)))
			Expect(strings.Count(err.Error(), fmt.Sprintf("%q", key))).To(Equal(1), "the bad key is quoted once: %v", err)
		},
		Entry("parent traversal", "../../etc/x"),
		Entry("path separator", "a/b"),
		Entry("dot", "."),
		Entry("dot-dot", ".."),
		Entry("empty", ""),
		Entry("space", "x y"),
		Entry("non-ASCII letter", "hełło"),
	)

	DescribeTable("refuses a relation name that is not a package-name slug, in every relation field",
		func(field string, set func(*schema.IndexEntry, []schema.Relation)) {
			for _, bad := range []string{"../../etc/x", "a/b", ".."} {
				e := plain()
				set(&e, []schema.Relation{{Name: "ok"}, {Name: bad}})
				_, err := BuildCatalog(slugIdx("app", e), "native", testHost)
				Expect(err).To(MatchError(ContainSubstring("catalog: app 1.0.0: %s: package name %q is not a valid slug", field, bad)))
				Expect(strings.Count(err.Error(), fmt.Sprintf("%q", bad))).To(Equal(1), "the bad name is quoted once: %v", err)
			}
		},
		Entry("depends", "depends", func(e *schema.IndexEntry, r []schema.Relation) { e.Depends = r }),
		Entry("recommends", "recommends", func(e *schema.IndexEntry, r []schema.Relation) { e.Recommends = r }),
		Entry("suggests", "suggests", func(e *schema.IndexEntry, r []schema.Relation) { e.Suggests = r }),
		Entry("provides", "provides", func(e *schema.IndexEntry, r []schema.Relation) { e.Provides = r }),
		Entry("conflicts", "conflicts", func(e *schema.IndexEntry, r []schema.Relation) { e.Conflicts = r }),
		Entry("obsoletes", "obsoletes", func(e *schema.IndexEntry, r []schema.Relation) { e.Obsoletes = r }),
	)

	It("accepts slug names made of letters, digits, dash and underscore", func() {
		e := plain()
		e.Depends = []schema.Relation{{Name: "Lib_2-x"}}
		e.Provides = []schema.Relation{{Name: "python3"}}
		_, err := BuildCatalog(slugIdx("My_pkg-1", e), "native", testHost)
		Expect(err).NotTo(HaveOccurred())
	})
})

var _ = Describe("BuildCatalog host filtering", func() {
	const foreign = "darwin/arm64"
	entry := func(version, plat string) schema.IndexEntry {
		return schema.IndexEntry{Version: version, Platform: plat, ContentHash: "blake3:" + version, Artifact: "pool/" + version + ".tar.zst"}
	}
	build := func(pkgs map[string][]schema.IndexEntry) (*Catalog, error) {
		return BuildCatalog(&schema.Index{Schema: "polypkg.index/v3", Expires: "2099-01-01T00:00:00Z", Packages: pkgs}, "native", testHost)
	}

	It("keeps platform-agnostic and host entries and drops every other platform", func() {
		c, err := build(map[string][]schema.IndexEntry{
			"rg": {
				entry("1.0.0", ""),
				entry("2.0.0", testHost),
				entry("2.0.0", foreign),
				entry("3.0.0", foreign),
				entry("3.0.0", "plan9/mips"),   // well-formed, never this host
				entry("3.0.0", "linux/arm/v7"), // variant segment: consumer grammar accepts, exact match only
			},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(c.Versions("rg")).To(Equal([]string{"2.0.0", "1.0.0"}))
		cand, err := c.Newest("rg", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(cand.Version).To(Equal("2.0.0"))
		Expect(cand.Platform).To(Equal(testHost))
		agnostic, err := c.Newest("rg", "=1.0.0")
		Expect(err).NotTo(HaveOccurred())
		Expect(agnostic.Platform).To(BeEmpty())
	})

	It("records the dropped platforms per version, sorted", func() {
		c, err := build(map[string][]schema.IndexEntry{
			"rg": {
				entry("2.0.0", testHost),
				entry("2.0.0", "windows/amd64"),
				entry("2.0.0", foreign),
				entry("1.0.0", ""),
			},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(c.OtherPlatforms("rg", "2.0.0")).To(Equal([]string{foreign, "windows/amd64"}))
		Expect(c.OtherPlatforms("rg", "1.0.0")).To(BeNil())
		Expect(c.OtherPlatforms("nope", "1.0.0")).To(BeNil())

		// The returned slice is a copy: mutating it must not corrupt the record.
		got := c.OtherPlatforms("rg", "2.0.0")
		got[0] = "mutated/x"
		Expect(c.OtherPlatforms("rg", "2.0.0")).To(Equal([]string{foreign, "windows/amd64"}))
	})

	It("reports the newest version published for any platform when none is for this host", func() {
		c, err := build(map[string][]schema.IndexEntry{
			"rg": {
				entry("14.0.0", "linux/arm64"),
				entry("14.1.1", foreign),
				entry("14.1.1", "windows/amd64"),
			},
			"fd": {entry("1.0.0", testHost), entry("2.0.0", foreign)},
		})
		Expect(err).NotTo(HaveOccurred())

		// A name with no host entry leaves the real-name views entirely.
		Expect(c.Names()).To(Equal([]string{"fd"}))
		Expect(c.Versions("rg")).To(BeEmpty())

		version, platforms, ok := c.NewestUnavailable("rg")
		Expect(ok).To(BeTrue())
		Expect(version).To(Equal("14.1.1"))
		Expect(platforms).To(Equal([]string{foreign, "windows/amd64"}))

		// A name with a host candidate is available, even if a newer version is not.
		_, _, ok = c.NewestUnavailable("fd")
		Expect(ok).To(BeFalse())
		Expect(c.OtherPlatforms("fd", "2.0.0")).To(Equal([]string{foreign}))

		// A name with no entries at all is not "unavailable"; it is unknown.
		_, _, ok = c.NewestUnavailable("nope")
		Expect(ok).To(BeFalse())
	})

	It("unions the platforms of version strings that parse to the same newest semver", func() {
		// "1.0" and "1.0.0" are one semver; neither may hide the other's
		// platforms, and the reported string must not depend on map order:
		// the lexically smaller spelling names the version, as mirror pull's
		// pick does.
		for range 20 {
			c, err := build(map[string][]schema.IndexEntry{
				"rg": {
					entry("0.9.0", "linux/arm64"),
					entry("1.0", foreign),
					entry("1.0", "windows/amd64"),
					entry("1.0.0", "freebsd/amd64"),
				},
			})
			Expect(err).NotTo(HaveOccurred())
			version, platforms, ok := c.NewestUnavailable("rg")
			Expect(ok).To(BeTrue())
			Expect(version).To(Equal("1.0"))
			Expect(platforms).To(Equal([]string{foreign, "freebsd/amd64", "windows/amd64"}))
		}
	})

	DescribeTable("refuses an entry whose platform is not consumer-grammar valid",
		func(plat string) {
			_, err := build(map[string][]schema.IndexEntry{"rg": {entry("1.0.0", plat)}})
			Expect(err).To(MatchError(ContainSubstring("catalog: rg 1.0.0: platform %q is not", plat)))
			Expect(strings.Count(err.Error(), fmt.Sprintf("%q", plat))).To(Equal(1), "the bad platform is quoted once: %v", err)
		},
		Entry("upper case", "Linux/amd64"),
		Entry("one segment", "linux"),
		Entry("four segments", "linux/arm/v7/x"),
		Entry("traversal", "../x"),
		Entry("the reserved claim token", "any"),
	)

	DescribeTable("refuses an index that lists one build of a version twice",
		func(entries []schema.IndexEntry, want string) {
			_, err := build(map[string][]schema.IndexEntry{"rg": entries})
			Expect(err).To(MatchError(want))
		},
		Entry("a host platform twice",
			[]schema.IndexEntry{entry("1.0.0", testHost), entry("1.0.0", testHost)},
			`catalog: rg "1.0.0" for platform "`+testHost+`" is listed more than once`),
		Entry("a foreign platform twice",
			[]schema.IndexEntry{entry("1.0.0", testHost), entry("1.0.0", foreign), entry("1.0.0", foreign)},
			`catalog: rg "1.0.0" for platform "`+foreign+`" is listed more than once`),
		Entry("the platform-agnostic build twice",
			[]schema.IndexEntry{entry("1.0.0", ""), entry("1.0.0", "")},
			`catalog: rg "1.0.0" for platform "any" is listed more than once`),
		Entry("semver-equal spellings for one platform",
			[]schema.IndexEntry{entry("1.0", testHost), entry("1.0.0", testHost)},
			`catalog: rg "1.0.0" for platform "`+testHost+`" is listed more than once (also listed as "1.0")`),
		Entry("spellings that differ only in build metadata, platform-agnostic",
			[]schema.IndexEntry{entry("1.0.0+a", ""), entry("1.0.0+b", "")},
			`catalog: rg "1.0.0+b" for platform "any" is listed more than once (also listed as "1.0.0+a")`),
	)

	DescribeTable("refuses names or versions that differ only in letter case",
		func(packages map[string][]schema.IndexEntry, want string) {
			_, err := build(packages)
			Expect(err).To(MatchError(ContainSubstring(want)))
			Expect(err.Error()).To(HavePrefix("catalog: "))
		},
		Entry("two names",
			map[string][]schema.IndexEntry{"rg": {entry("1.0.0", "")}, "RG": {entry("1.0.0", "")}},
			`package names "RG" and "rg" differ only in letter case`),
		Entry("two versions of one name",
			map[string][]schema.IndexEntry{"rg": {entry("1.0.0-rc1", testHost), entry("1.0.0-RC1", foreign)}},
			`package "rg" versions "1.0.0-rc1" and "1.0.0-RC1" differ only in letter case`),
	)

	DescribeTable("refuses a version with both a platform-agnostic entry and platform entries",
		func(entries []schema.IndexEntry, plat string) {
			_, err := build(map[string][]schema.IndexEntry{"rg": entries})
			Expect(err).To(MatchError(`catalog: rg "1.0.0" has both a platform-agnostic entry and a "` + plat + `" entry`))
		},
		Entry("agnostic first, host platform second", []schema.IndexEntry{entry("1.0.0", ""), entry("1.0.0", testHost)}, testHost),
		Entry("host platform first, agnostic second", []schema.IndexEntry{entry("1.0.0", testHost), entry("1.0.0", "")}, testHost),
		Entry("agnostic and a foreign platform", []schema.IndexEntry{entry("1.0.0", ""), entry("1.0.0", foreign)}, foreign),
		Entry("a foreign platform and agnostic", []schema.IndexEntry{entry("1.0.0", foreign), entry("1.0.0", "")}, foreign),
	)

	It("refuses an agnostic entry and a platform entry whose versions are semver-equal", func() {
		_, err := build(map[string][]schema.IndexEntry{"rg": {entry("1.0", ""), entry("1.0.0", testHost)}})
		Expect(err).To(MatchError(`catalog: rg "1.0.0" has both a platform-agnostic entry and a "` + testHost + `" entry (also listed as "1.0")`))
	})

	It("accepts semver-equal spellings for distinct platforms", func() {
		_, err := build(map[string][]schema.IndexEntry{"rg": {entry("1.0", testHost), entry("1.0.0", foreign)}})
		Expect(err).NotTo(HaveOccurred())
	})

	It("admits many versions without comparing every pair", func() {
		// Quadrupling the input quadruples a keyed check's cost and
		// multiplies a pairwise one's by sixteen. Comparing two sizes timed
		// on the same machine cancels the uniform slowdown (-race, coverage,
		// a shared runner) that made an absolute time bound flaky.
		versions := func(n int) []schema.IndexEntry {
			entries := make([]schema.IndexEntry, 0, n+1)
			for i := range n {
				entries = append(entries, entry(fmt.Sprintf("1.%d.0", i), testHost))
			}
			return entries
		}
		// bestOf3 takes the fastest of three runs to shed GC and scheduler noise.
		bestOf3 := func(n int) time.Duration {
			entries := versions(n)
			best := time.Duration(math.MaxInt64)
			for range 3 {
				start := time.Now()
				_, err := build(map[string][]schema.IndexEntry{"rg": entries})
				Expect(err).NotTo(HaveOccurred())
				best = min(best, time.Since(start))
			}
			return best
		}
		small, large := bestOf3(10_000), bestOf3(40_000)
		Expect(float64(large)/float64(small)).To(BeNumerically("<", 10),
			"40k entries took %s against %s for 10k: growth is superlinear", large, small)

		_, err := build(map[string][]schema.IndexEntry{"rg": append(versions(1_000), entry("1.0", testHost))})
		Expect(err).To(MatchError(`catalog: rg "1.0" for platform "` + testHost + `" is listed more than once (also listed as "1.0.0")`))
	})

	It("validates a foreign-platform entry before dropping it", func() {
		bad := entry("1.0.0", foreign)
		bad.Depends = []schema.Relation{{Name: "../../etc/x"}}
		_, err := build(map[string][]schema.IndexEntry{"rg": {entry("1.0.0", testHost), bad}})
		Expect(err).To(MatchError(ContainSubstring(`catalog: rg 1.0.0: depends: package name "../../etc/x" is not a valid slug`)))
	})
})

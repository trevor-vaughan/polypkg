package cli

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/platform"
	"github.com/trevor-vaughan/polypkg/internal/resolver"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("isPinned", func() {
	DescribeTable("classifies a profile constraint as pinned (=X) or range-y",
		func(constraint string, want bool) {
			Expect(isPinned(constraint)).To(Equal(want))
		},
		// Only an "="-prefixed exact constraint is a pin.
		Entry("exact pin", "=1.0.0", true),
		// Everything range-y is not a pin. Each is verified valid Masterminds
		// semver syntax in svcheck before inclusion (1.x included: it is valid).
		Entry(">= floor", ">=1.0.0", false),
		Entry("caret range", "^1.0", false),
		Entry("tilde range", "~1.2", false),
		Entry("wildcard", "*", false),
		Entry("x-range", "1.x", false),
		Entry("empty constraint", "", false),
	)
})

// stubCatalog builds a real resolver.Catalog from a name->versions map so the
// held-back computation runs against the same Newest() the production path uses.
func stubCatalog(pkgs map[string][]string) *resolver.Catalog {
	idx := &schema.Index{
		Schema:   "polypkg.index/v3",
		Expires:  "2099-01-01T00:00:00Z",
		Packages: map[string][]schema.IndexEntry{},
	}
	for name, versions := range pkgs {
		for _, v := range versions {
			idx.Packages[name] = append(idx.Packages[name], schema.IndexEntry{
				Version:     v,
				ContentHash: "blake3:" + name + v,
				Artifact:    name + "-" + v + ".tar.zst",
			})
		}
	}
	c, err := resolver.BuildCatalog(idx, "native", platform.Host())
	Expect(err).NotTo(HaveOccurred())
	return c
}

var _ = Describe("computeHeldBack", func() {
	It("reports a pinned package whose catalog newest exceeds the pin", func() {
		cat := stubCatalog(map[string][]string{"hello": {"1.0.0", "1.1.0"}})
		entries, err := computeHeldBack(cat, map[string]string{"hello": "=1.0.0"})
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(HaveLen(1))
		Expect(entries[0]).To(Equal(heldBackEntry{Name: "hello", Pinned: "=1.0.0", Available: "1.1.0"}))
	})

	It("omits a pinned package already at the newest version", func() {
		cat := stubCatalog(map[string][]string{"hello": {"1.0.0", "1.1.0"}})
		entries, err := computeHeldBack(cat, map[string]string{"hello": "=1.1.0"})
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(BeEmpty())
	})

	It("ignores range-constrained packages (they re-resolve on apply)", func() {
		cat := stubCatalog(map[string][]string{"hello": {"1.0.0", "1.1.0"}})
		entries, err := computeHeldBack(cat, map[string]string{"hello": ">=1.0.0"})
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(BeEmpty())
	})

	It("returns entries sorted by name for deterministic output", func() {
		cat := stubCatalog(map[string][]string{
			"beta":  {"1.0.0", "2.0.0"},
			"alpha": {"1.0.0", "2.0.0"},
		})
		entries, err := computeHeldBack(cat, map[string]string{
			"beta":  "=1.0.0",
			"alpha": "=1.0.0",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(entries).To(HaveLen(2))
		Expect(entries[0].Name).To(Equal("alpha"))
		Expect(entries[1].Name).To(Equal("beta"))
	})
})

var _ = Describe("decideUpgrade", func() {
	It("bumps a pin to =<newest> when a newer version exists", func() {
		cat := stubCatalog(map[string][]string{"hello": {"1.0.0", "1.1.0"}})
		d, err := decideUpgrade(cat, "hello", "=1.0.0")
		Expect(err).NotTo(HaveOccurred())
		Expect(d.Action).To(Equal(upgradeBump))
		Expect(d.NewConstraint).To(Equal("=1.1.0"))
		Expect(d.Available).To(Equal("1.1.0"))
	})

	It("keeps a pin already at the newest version (no edit)", func() {
		cat := stubCatalog(map[string][]string{"hello": {"1.0.0", "1.1.0"}})
		d, err := decideUpgrade(cat, "hello", "=1.1.0")
		Expect(err).NotTo(HaveOccurred())
		Expect(d.Action).To(Equal(upgradeAtNewest))
		Expect(d.NewConstraint).To(BeEmpty())
		Expect(d.Available).To(Equal("1.1.0"))
	})

	It("leaves a range constraint untouched but flags it for re-resolution", func() {
		cat := stubCatalog(map[string][]string{"hello": {"1.0.0", "1.1.0"}})
		d, err := decideUpgrade(cat, "hello", ">=1.0.0")
		Expect(err).NotTo(HaveOccurred())
		Expect(d.Action).To(Equal(upgradeRange))
		Expect(d.NewConstraint).To(BeEmpty())
		Expect(d.Constraint).To(Equal(">=1.0.0"))
	})

	It("returns a typed resolve error for a name absent from the catalog", func() {
		cat := stubCatalog(map[string][]string{"hello": {"1.0.0"}})
		_, err := decideUpgrade(cat, "ghost", "=1.0.0")
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("renderHeldBack", func() {
	It("uses a semicolon (house style) not an em dash and names the bump command", func() {
		line := heldBackLine(heldBackEntry{Name: "hello", Pinned: "=1.0.0", Available: "1.1.0"})
		Expect(line).To(Equal("held back: hello =1.0.0 (1.1.0 available); run `polypkg upgrade hello` to bump the pin"))
		Expect(line).NotTo(ContainSubstring("—"))
	})
})

var _ = Describe("prerelease policy", func() {
	// Masterminds semver: range constraints like >=1.0.0 exclude prereleases by
	// default. However the empty-constraint path in constraintAllows is
	// short-circuited to always-true, so Newest(name,"") returns a prerelease if
	// it sorts highest. We therefore filter in the CLI layer when the current pin
	// is stable.

	Describe("computeHeldBack", func() {
		It("stable pin held back to stable, not prerelease, when catalog has both", func() {
			// Catalog: 1.0.0 (stable), 1.1.0 (stable), 2.0.0-rc1 (prerelease).
			// Pin =1.0.0 (stable) → held back reports 1.1.0, NOT 2.0.0-rc1.
			cat := stubCatalog(map[string][]string{"hello": {"1.0.0", "1.1.0", "2.0.0-rc1"}})
			entries, err := computeHeldBack(cat, map[string]string{"hello": "=1.0.0"})
			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(HaveLen(1))
			Expect(entries[0].Available).To(Equal("1.1.0"), "stable pin must not be held-back to a prerelease")
		})

		It("stable pin at the newest stable is not held back even if a prerelease is higher", func() {
			// Catalog: 1.0.0, 1.1.0, 2.0.0-rc1. Pin =1.1.0 → no held-back entry.
			cat := stubCatalog(map[string][]string{"hello": {"1.0.0", "1.1.0", "2.0.0-rc1"}})
			entries, err := computeHeldBack(cat, map[string]string{"hello": "=1.1.0"})
			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(BeEmpty(), "stable pin at newest stable must not be held back")
		})

		It("prerelease pin is held back to a newer prerelease (opt-in track)", func() {
			// Catalog: 2.0.0-rc1, 2.0.0-rc2. Pin =2.0.0-rc1 → held back to rc2.
			cat := stubCatalog(map[string][]string{"hello": {"2.0.0-rc1", "2.0.0-rc2"}})
			entries, err := computeHeldBack(cat, map[string]string{"hello": "=2.0.0-rc1"})
			Expect(err).NotTo(HaveOccurred())
			Expect(entries).To(HaveLen(1))
			Expect(entries[0].Available).To(Equal("2.0.0-rc2"), "prerelease pin must be eligible for newer prerelease")
		})
	})

	Describe("decideUpgrade", func() {
		It("stable pin bumps to newest stable, not to prerelease", func() {
			// Catalog: 1.0.0, 1.1.0, 2.0.0-rc1. Pin =1.0.0 → bumps to =1.1.0.
			cat := stubCatalog(map[string][]string{"hello": {"1.0.0", "1.1.0", "2.0.0-rc1"}})
			d, err := decideUpgrade(cat, "hello", "=1.0.0")
			Expect(err).NotTo(HaveOccurred())
			Expect(d.Action).To(Equal(upgradeBump))
			Expect(d.NewConstraint).To(Equal("=1.1.0"), "stable pin must bump to stable, not prerelease")
		})

		It("stable pin already at newest stable reports at-newest even though prerelease is higher", func() {
			// Catalog: 1.0.0, 1.1.0, 2.0.0-rc1. Pin =1.1.0 → at-newest.
			cat := stubCatalog(map[string][]string{"hello": {"1.0.0", "1.1.0", "2.0.0-rc1"}})
			d, err := decideUpgrade(cat, "hello", "=1.1.0")
			Expect(err).NotTo(HaveOccurred())
			Expect(d.Action).To(Equal(upgradeAtNewest))
			Expect(d.Available).To(Equal("1.1.0"), "available must reflect the newest stable, not the prerelease")
		})

		It("prerelease pin bumps to newer prerelease (opt-in track)", func() {
			// Catalog: 2.0.0-rc1, 2.0.0-rc2. Pin =2.0.0-rc1 → bumps to =2.0.0-rc2.
			cat := stubCatalog(map[string][]string{"hello": {"2.0.0-rc1", "2.0.0-rc2"}})
			d, err := decideUpgrade(cat, "hello", "=2.0.0-rc1")
			Expect(err).NotTo(HaveOccurred())
			Expect(d.Action).To(Equal(upgradeBump))
			Expect(d.NewConstraint).To(Equal("=2.0.0-rc2"))
		})
	})
})

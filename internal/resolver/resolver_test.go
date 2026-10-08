package resolver

import (
	"errors"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func build(pkgs map[string][]schema.IndexEntry) *Catalog {
	GinkgoHelper()
	c, err := BuildCatalog(&schema.Index{Schema: "polypkg.index/v3", Expires: "2099-01-01T00:00:00Z", Packages: pkgs}, "native", testHost)
	Expect(err).NotTo(HaveOccurred())
	return c
}

func names(rs []Resolved) map[string]string {
	m := map[string]string{}
	for _, r := range rs {
		m[r.Name] = r.Version
	}
	return m
}

var _ = Describe("Resolve provenance fields", func() {
	It("returns Resolved with Weak=false and nil RecommendedBy for hard installs", func() {
		idx := &schema.Index{Schema: "polypkg.index/v3", Expires: "2099-01-01T00:00:00Z", Packages: map[string][]schema.IndexEntry{
			"foo": {{Version: "1.0.0", ContentHash: "blake3:aa", Artifact: "foo"}},
		}}
		cat, err := BuildCatalog(idx, "native", testHost)
		Expect(err).NotTo(HaveOccurred())
		out, err := Resolve([]Requirement{{Name: "foo"}}, cat)
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(HaveLen(1))
		Expect(out[0].Weak).To(BeFalse())
		Expect(out[0].RecommendedBy).To(BeNil())
	})
})

var _ = Describe("Resolve", func() {
	It("carries the catalog source into each resolved entry", func() {
		idx := &schema.Index{Schema: "polypkg.index/v3", Expires: "2099-01-01T00:00:00Z", Packages: map[string][]schema.IndexEntry{
			"hello": {{Version: "1.0.0", ContentHash: "blake3:aa", Artifact: "hello-1.0.0.tar.zst"}},
		}}
		cat, err := BuildCatalog(idx, "native", testHost)
		Expect(err).NotTo(HaveOccurred())
		got, err := Resolve([]Requirement{{Name: "hello", VersionRange: "=1.0.0"}}, cat)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HaveLen(1))
		Expect(got[0].Source).To(Equal("native"))
	})

	It("picks the highest version satisfying the range", func() {
		c := build(map[string][]schema.IndexEntry{
			"a": {
				{Version: "1.0.0", ContentHash: "blake3:1", Artifact: "a-1.0.0.tar.zst"},
				{Version: "1.3.0", ContentHash: "blake3:2", Artifact: "a-1.3.0.tar.zst"},
			},
		})
		got, err := Resolve([]Requirement{{Name: "a", VersionRange: "^1.0"}}, c)
		Expect(err).NotTo(HaveOccurred())
		Expect(names(got)["a"]).To(Equal("1.3.0"))
	})

	It("resolves transitive depends", func() {
		c := build(map[string][]schema.IndexEntry{
			"app": {{Version: "1.0.0", ContentHash: "blake3:1", Artifact: "app.tar.zst",
				Depends: []schema.Relation{{Name: "lib", Version: "^2.0"}}}},
			"lib": {{Version: "2.4.0", ContentHash: "blake3:2", Artifact: "lib.tar.zst"}},
		})
		got, err := Resolve([]Requirement{{Name: "app"}}, c)
		Expect(err).NotTo(HaveOccurred())
		n := names(got)
		Expect(n["app"]).To(Equal("1.0.0"))
		Expect(n["lib"]).To(Equal("2.4.0"))
	})

	It("converges a diamond on a shared base", func() {
		c := build(map[string][]schema.IndexEntry{
			"top": {{Version: "1.0.0", ContentHash: "h", Artifact: "top.tar.zst",
				Depends: []schema.Relation{{Name: "left"}, {Name: "right"}}}},
			"left":  {{Version: "1.0.0", ContentHash: "h", Artifact: "l.tar.zst", Depends: []schema.Relation{{Name: "base", Version: ">=1.2"}}}},
			"right": {{Version: "1.0.0", ContentHash: "h", Artifact: "r.tar.zst", Depends: []schema.Relation{{Name: "base", Version: "<2.0"}}}},
			"base":  {{Version: "1.5.0", ContentHash: "h", Artifact: "b.tar.zst"}},
		})
		got, err := Resolve([]Requirement{{Name: "top"}}, c)
		Expect(err).NotTo(HaveOccurred())
		Expect(names(got)["base"]).To(Equal("1.5.0"))
	})

	It("backtracks when a downstream constraint rules out the top candidate", func() {
		c := build(map[string][]schema.IndexEntry{
			"app": {{Version: "1.0.0", ContentHash: "h", Artifact: "app.tar.zst", Depends: []schema.Relation{{Name: "lib"}}}},
			"lib": {
				{Version: "2.0.0", ContentHash: "h", Artifact: "lib2.tar.zst", Depends: []schema.Relation{{Name: "base", Version: ">=2.0"}}},
				{Version: "1.0.0", ContentHash: "h", Artifact: "lib1.tar.zst", Depends: []schema.Relation{{Name: "base", Version: "<2.0"}}},
			},
			"base": {{Version: "1.9.0", ContentHash: "h", Artifact: "base.tar.zst"}},
		})
		got, err := Resolve([]Requirement{{Name: "app"}}, c)
		Expect(err).NotTo(HaveOccurred())
		n := names(got)
		Expect(n["lib"]).To(Equal("1.0.0"))
		Expect(n["base"]).To(Equal("1.9.0"))
	})

	It("satisfies a virtual provider without leaking its name", func() {
		c := build(map[string][]schema.IndexEntry{
			"app": {{Version: "1.0.0", ContentHash: "h", Artifact: "app.tar.zst", Depends: []schema.Relation{{Name: "python3"}}}},
			"py":  {{Version: "3.11.0", ContentHash: "h", Artifact: "py.tar.zst", Provides: []schema.Relation{{Name: "python3"}}}},
		})
		got, err := Resolve([]Requirement{{Name: "app"}}, c)
		Expect(err).NotTo(HaveOccurred())
		n := names(got)
		Expect(n["py"]).To(Equal("3.11.0"))
		Expect(n).NotTo(HaveKey("python3"))
	})

	It("reports an explicit Conflicts clash as a ResolveError", func() {
		c := build(map[string][]schema.IndexEntry{
			"a": {{Version: "1.0.0", ContentHash: "h", Artifact: "a.tar.zst", Conflicts: []schema.Relation{{Name: "b"}}}},
			"b": {{Version: "1.0.0", ContentHash: "h", Artifact: "b.tar.zst"}},
		})
		_, err := Resolve([]Requirement{{Name: "a"}, {Name: "b"}}, c)
		Expect(err).To(HaveOccurred())
		var rerr *ResolveError
		Expect(errors.As(err, &rerr)).To(BeTrue())
	})

	// Obsoletes is enforced as a mutual conflict: requiring both an obsoleter
	// and the package it obsoletes is rejected (supersession/auto-drop is
	// deferred).
	It("treats Obsoletes as a mutual conflict", func() {
		c := build(map[string][]schema.IndexEntry{
			"ng":  {{Version: "2.0.0", ContentHash: "h", Artifact: "ng.tar.zst", Obsoletes: []schema.Relation{{Name: "old"}}}},
			"old": {{Version: "1.0.0", ContentHash: "h", Artifact: "old.tar.zst"}},
		})
		_, err := Resolve([]Requirement{{Name: "ng"}, {Name: "old"}}, c)
		Expect(err).To(HaveOccurred())
	})

	It("surfaces the missing requirement when no candidate exists", func() {
		c := build(map[string][]schema.IndexEntry{
			"a": {{Version: "1.0.0", ContentHash: "h", Artifact: "a.tar.zst"}},
		})
		_, err := Resolve([]Requirement{{Name: "a", VersionRange: ">=9.0"}}, c)
		Expect(err).To(HaveOccurred())
		var rerr *ResolveError
		Expect(errors.As(err, &rerr)).To(BeTrue())
		Expect(rerr.Requirement.Name).To(Equal("a"))
	})

	It("resolves a satisfiable dependency cycle", func() {
		c := build(map[string][]schema.IndexEntry{
			"x": {{Version: "1.0.0", ContentHash: "h", Artifact: "x.tar.zst", Depends: []schema.Relation{{Name: "y"}}}},
			"y": {{Version: "1.0.0", ContentHash: "h", Artifact: "y.tar.zst", Depends: []schema.Relation{{Name: "x"}}}},
		})
		got, err := Resolve([]Requirement{{Name: "x"}}, c)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HaveLen(2))
	})

	It("produces a deterministic result across repeated runs", func() {
		c := build(map[string][]schema.IndexEntry{
			"app": {{Version: "1.0.0", ContentHash: "h", Artifact: "app.tar.zst", Depends: []schema.Relation{{Name: "x"}, {Name: "y"}}}},
			"x":   {{Version: "1.0.0", ContentHash: "h", Artifact: "x.tar.zst"}},
			"y":   {{Version: "1.0.0", ContentHash: "h", Artifact: "y.tar.zst"}},
		})
		first, err := Resolve([]Requirement{{Name: "app"}}, c)
		Expect(err).NotTo(HaveOccurred())
		for range 20 {
			again, err := Resolve([]Requirement{{Name: "app"}}, c)
			Expect(err).NotTo(HaveOccurred())
			Expect(again).To(Equal(first))
		}
	})

	It("enforces the resolver budget", func() {
		c := build(map[string][]schema.IndexEntry{
			"a": {{Version: "1.0.0", ContentHash: "h", Artifact: "a.tar.zst"}},
		})
		_, err := resolveWithBudget([]Requirement{{Name: "a"}}, c, 0)
		Expect(err).To(HaveOccurred())
		var rerr *ResolveError
		Expect(errors.As(err, &rerr)).To(BeTrue())
		Expect(rerr.Kind).To(Equal(KindTooComplex))
	})

	// Builds a profile that naive backtracking explores in 2^N branches: root
	// depends on p0..pN, each pi has a 2.0.0 variant (needs base >=2.0) and a
	// 1.0.0 variant (needs base <2.0), and base exists only at 1.5.0. The
	// unique solution is every pi=1.0.0 + base 1.5.0. Forward-checking must
	// prune every pi=2.0.0 immediately (base >=2.0 has an empty catalog
	// domain), collapsing the search to linear and resolving without tripping
	// the budget.
	It("prunes pigeonhole branches via forward checking", func() {
		const n = 20
		pkgs := map[string][]schema.IndexEntry{
			"base": {{Version: "1.5.0", ContentHash: "h", Artifact: "base.tar.zst"}},
		}
		roots := make([]Requirement, 0, n)
		for i := range n {
			name := fmt.Sprintf("p%d", i)
			pkgs[name] = []schema.IndexEntry{
				{Version: "2.0.0", ContentHash: "h", Artifact: name + "-2.tar.zst",
					Depends: []schema.Relation{{Name: "base", Version: ">=2.0"}}},
				{Version: "1.0.0", ContentHash: "h", Artifact: name + "-1.tar.zst",
					Depends: []schema.Relation{{Name: "base", Version: "<2.0"}}},
			}
			roots = append(roots, Requirement{Name: name})
		}
		c := build(pkgs)
		got, err := Resolve(roots, c)
		Expect(err).NotTo(HaveOccurred())
		gotNames := names(got)
		Expect(gotNames["base"]).To(Equal("1.5.0"))
		for i := range n {
			name := fmt.Sprintf("p%d", i)
			Expect(gotNames[name]).To(Equal("1.0.0"))
		}
	})

	// Resolves a long satisfiable chain a0 -> a1 -> ... that, before bounding
	// per-step work, took O(N^2) time (clone + full-map scans per decision).
	// With the undo-log and O(1) predicates this completes near-instantly; the
	// test simply not timing out is the implicit speed assertion.
	It("resolves a deep linear chain without quadratic blowup", func() {
		const n = 5000
		pkgs := make(map[string][]schema.IndexEntry, n)
		for i := range n {
			name := fmt.Sprintf("a%d", i)
			var deps []schema.Relation
			if i+1 < n {
				deps = []schema.Relation{{Name: fmt.Sprintf("a%d", i+1)}}
			}
			pkgs[name] = []schema.IndexEntry{
				{Version: "1.0.0", ContentHash: "h", Artifact: name + ".tar.zst", Depends: deps},
			}
		}
		c := build(pkgs)
		got, err := Resolve([]Requirement{{Name: "a0"}}, c)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(HaveLen(n))
	})

	// Runs the same multi-conflict failing resolve many times and asserts the
	// error string never varies. Several selected packages clash with the final
	// candidate; conflictReason must report a stable representative (smallest
	// by Name, Version) regardless of map iteration order.
	It("produces a deterministic multi-conflict error string", func() {
		c := build(map[string][]schema.IndexEntry{
			"x": {{Version: "1.0.0", ContentHash: "h", Artifact: "x.tar.zst"}},
			"y": {{Version: "1.0.0", ContentHash: "h", Artifact: "y.tar.zst"}},
			"z": {{Version: "1.0.0", ContentHash: "h", Artifact: "z.tar.zst"}},
			// c is required last and conflicts with all of x, y, z.
			"c": {{Version: "1.0.0", ContentHash: "h", Artifact: "c.tar.zst",
				Conflicts: []schema.Relation{{Name: "x"}, {Name: "y"}, {Name: "z"}}}},
		})
		roots := []Requirement{{Name: "x"}, {Name: "y"}, {Name: "z"}, {Name: "c"}}
		_, err := Resolve(roots, c)
		Expect(err).To(HaveOccurred())
		want := err.Error()
		for range 50 {
			_, err := Resolve(roots, c)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal(want))
		}
	})
})

package action

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// configFixture builds a staging scope with a package source file and returns
// the scope plus the absolute dest path. liveRoot/priorGenDir are "" unless a
// prior generation is simulated via simulatePriorGen.
func configFixture(srcContent []byte) (Scope, string, string) {
	dir := GinkgoT().TempDir()
	pkgRoot := filepath.Join(dir, "store", "hello", "content")
	Expect(os.MkdirAll(pkgRoot, 0o755)).To(Succeed())
	src := filepath.Join(pkgRoot, "app.conf")
	Expect(os.WriteFile(src, srcContent, 0o644)).To(Succeed())
	scope := Scope{
		ActiveRoot:  filepath.Join(dir, "active"),
		PackageName: "hello",
		PackageRoot: pkgRoot,
	}
	dest := filepath.Join(scope.ActiveRoot, "hello", "etc", "app.conf")
	return scope, src, dest
}

// simulatePriorGen creates a prior generation's active tree with the given live
// content at the package-relative path, plus a config-base snapshot for baseHash,
// and returns liveRoot and priorGenDir for wiring into a Scope.
func simulatePriorGen(scope Scope, dest string, liveContent []byte, baseHash string, baseContent []byte) (liveRoot, priorGenDir string) {
	root := GinkgoT().TempDir()
	priorGenDir = filepath.Join(root, "generations", "1")
	liveRoot = filepath.Join(priorGenDir, "active")
	rel, ok := relWithin(filepath.Join(scope.ActiveRoot, scope.PackageName), dest)
	Expect(ok).To(BeTrue())
	livePath := filepath.Join(liveRoot, scope.PackageName, rel)
	Expect(os.MkdirAll(filepath.Dir(livePath), 0o755)).To(Succeed())
	Expect(os.WriteFile(livePath, liveContent, 0o644)).To(Succeed())
	if baseHash != "" {
		basePath := filepath.Join(priorGenDir, schema.ConfigBaseRelPath(baseHash))
		Expect(os.MkdirAll(filepath.Dir(basePath), 0o755)).To(Succeed())
		Expect(os.WriteFile(basePath, baseContent, 0o644)).To(Succeed())
	}
	return liveRoot, priorGenDir
}

var _ = Describe("Config first install", func() {
	DescribeTable("writes incoming and sets ContentHash == SourceHash for every policy",
		func(policy string) {
			scope, src, dest := configFixture([]byte("incoming\n"))
			inv := Invocation{Action: "config", PackageName: "hello", Phase: PhasePostPlace,
				Params: map[string]any{"src": src, "dest": dest, "policy": policy}}
			res, err := Config(inv, scope)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Outcome).To(Equal("ok"))
			got, _ := os.ReadFile(dest)
			Expect(string(got)).To(Equal("incoming\n"))
			Expect(res.Expected.ContentHash).To(Equal(blake3Hex([]byte("incoming\n"))))
			Expect(res.Expected.SourceHash).To(Equal(blake3Hex([]byte("incoming\n"))))
			Expect(res.SourceBytes).To(Equal([]byte("incoming\n")))
		},
		Entry("replace", "replace"),
		Entry("preserve", "preserve"),
		Entry("preserve_warn", "preserve_warn"),
		Entry("three_way_merge", "three_way_merge"),
	)

	It("defaults to preserve policy with notify_preserve drift", func() {
		scope, src, dest := configFixture([]byte("x\n"))
		inv := Invocation{Action: "config", PackageName: "hello", Phase: PhasePostPlace,
			Params: map[string]any{"src": src, "dest": dest}}
		res, err := Config(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.DriftPolicy).To(Equal("notify_preserve"))
	})

	It("uses notify_heal drift for replace policy", func() {
		scope, src, dest := configFixture([]byte("x\n"))
		inv := Invocation{Action: "config", PackageName: "hello", Phase: PhasePostPlace,
			Params: map[string]any{"src": src, "dest": dest, "policy": "replace"}}
		res, err := Config(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.DriftPolicy).To(Equal("notify_heal"))
	})

	It("rejects an invalid policy", func() {
		scope, src, dest := configFixture([]byte("x\n"))
		inv := Invocation{Action: "config", PackageName: "hello", Phase: PhasePostPlace,
			Params: map[string]any{"src": src, "dest": dest, "policy": "bogus"}}
		_, err := Config(inv, scope)
		Expect(err).To(MatchError(ContainSubstring("invalid policy")))
	})

	It("rejects src outside the package files", func() {
		scope, _, dest := configFixture([]byte("x\n"))
		inv := Invocation{Action: "config", PackageName: "hello", Phase: PhasePostPlace,
			Params: map[string]any{"src": "/etc/shadow", "dest": dest, "policy": "replace"}}
		_, err := Config(inv, scope)
		Expect(err).To(MatchError(ContainSubstring("outside")))
	})

	It("rejects dest outside the package scope", func() {
		scope, src, _ := configFixture([]byte("x\n"))
		inv := Invocation{Action: "config", PackageName: "hello", Phase: PhasePostPlace,
			Params: map[string]any{"src": src, "dest": filepath.Join(scope.ActiveRoot, "other", "f"), "policy": "replace"}}
		_, err := Config(inv, scope)
		Expect(err).To(MatchError(ContainSubstring("outside")))
	})
})

var _ = Describe("Config preserve modes", func() {
	// preserveInv wires a prior gen and marks dest as drifted via PreserveActions.
	preserveInv := func(scope *Scope, src, dest, policy string, live, base []byte, baseHash string) Invocation {
		liveRoot, priorGenDir := simulatePriorGen(*scope, dest, live, baseHash, base)
		scope.LiveRoot, scope.PriorGenDir = liveRoot, priorGenDir
		ownPath := filepath.ToSlash(mustRel(scope.ActiveRoot, dest))
		return Invocation{Action: "config", PackageName: "hello", Phase: PhasePostPlace,
			Params:          map[string]any{"src": src, "dest": dest, "policy": policy},
			PreserveActions: map[string]string{ownPath: blake3Hex(live)}}
	}

	It("preserve keeps live bytes and reports ContentHash != SourceHash", func() {
		scope, src, dest := configFixture([]byte("incoming\n"))
		inv := preserveInv(&scope, src, dest, "preserve", []byte("local edit\n"), nil, "")
		res, err := Config(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		got, _ := os.ReadFile(dest)
		Expect(string(got)).To(Equal("local edit\n"))
		Expect(res.Expected.ContentHash).To(Equal(blake3Hex([]byte("local edit\n"))))
		Expect(res.Expected.SourceHash).To(Equal(blake3Hex([]byte("incoming\n"))))
		Expect(res.Expected.ContentHash).NotTo(Equal(res.Expected.SourceHash))
	})

	It("preserve_warn keeps live, writes <dest>.new, and warns", func() {
		scope, src, dest := configFixture([]byte("incoming\n"))
		inv := preserveInv(&scope, src, dest, "preserve_warn", []byte("local\n"), nil, "")
		res, err := Config(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		got, _ := os.ReadFile(dest)
		Expect(string(got)).To(Equal("local\n"))
		dotNew, _ := os.ReadFile(dest + ".new")
		Expect(string(dotNew)).To(Equal("incoming\n"))
		Expect(res.Warnings).To(HaveLen(1))
		Expect(res.Warnings[0].Kind).To(Equal("config_preserve_warn"))
	})

	It("three_way_merge merges cleanly when changes do not overlap", func() {
		base := []byte("a\nb\nc\n")
		scope, src, dest := configFixture([]byte("a\nb\nc\nINCOMING\n"))
		live := []byte("LIVE\na\nb\nc\n")
		baseHash := blake3Hex(base)
		inv := preserveInv(&scope, src, dest, "three_way_merge", live, base, baseHash)
		inv.PriorEntry = &schema.OwnershipEntry{Expected: schema.Expected{SourceHash: baseHash}}
		res, err := Config(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		got, _ := os.ReadFile(dest)
		Expect(string(got)).To(Equal("LIVE\na\nb\nc\nINCOMING\n"))
		Expect(res.Warnings).To(BeEmpty())
	})

	It("three_way_merge emits conflict markers and warns on overlap", func() {
		base := []byte("a\nb\nc\n")
		scope, src, dest := configFixture([]byte("a\nINCOMING\nc\n"))
		live := []byte("a\nLIVE\nc\n")
		baseHash := blake3Hex(base)
		inv := preserveInv(&scope, src, dest, "three_way_merge", live, base, baseHash)
		inv.PriorEntry = &schema.OwnershipEntry{Expected: schema.Expected{SourceHash: baseHash}}
		res, err := Config(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		got, _ := os.ReadFile(dest)
		Expect(string(got)).To(ContainSubstring("<<<<<<< LIVE"))
		Expect(res.Warnings[0].Kind).To(Equal("three_way_merge_conflicts"))
		Expect(res.Warnings[0].Fields["marker_count"]).To(Equal(1))
	})

	It("three_way_merge falls back to preserve_warn when base is missing", func() {
		scope, src, dest := configFixture([]byte("incoming\n"))
		live := []byte("local\n")
		// baseHash set on PriorEntry but no base file written -> not in store.
		inv := preserveInv(&scope, src, dest, "three_way_merge", live, nil, "")
		inv.PriorEntry = &schema.OwnershipEntry{Expected: schema.Expected{SourceHash: "blake3:deadbeef"}}
		res, err := Config(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		got, _ := os.ReadFile(dest)
		Expect(string(got)).To(Equal("local\n"))
		dotNew, _ := os.ReadFile(dest + ".new")
		Expect(string(dotNew)).To(Equal("incoming\n"))
		Expect(res.Warnings[0].Kind).To(Equal("three_way_merge_fallback"))
		Expect(res.Warnings[0].Fields["reason"]).To(Equal("base_not_in_store"))
	})

	It("three_way_merge falls back when live is binary", func() {
		base := []byte("a\nb\n")
		scope, src, dest := configFixture([]byte("a\nb\nc\n"))
		live := []byte("a\x00b\n")
		baseHash := blake3Hex(base)
		inv := preserveInv(&scope, src, dest, "three_way_merge", live, base, baseHash)
		inv.PriorEntry = &schema.OwnershipEntry{Expected: schema.Expected{SourceHash: baseHash}}
		res, err := Config(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Warnings[0].Fields["reason"]).To(Equal("binary_live"))
	})

	It("sticky preserve keeps live when no current drift but prior ContentHash != SourceHash", func() {
		scope, src, dest := configFixture([]byte("incoming\n"))
		live := []byte("local\n")
		liveRoot, priorGenDir := simulatePriorGen(scope, dest, live, "", nil)
		scope.LiveRoot, scope.PriorGenDir = liveRoot, priorGenDir
		inv := Invocation{Action: "config", PackageName: "hello", Phase: PhasePostPlace,
			Params: map[string]any{"src": src, "dest": dest, "policy": "preserve"},
			PriorEntry: &schema.OwnershipEntry{Expected: schema.Expected{
				ContentHash: blake3Hex(live), SourceHash: blake3Hex([]byte("incoming\n"))}}}
		res, err := Config(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		got, _ := os.ReadFile(dest)
		Expect(string(got)).To(Equal("local\n"))
		Expect(res.Expected.ContentHash).To(Equal(blake3Hex(live)))
	})

	It("reset force-writes incoming even when the path is drifting", func() {
		scope, src, dest := configFixture([]byte("incoming\n"))
		inv := preserveInv(&scope, src, dest, "preserve", []byte("local\n"), nil, "")
		ownPath := filepath.ToSlash(mustRel(scope.ActiveRoot, dest))
		inv.ResetPaths = map[string]bool{ownPath: true}
		res, err := Config(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		got, _ := os.ReadFile(dest)
		Expect(string(got)).To(Equal("incoming\n"))
		Expect(res.Expected.ContentHash).To(Equal(res.Expected.SourceHash))
	})

	It("writes incoming when preserve mode is set but the live file is gone", func() {
		scope, src, dest := configFixture([]byte("incoming\n"))
		// Wire a prior gen dir but do NOT create the live file.
		root := GinkgoT().TempDir()
		scope.PriorGenDir = filepath.Join(root, "generations", "1")
		scope.LiveRoot = filepath.Join(scope.PriorGenDir, "active")
		Expect(os.MkdirAll(scope.LiveRoot, 0o755)).To(Succeed())
		ownPath := filepath.ToSlash(mustRel(scope.ActiveRoot, dest))
		inv := Invocation{Action: "config", PackageName: "hello", Phase: PhasePostPlace,
			Params:          map[string]any{"src": src, "dest": dest, "policy": "preserve"},
			PreserveActions: map[string]string{ownPath: "blake3:whatever"}}
		res, err := Config(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		got, _ := os.ReadFile(dest)
		Expect(string(got)).To(Equal("incoming\n"))
		Expect(res.Expected.ContentHash).To(Equal(res.Expected.SourceHash))
	})
})

// mustRel is a test helper returning the path of dest relative to base.
func mustRel(base, dest string) string {
	rel, err := filepath.Rel(base, dest)
	Expect(err).NotTo(HaveOccurred())
	return rel
}

var _ = Describe("Config idempotency", func() {
	It("re-applying preserve with sticky invariant is a no-op on content", func() {
		scope, src, dest := configFixture([]byte("incoming\n"))
		live := []byte("local\n")
		liveRoot, priorGenDir := simulatePriorGen(scope, dest, live, "", nil)
		scope.LiveRoot, scope.PriorGenDir = liveRoot, priorGenDir
		inv := Invocation{Action: "config", PackageName: "hello", Phase: PhasePostPlace,
			Params: map[string]any{"src": src, "dest": dest, "policy": "preserve"},
			PriorEntry: &schema.OwnershipEntry{Expected: schema.Expected{
				ContentHash: blake3Hex(live), SourceHash: blake3Hex([]byte("incoming\n"))}}}
		r1, err := Config(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		r2, err := Config(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(r2.Expected).To(Equal(r1.Expected))
		got, _ := os.ReadFile(dest)
		Expect(string(got)).To(Equal("local\n"))
	})
})

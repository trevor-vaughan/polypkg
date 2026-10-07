package planner

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/action"
	"github.com/trevor-vaughan/polypkg/internal/extractstore"
	"github.com/trevor-vaughan/polypkg/internal/runner"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// projMember is one tar entry of a projection fixture archive.
type projMember struct {
	name, body, link string
	typeflag         byte
	mode             int64
}

var projAppMembers = []projMember{
	{name: "app-1.0/bin/app", typeflag: tar.TypeReg, mode: 0o755, body: "#!/bin/sh\necho app\n"},
	{name: "app-1.0/bin/app-link", typeflag: tar.TypeSymlink, mode: 0o777, link: "app"},
	{name: "app-1.0/doc/README", typeflag: tar.TypeReg, mode: 0o644, body: "docs\n"},
}

// writeExtractSource creates a package root holding content/app.tar.gz built
// from members and returns the root.
func writeExtractSource(members ...projMember) string {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, m := range members {
		Expect(tw.WriteHeader(&tar.Header{
			Name: m.name, Typeflag: m.typeflag, Mode: m.mode, Linkname: m.link, Size: int64(len(m.body)),
		})).To(Succeed())
		_, err := tw.Write([]byte(m.body))
		Expect(err).NotTo(HaveOccurred())
	}
	Expect(tw.Close()).To(Succeed())
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, err := zw.Write(raw.Bytes())
	Expect(err).NotTo(HaveOccurred())
	Expect(zw.Close()).To(Succeed())

	root := GinkgoT().TempDir()
	Expect(os.MkdirAll(filepath.Join(root, "content"), 0o755)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(root, "content", "app.tar.gz"), gz.Bytes(), 0o644)).To(Succeed())
	return root
}

func projExtractPkg() *schema.Package {
	return &schema.Package{
		Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
		Actions: []schema.PackageAction{{
			Phase: "post-place", Action: "extract", Drift: "refuse",
			Params: map[string]any{
				"src": "$PKG/content/app.tar.gz", "dest": "$ACTIVE/hello/dist", "strip_components": 1,
			},
		}},
	}
}

var _ = Describe("projectOwnership multi-result actions", func() {
	DescribeTable("projects exactly the entries the extract action records at apply",
		func(scopeName string, dirMode os.FileMode, wantDirMode string) {
			pkgRoot := writeExtractSource(projAppMembers...)
			pkg := projExtractPkg()

			own, err := projectOwnership([]runner.RunEntry{{Package: pkg, PkgRoot: pkgRoot}}, "$ACTIVE", nil, Options{Scope: scopeName, DirMode: dirMode, StateHome: GinkgoT().TempDir()})
			Expect(err).NotTo(HaveOccurred())

			out, err := runner.DispatchActions(context.Background(), pkg, pkgRoot,
				action.Scope{ActiveRoot: GinkgoT().TempDir(), PackageName: "hello", DirMode: dirMode},
				"post-place", nil, nil, nil, nil)
			Expect(err).NotTo(HaveOccurred())
			applied := make([]schema.OwnershipEntry, len(out.Entries))
			for i, e := range out.Entries {
				e.Stat = schema.StatInfo{} // the projection leaves Stat zero by design
				applied[i] = e
			}

			Expect(own.Entries).To(ConsistOf(applied))
			Expect(own.Entries).To(HaveLen(6), "dist, dist/bin, dist/bin/app, dist/bin/app-link, dist/doc, dist/doc/README")
			for _, e := range own.Entries {
				Expect(e.DriftPolicy).To(Equal("refuse"))
				if e.Expected.FileType == "dir" {
					Expect(e.Expected.Mode).To(Equal(wantDirMode), "dir mode of %s", e.Path)
				}
			}
		},
		Entry("user scope", "user", os.FileMode(0o700), "0700"),
		Entry("system scope", "system", os.FileMode(0o755), "0755"),
		Entry("an explicit mode, whatever the scope", "user", os.FileMode(0o750), "0750"),
	)

	It("projects inside the state home's extract store and leaves nothing behind", func() {
		// Build the fixture first: GinkgoT().TempDir honours TMPDIR too.
		pkgRoot := writeExtractSource(projAppMembers...)
		stateHome := GinkgoT().TempDir()
		tmp := GinkgoT().TempDir()
		GinkgoT().Setenv("TMPDIR", tmp)
		spec := action.Registry["extract"]
		var projectedInto string
		recording := spec
		recording.MultiHandler = func(inv action.Invocation, scope action.Scope) ([]action.Result, error) {
			projectedInto = scope.ActiveRoot
			return spec.MultiHandler(inv, scope)
		}
		action.Registry["extract"] = recording
		DeferCleanup(func() { action.Registry["extract"] = spec })

		_, err := projectOwnership([]runner.RunEntry{{Package: projExtractPkg(), PkgRoot: pkgRoot}}, "$ACTIVE", nil,
			Options{Scope: "user", StateHome: stateHome})
		Expect(err).NotTo(HaveOccurred())
		Expect(filepath.Dir(projectedInto)).To(Equal(extractstore.Root(stateHome)),
			"the throwaway root lives where the extract-store sweep reclaims it after a crash")
		left, err := os.ReadDir(extractstore.Root(stateHome))
		Expect(err).NotTo(HaveOccurred())
		Expect(left).To(BeEmpty())
		left, err = os.ReadDir(tmp)
		Expect(err).NotTo(HaveOccurred())
		Expect(left).To(BeEmpty(), "nothing is written to the system temp dir")
	})

	It("refuses to project a multi-result action without a state home", func() {
		pkgRoot := writeExtractSource(projAppMembers...)
		_, err := projectOwnership([]runner.RunEntry{{Package: projExtractPkg(), PkgRoot: pkgRoot}}, "$ACTIVE", nil, Options{Scope: "user"})
		Expect(err).To(MatchError(ContainSubstring("no state home")))
	})

	It("surfaces an archive the action would refuse as a projection error", func() {
		pkgRoot := writeExtractSource(append(projAppMembers,
			projMember{name: "../evil", typeflag: tar.TypeReg, mode: 0o644, body: "x"})...)

		_, err := projectOwnership([]runner.RunEntry{{Package: projExtractPkg(), PkgRoot: pkgRoot}}, "$ACTIVE", nil, Options{Scope: "user", StateHome: GinkgoT().TempDir()})
		Expect(err).To(MatchError(ContainSubstring("action extract (pkg hello)")))
	})

	It("applies a result's own drift policy before the declared one, as the runner does", func() {
		action.Registry["test-multi"] = action.Spec{Name: "test-multi", FilePlacing: true,
			MultiHandler: func(_ action.Invocation, s action.Scope) ([]action.Result, error) {
				base := filepath.Join(s.ActiveRoot, s.PackageName, "tree")
				return []action.Result{
					{Action: "test-multi", Path: base, Outcome: "ok", Expected: schema.Expected{FileType: "dir", Mode: "0700"}},
					{Action: "test-multi", Path: filepath.Join(base, "f"), Outcome: "ok", DriftPolicy: "notify_preserve",
						Expected: schema.Expected{FileType: "regular", ContentHash: "blake3:aa", Mode: "0644"}},
				}, nil
			}}
		DeferCleanup(func() { delete(action.Registry, "test-multi") })
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{Phase: "post-place", Action: "test-multi", Drift: "refuse", Params: map[string]any{}}},
		}

		own, err := projectOwnership([]runner.RunEntry{{Package: pkg, PkgRoot: GinkgoT().TempDir()}}, "$ACTIVE", nil, Options{Scope: "user", StateHome: GinkgoT().TempDir()})
		Expect(err).NotTo(HaveOccurred())
		out, err := runner.DispatchActions(context.Background(), pkg, GinkgoT().TempDir(),
			action.Scope{ActiveRoot: GinkgoT().TempDir(), PackageName: "hello"}, "post-place", nil, nil, nil, nil)
		Expect(err).NotTo(HaveOccurred())

		Expect(own.Entries).To(Equal(out.Entries))
		Expect(own.Entries[0].DriftPolicy).To(Equal("refuse"))
		Expect(own.Entries[1].DriftPolicy).To(Equal("notify_preserve"))
	})

	It("fails the projection when a result is not ok, as the runner does", func() {
		action.Registry["test-multi"] = action.Spec{Name: "test-multi", FilePlacing: true,
			MultiHandler: func(_ action.Invocation, s action.Scope) ([]action.Result, error) {
				return []action.Result{{Action: "test-multi", Path: filepath.Join(s.ActiveRoot, s.PackageName, "t"),
					Outcome: "error", ErrorMsg: "boom"}}, nil
			}}
		DeferCleanup(func() { delete(action.Registry, "test-multi") })
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{Phase: "post-place", Action: "test-multi", Params: map[string]any{}}},
		}

		_, err := projectOwnership([]runner.RunEntry{{Package: pkg, PkgRoot: GinkgoT().TempDir()}}, "$ACTIVE", nil, Options{Scope: "user", StateHome: GinkgoT().TempDir()})
		Expect(err).To(MatchError(ContainSubstring("action test-multi (pkg hello): failed: boom")))
	})

	It("leaves multi-result actions out without running them when told to skip them", func() {
		pkgRoot := writeExtractSource(append(projAppMembers,
			projMember{name: "../evil", typeflag: tar.TypeReg, mode: 0o644, body: "x"})...)

		own, err := projectOwnership([]runner.RunEntry{{Package: projExtractPkg(), PkgRoot: pkgRoot}}, "$ACTIVE", nil, Options{Scope: "user", SkipMultiResultProjection: true})
		Expect(err).NotTo(HaveOccurred(), "a refusing archive is never opened")
		Expect(own.Entries).To(BeEmpty())
	})
})

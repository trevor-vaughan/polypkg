package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/action"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/starlarkeval"
)

var _ = Describe("DispatchActions", func() {
	It("executes install and dir actions and emits ownership entries", func() {
		dir := GinkgoT().TempDir()
		pkgRoot := filepath.Join(dir, "pkg-root")
		Expect(os.MkdirAll(filepath.Join(pkgRoot, "content/bin"), 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(pkgRoot, "content/bin/hi"), []byte("#!/bin/sh\n"), 0o755)).To(Succeed())

		active := filepath.Join(dir, "active")
		scope := action.Scope{ActiveRoot: active, PackageName: "hello"}

		pkg := &schema.Package{
			Schema:  "polypkg.package/v1",
			Name:    "hello",
			Version: "1.0.0",
			Actions: []schema.PackageAction{
				{
					Phase:  "post-place",
					Action: "dir",
					Params: map[string]any{
						"path": "$ACTIVE/hello/bin",
						"mode": "0o755",
					},
				},
				{
					Phase:  "post-place",
					Action: "install",
					Params: map[string]any{
						"src":    "$PKG/content/bin/hi",
						"dest":   "$ACTIVE/hello/bin/hi",
						"policy": "symlink",
					},
				},
			},
		}

		ev := starlarkeval.NewInProcessEvaluator(starlarkeval.Limits{
			MaxSteps: 1_000_000, Timeout: time.Second, MaxMemoryBytes: 64 << 20, MaxOutputBytes: 64 << 10,
		})
		out, err := DispatchActions(context.Background(), pkg, pkgRoot, scope, "post-place", ev, nil, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(out.Entries).To(HaveLen(2))

		byPath := map[string]schema.OwnershipEntry{}
		for _, e := range out.Entries {
			byPath[e.Path] = e
		}
		dirEntry, ok := byPath["hello/bin"]
		Expect(ok).To(BeTrue())
		Expect(dirEntry.Action).To(Equal("dir"))
		Expect(dirEntry.Package).To(Equal("hello"))
		Expect(dirEntry.DriftPolicy).To(Equal("notify_heal"))

		hiEntry, ok := byPath["hello/bin/hi"]
		Expect(ok).To(BeTrue())
		Expect(hiEntry.Action).To(Equal("install"))
		Expect(hiEntry.Expected.FileType).To(Equal("symlink"))
		Expect(hiEntry.Expected.ContentHash).NotTo(BeEmpty())

		info, err := os.Stat(filepath.Join(active, "hello/bin"))
		Expect(err).NotTo(HaveOccurred())
		Expect(info.IsDir()).To(BeTrue())

		link, err := os.Lstat(filepath.Join(active, "hello/bin/hi"))
		Expect(err).NotTo(HaveOccurred())
		Expect(link.Mode()&os.ModeSymlink != 0).To(BeTrue())
	})
})

var _ = Describe("DispatchActions config", func() {
	It("runs a config action, collects ConfigBases keyed by SourceHash, and threads prior entry", func() {
		dir := GinkgoT().TempDir()
		pkgRoot := filepath.Join(dir, "pkg-root")
		Expect(os.MkdirAll(filepath.Join(pkgRoot, "content"), 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(pkgRoot, "content/app.conf"), []byte("incoming\n"), 0o644)).To(Succeed())

		active := filepath.Join(dir, "active")
		scope := action.Scope{ActiveRoot: active, PackageName: "hello"}
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "config",
				Params: map[string]any{"src": "$PKG/content/app.conf", "dest": "$ACTIVE/hello/etc/app.conf", "policy": "preserve"},
			}},
		}
		ev := starlarkeval.NewInProcessEvaluator(starlarkeval.Limits{
			MaxSteps: 1_000_000, Timeout: time.Second, MaxMemoryBytes: 64 << 20, MaxOutputBytes: 64 << 10})

		out, err := DispatchActions(context.Background(), pkg, pkgRoot, scope, "post-place", ev, nil, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(out.Entries).To(HaveLen(1))
		Expect(out.Entries[0].Action).To(Equal("config"))
		Expect(out.Entries[0].DriftPolicy).To(Equal("notify_preserve"))
		Expect(out.Entries[0].Expected.SourceHash).NotTo(BeEmpty())
		Expect(out.ConfigBases).To(HaveKey(out.Entries[0].Expected.SourceHash))
		Expect(out.ConfigBases[out.Entries[0].Expected.SourceHash]).To(Equal([]byte("incoming\n")))
	})
})

var _ = Describe("DispatchActions unmanaged and state", func() {
	It("dispatches both non-placement actions and records their ownership entries", func() {
		dir := GinkgoT().TempDir()
		pkgRoot := filepath.Join(dir, "pkg-root")
		Expect(os.MkdirAll(pkgRoot, 0o755)).To(Succeed())
		active := filepath.Join(dir, "active")
		scope := action.Scope{ActiveRoot: active, StateRoot: filepath.Join(dir, "state"), PackageName: "hello"}
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{
				{Phase: "post-place", Action: "unmanaged", Params: map[string]any{"path": "$ACTIVE/hello/var/run/app.sock"}},
				{Phase: "post-place", Action: "state", Params: map[string]any{"path": "$ACTIVE/hello/var/lib/app"}},
			},
		}
		ev := starlarkeval.NewInProcessEvaluator(starlarkeval.Limits{
			MaxSteps: 1_000_000, Timeout: time.Second, MaxMemoryBytes: 64 << 20, MaxOutputBytes: 64 << 10})
		out, err := DispatchActions(context.Background(), pkg, pkgRoot, scope, "post-place", ev, nil, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(out.Entries).To(HaveLen(2))
		byPath := map[string]schema.OwnershipEntry{}
		for _, e := range out.Entries {
			byPath[e.Path] = e
		}
		Expect(byPath["hello/var/run/app.sock"].Expected.FileType).To(Equal("ghost"))
		Expect(byPath["hello/var/run/app.sock"].DriftPolicy).To(Equal("unmanaged"))
		Expect(byPath["hello/var/lib/app"].Expected.FileType).To(Equal("state"))
		Expect(byPath["hello/var/lib/app"].DriftPolicy).To(Equal("state"))
		Expect(out.ConfigBases).To(BeEmpty())
	})
})

var _ = Describe("DispatchActions path", func() {
	It("dispatches the path action and records a bin/<name> symlink entry", func() {
		dir := GinkgoT().TempDir()
		pkgRoot := filepath.Join(dir, "pkg-root")
		Expect(os.MkdirAll(pkgRoot, 0o755)).To(Succeed())
		active := filepath.Join(dir, "active")
		scope := action.Scope{ActiveRoot: active, PackageName: "hello"}
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{
				{Phase: "post-place", Action: "path",
					Params: map[string]any{"name": "hello", "source": "$ACTIVE/hello/bin/hello"}},
			},
		}
		ev := starlarkeval.NewInProcessEvaluator(starlarkeval.Limits{
			MaxSteps: 1_000_000, Timeout: time.Second, MaxMemoryBytes: 64 << 20, MaxOutputBytes: 64 << 10})
		out, err := DispatchActions(context.Background(), pkg, pkgRoot, scope, "post-place", ev, nil, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(out.Entries).To(HaveLen(1))
		Expect(out.Entries[0].Path).To(Equal("bin/hello"))
		Expect(out.Entries[0].Action).To(Equal("path"))
		Expect(out.Entries[0].Expected.FileType).To(Equal("symlink"))
		Expect(out.Entries[0].DriftPolicy).To(Equal("notify_heal"))
	})
})

var _ = Describe("DispatchActions alternatives", func() {
	It("dispatches the alternatives action and records a bin/<name> entry with priority", func() {
		dir := GinkgoT().TempDir()
		pkgRoot := filepath.Join(dir, "pkg-root")
		Expect(os.MkdirAll(pkgRoot, 0o755)).To(Succeed())
		active := filepath.Join(dir, "active")
		altRoot := filepath.Join(dir, "alternatives")
		scope := action.Scope{ActiveRoot: active, AltRoot: altRoot, PackageName: "neovim"}
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "neovim", Version: "1.0.0",
			Actions: []schema.PackageAction{
				{Phase: "post-place", Action: "alternatives",
					Params: map[string]any{"name": "editor", "source": "$ACTIVE/neovim/bin/nvim", "priority": 30}},
			},
		}
		ev := starlarkeval.NewInProcessEvaluator(starlarkeval.Limits{
			MaxSteps: 1_000_000, Timeout: time.Second, MaxMemoryBytes: 64 << 20, MaxOutputBytes: 64 << 10})
		out, err := DispatchActions(context.Background(), pkg, pkgRoot, scope, "post-place", ev, nil, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(out.Entries).To(HaveLen(1))
		Expect(out.Entries[0].Path).To(Equal("bin/editor"))
		Expect(out.Entries[0].Action).To(Equal("alternatives"))
		Expect(out.Entries[0].Expected.Priority).To(Equal(30))
	})
})

var _ = Describe("DispatchActions unknown action", func() {
	It("returns an error naming the action and package", func() {
		pkg := &schema.Package{
			Schema:  "polypkg.package/v1",
			Name:    "hello",
			Version: "1.0.0",
			Actions: []schema.PackageAction{{Phase: "post-place", Action: "nope", Params: map[string]any{}}},
		}
		scope := action.Scope{ActiveRoot: GinkgoT().TempDir(), PackageName: "hello"}
		_, err := DispatchActions(context.Background(), pkg, GinkgoT().TempDir(), scope, "post-place", nil, nil, nil, nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring(`unknown action "nope" in package "hello"`))
	})
})

var _ = Describe("DispatchActions computed mode", func() {
	It("refuses a !starlark mode that evaluates to an unsafe value", func() {
		dir := GinkgoT().TempDir()
		active := filepath.Join(dir, "active")
		scope := action.Scope{ActiveRoot: active, PackageName: "hello"}
		pkg := &schema.Package{
			Schema:  "polypkg.package/v1",
			Name:    "hello",
			Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase:  "post-place",
				Action: "dir",
				Params: map[string]any{
					"path": "$ACTIVE/hello/data",
					"mode": schema.StarlarkExpr{Source: `return "0o777"`},
				},
			}},
		}

		ev := starlarkeval.NewInProcessEvaluator(starlarkeval.Limits{
			MaxSteps: 1_000_000, Timeout: time.Second, MaxMemoryBytes: 64 << 20, MaxOutputBytes: 64 << 10,
		})
		_, err := DispatchActions(context.Background(), pkg, filepath.Join(dir, "pkg-root"), scope, "post-place", ev, nil, nil, nil)
		Expect(err).To(MatchError(ContainSubstring(`refusing mode "0o777"`)))
		Expect(err.Error()).To(ContainSubstring("sets group-write, other-write;"))

		_, statErr := os.Stat(active)
		Expect(os.IsNotExist(statErr)).To(BeTrue(), "a refused computed mode must not create anything")
	})
})

var _ = Describe("substituteParams", func() {
	It("evaluates a Starlark expression then substitutes template variables", func() {
		ev := starlarkeval.NewInProcessEvaluator(starlarkeval.Limits{
			MaxSteps: 1_000_000, Timeout: time.Second, MaxMemoryBytes: 64 << 20, MaxOutputBytes: 64 << 10,
		})
		var in starlarkeval.Inputs
		in.Host.Arch = "arm64"
		params := map[string]any{
			"dest":   schema.StarlarkExpr{Source: `return "$ACTIVE/hello/" + host.arch`},
			"policy": "symlink",
		}
		out, err := substituteParams(context.Background(), params, "/active", "/pkg", in, ev)
		Expect(err).NotTo(HaveOccurred())
		Expect(out["dest"]).To(Equal("/active/hello/arm64"))
		Expect(out["policy"]).To(Equal("symlink"))
	})

	It("propagates evaluator errors when the result is not a string", func() {
		ev := starlarkeval.NewInProcessEvaluator(starlarkeval.Limits{MaxSteps: 1000, MaxOutputBytes: 100})
		params := map[string]any{"dest": schema.StarlarkExpr{Source: `return 5`}}
		_, err := substituteParams(context.Background(), params, "/a", "/p", starlarkeval.Inputs{}, ev)
		Expect(err).To(MatchError(ContainSubstring("must be a string")))
	})
})

var _ = Describe("DispatchActions multi-result actions", func() {
	// registerMulti installs a throwaway multi-result action for one spec and
	// removes it afterwards, so the real Registry is unchanged for other specs.
	registerMulti := func(h func(action.Invocation, action.Scope) ([]action.Result, error)) {
		action.Registry["test-multi"] = action.Spec{Name: "test-multi", FilePlacing: true, MultiHandler: h}
		DeferCleanup(func() { delete(action.Registry, "test-multi") })
	}
	multiPkg := func() *schema.Package {
		return &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{Phase: "post-place", Action: "test-multi", Drift: "refuse", Params: map[string]any{}}},
		}
	}

	It("records one ownership entry per returned result", func() {
		warning := action.ConfigWarning{Kind: "test", Fields: map[string]any{"n": 1}}
		registerMulti(func(_ action.Invocation, s action.Scope) ([]action.Result, error) {
			base := filepath.Join(s.ActiveRoot, s.PackageName, "tree")
			return []action.Result{
				{Action: "test-multi", Path: base, Outcome: "ok",
					Expected: schema.Expected{FileType: "dir", Mode: "0700"}},
				{Action: "test-multi", Path: filepath.Join(base, "f"), Outcome: "ok",
					Expected: schema.Expected{FileType: "regular", ContentHash: "blake3:aa", Mode: "0644"},
					Warnings: []action.ConfigWarning{warning}},
			}, nil
		})
		scope := action.Scope{ActiveRoot: GinkgoT().TempDir(), PackageName: "hello"}
		out, err := DispatchActions(context.Background(), multiPkg(), GinkgoT().TempDir(), scope, "post-place", nil, nil, nil, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(out.Entries).To(Equal([]schema.OwnershipEntry{
			{Path: "hello/tree", Package: "hello", Version: "1.0.0", Action: "test-multi",
				Expected: schema.Expected{FileType: "dir", Mode: "0700"}, DriftPolicy: "refuse"},
			{Path: "hello/tree/f", Package: "hello", Version: "1.0.0", Action: "test-multi",
				Expected: schema.Expected{FileType: "regular", ContentHash: "blake3:aa", Mode: "0644"}, DriftPolicy: "refuse"},
		}))
		Expect(out.Warnings).To(ConsistOf(warning))
	})

	It("fails the phase when any returned result is not ok", func() {
		registerMulti(func(_ action.Invocation, s action.Scope) ([]action.Result, error) {
			base := filepath.Join(s.ActiveRoot, s.PackageName, "tree")
			return []action.Result{
				{Action: "test-multi", Path: base, Outcome: "ok", Expected: schema.Expected{FileType: "dir", Mode: "0700"}},
				{Action: "test-multi", Path: filepath.Join(base, "f"), Outcome: "error", ErrorMsg: "boom"},
			}, nil
		})
		scope := action.Scope{ActiveRoot: GinkgoT().TempDir(), PackageName: "hello"}
		_, err := DispatchActions(context.Background(), multiPkg(), GinkgoT().TempDir(), scope, "post-place", nil, nil, nil, nil)
		Expect(err).To(MatchError(ContainSubstring("action test-multi (pkg hello) failed: boom")))
	})

	It("wraps a multi-result handler error with the action and package", func() {
		registerMulti(func(action.Invocation, action.Scope) ([]action.Result, error) {
			return nil, errors.New("archive refused")
		})
		scope := action.Scope{ActiveRoot: GinkgoT().TempDir(), PackageName: "hello"}
		_, err := DispatchActions(context.Background(), multiPkg(), GinkgoT().TempDir(), scope, "post-place", nil, nil, nil, nil)
		Expect(err).To(MatchError(ContainSubstring("action test-multi (pkg hello): archive refused")))
	})
})

package runner

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/audit"
	"github.com/trevor-vaughan/polypkg/internal/gc"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/starlarkeval"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

// recordingWriter captures audit events in memory so tests can assert on
// their presence and field contents without parsing JSON-Lines from disk.
type recordingWriter struct{ events []audit.Event }

func (w *recordingWriter) Write(e audit.Event) error { w.events = append(w.events, e); return nil }
func (w *recordingWriter) Close() error              { return nil }

var _ = Describe("Run", func() {
	It("commits an empty manifest as generation 1 with an empty ownership", func() {
		root := GinkgoT().TempDir()
		sub, err := substrate.NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		w, err := audit.NewFileWriter(filepath.Join(root, "audit.log"))
		Expect(err).NotTo(HaveOccurred())
		defer w.Close()

		m := &schema.Manifest{
			Schema: "polypkg.manifest/v2", Generation: 0, Scope: "user", Entries: []schema.ManifestEntry{},
		}

		r := New(Options{
			Substrate:   sub,
			AuditWriter: w,
			LockPath:    filepath.Join(root, "apply.lock"),
			Scope:       "user",
		})
		gen, err := r.Run(context.Background(), m, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(gen).To(Equal(1))

		current, err := sub.CurrentGeneration()
		Expect(err).NotTo(HaveOccurred())
		Expect(current).To(Equal(1))

		f, err := os.Open(filepath.Join(root, "generations", strconv.Itoa(gen), "ownership.json"))
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		own, err := schema.ParseOwnership(f)
		Expect(err).NotTo(HaveOccurred())
		Expect(own.Schema).To(Equal("polypkg.ownership/v1"))
		Expect(own.Entries).To(HaveLen(0))
	})

	Describe("opportunistic GC", func() {
		It("removes the oldest generation when policy is set and emits a gc.run event", func() {
			tmp := GinkgoT().TempDir()
			sub, err := substrate.NewOwnStore(tmp)
			Expect(err).NotTo(HaveOccurred())

			w := &recordingWriter{}
			r := New(Options{
				Substrate: sub, AuditWriter: w, LockPath: filepath.Join(tmp, "apply.lock"),
				Scope:    "user",
				GCPolicy: &gc.Policy{Count: 2, Age: 0},
			})

			mk := func() {
				m := &schema.Manifest{
					Schema: "polypkg.manifest/v2", Scope: "user",
					Entries: []schema.ManifestEntry{},
					ProducedBy: schema.ProducedBy{Tool: "polypkg", Version: "test", Host: "h",
						Timestamp: time.Now().UTC()},
				}
				_, err := r.Run(context.Background(), m, nil)
				Expect(err).NotTo(HaveOccurred())
			}
			mk() // gen 1
			mk() // gen 2 — opportunistic GC retains {1,2}
			mk() // gen 3 — opportunistic GC keeps {2,3}, removes 1

			gens, err := sub.ListGenerations()
			Expect(err).NotTo(HaveOccurred())
			Expect(gens).To(HaveLen(2), "GC should have removed gen 1")
			ids := []int{gens[0].ID, gens[1].ID}
			sort.Ints(ids)
			Expect(ids).To(Equal([]int{2, 3}))

			found := false
			for _, e := range w.events {
				if e.Event == "gc.run" && e.Fields["trigger"] == "opportunistic" {
					found = true
					break
				}
			}
			Expect(found).To(BeTrue(), "expected gc.run event with trigger=opportunistic")
		})

		It("skips GC entirely when GCPolicy is nil", func() {
			tmp := GinkgoT().TempDir()
			sub, err := substrate.NewOwnStore(tmp)
			Expect(err).NotTo(HaveOccurred())
			w := &recordingWriter{}
			r := New(Options{
				Substrate: sub, AuditWriter: w, LockPath: filepath.Join(tmp, "apply.lock"),
				Scope: "user",
			})
			for i := 0; i < 3; i++ {
				m := &schema.Manifest{
					Schema: "polypkg.manifest/v2", Scope: "user",
					Entries: []schema.ManifestEntry{},
					ProducedBy: schema.ProducedBy{Tool: "polypkg", Version: "test", Host: "h",
						Timestamp: time.Now().UTC()},
				}
				_, err := r.Run(context.Background(), m, nil)
				Expect(err).NotTo(HaveOccurred())
			}
			gens, err := sub.ListGenerations()
			Expect(err).NotTo(HaveOccurred())
			Expect(gens).To(HaveLen(3), "no GC should run when GCPolicy is nil")
			for _, e := range w.events {
				Expect(e.Event).NotTo(Equal("gc.run"), "no gc.run event when GCPolicy is nil")
			}
		})
	})
})

var _ = Describe("Run config reset", func() {
	It("force-restores package content when the path is queued for reset, then clears the queue", func() {
		dir := GinkgoT().TempDir()
		root := filepath.Join(dir, "store")
		sub, err := substrate.NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		pkgRoot := filepath.Join(dir, "pkg")
		Expect(os.MkdirAll(filepath.Join(pkgRoot, "content"), 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(pkgRoot, "content/app.conf"), []byte("from-pkg\n"), 0o644)).To(Succeed())
		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "config",
				Params: map[string]any{"src": "$PKG/content/app.conf", "dest": "$ACTIVE/hello/etc/app.conf", "policy": "preserve"},
			}},
		}
		m := &schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}}
		resetsPath := filepath.Join(dir, "pending-resets.json")
		r := New(Options{Substrate: sub, Scope: "user", LockPath: filepath.Join(dir, "apply.lock"),
			ResetsPath:     resetsPath,
			StarlarkLimits: starlarkeval.Limits{MaxSteps: 1_000_000, Timeout: time.Second, MaxMemoryBytes: 64 << 20, MaxOutputBytes: 64 << 10}})
		entries := []RunEntry{{Package: pkg, PkgRoot: pkgRoot}}

		_, err = r.Run(context.Background(), m, entries)
		Expect(err).NotTo(HaveOccurred())
		live := filepath.Join(root, "active", "hello", "etc", "app.conf")
		Expect(os.WriteFile(live, []byte("local-edit\n"), 0o644)).To(Succeed())

		// Queue a reset for the path.
		Expect(os.WriteFile(resetsPath,
			[]byte(`{"schema":"polypkg.resets/v1","scope":"user","paths":["hello/etc/app.conf"]}`), 0o600)).To(Succeed())

		_, err = r.Run(context.Background(), m, entries)
		Expect(err).NotTo(HaveOccurred())
		got, _ := os.ReadFile(live)
		Expect(string(got)).To(Equal("from-pkg\n"))
		// Queue cleared.
		_, statErr := os.Stat(resetsPath)
		Expect(os.IsNotExist(statErr)).To(BeTrue())
	})

	It("fails the apply when pending-resets.json is corrupt", func() {
		dir := GinkgoT().TempDir()
		sub, err := substrate.NewOwnStore(filepath.Join(dir, "store"))
		Expect(err).NotTo(HaveOccurred())
		resetsPath := filepath.Join(dir, "pending-resets.json")
		Expect(os.WriteFile(resetsPath, []byte("{not json"), 0o600)).To(Succeed())
		m := &schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}}
		r := New(Options{Substrate: sub, Scope: "user", LockPath: filepath.Join(dir, "apply.lock"), ResetsPath: resetsPath})
		_, err = r.Run(context.Background(), m, nil)
		Expect(err).To(MatchError(ContainSubstring("pending-resets")))
	})
})

var _ = Describe("Run refuses shared-path conflicts", func() {
	It("aborts the apply when two packages claim the same bin path", func() {
		dir := GinkgoT().TempDir()
		sub, err := substrate.NewOwnStore(filepath.Join(dir, "store"))
		Expect(err).NotTo(HaveOccurred())

		mkPkg := func(name string) *schema.Package {
			return &schema.Package{
				Schema: "polypkg.package/v1", Name: name, Version: "1.0.0",
				Actions: []schema.PackageAction{{
					Phase: "post-place", Action: "path",
					Params: map[string]any{"name": "foo", "source": "$ACTIVE/" + name + "/bin/foo"},
				}},
			}
		}
		entryA := RunEntry{Package: mkPkg("alpha")}
		entryB := RunEntry{Package: mkPkg("beta")}

		m := &schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}}
		w := &recordingWriter{}
		r := New(Options{Substrate: sub, AuditWriter: w, Scope: "user", LockPath: filepath.Join(dir, "apply.lock"),
			StarlarkLimits: starlarkeval.Limits{MaxSteps: 1_000_000, Timeout: time.Second, MaxMemoryBytes: 64 << 20, MaxOutputBytes: 64 << 10}})

		_, err = r.Run(context.Background(), m, []RunEntry{entryA, entryB})
		Expect(err).To(MatchError(ContainSubstring("conflict")))

		// No generation was committed: CurrentOwnership reports no current gen.
		_, _, _, cerr := sub.CurrentOwnership()
		Expect(cerr).To(MatchError(substrate.ErrNoCurrentGeneration))

		// The refusal is audited as apply.failed at the conflict stage.
		conflictEvents := 0
		for _, e := range w.events {
			if e.Event == "apply.failed" && e.Fields["stage"] == "conflict" {
				conflictEvents++
			}
		}
		Expect(conflictEvents).To(Equal(1), "expected exactly one apply.failed event with stage=conflict")
	})
})

var _ = Describe("Run materializes alternatives winners", func() {
	It("links the highest-priority provider's source in the stable area", func() {
		dir := GinkgoT().TempDir()
		sub, err := substrate.NewOwnStore(filepath.Join(dir, "store"))
		Expect(err).NotTo(HaveOccurred())

		mkAlt := func(name string, priority int, source string) *schema.Package {
			return &schema.Package{
				Schema: "polypkg.package/v1", Name: name, Version: "1.0.0",
				Actions: []schema.PackageAction{{
					Phase: "post-place", Action: "alternatives",
					Params: map[string]any{"name": "editor", "source": source, "priority": priority},
				}},
			}
		}
		vimEntry := RunEntry{Package: mkAlt("vim", 10, "$ACTIVE/vim/bin/vim")}
		nvimEntry := RunEntry{Package: mkAlt("neovim", 30, "$ACTIVE/neovim/bin/nvim")}

		m := &schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}}
		w := &recordingWriter{}
		r := New(Options{Substrate: sub, AuditWriter: w, Scope: "user", LockPath: filepath.Join(dir, "apply.lock"),
			StarlarkLimits: starlarkeval.Limits{MaxSteps: 1_000_000, Timeout: time.Second, MaxMemoryBytes: 64 << 20, MaxOutputBytes: 64 << 10}})

		_, err = r.Run(context.Background(), m, []RunEntry{vimEntry, nvimEntry})
		Expect(err).NotTo(HaveOccurred())

		mid := filepath.Join(sub.AltRoot(), "editor")
		target, rerr := os.Readlink(mid)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(target).To(ContainSubstring(filepath.Join("neovim", "bin", "nvim")))
	})
})

var _ = Describe("Run config preserve", func() {
	It("preserves a live edit across a second apply", func() {
		dir := GinkgoT().TempDir()
		root := filepath.Join(dir, "store")
		sub, err := substrate.NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())

		pkgRoot := filepath.Join(dir, "pkg")
		Expect(os.MkdirAll(filepath.Join(pkgRoot, "content"), 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(pkgRoot, "content/app.conf"), []byte("from-pkg\n"), 0o644)).To(Succeed())

		pkg := &schema.Package{
			Schema: "polypkg.package/v1", Name: "hello", Version: "1.0.0",
			Actions: []schema.PackageAction{{
				Phase: "post-place", Action: "config",
				Params: map[string]any{"src": "$PKG/content/app.conf", "dest": "$ACTIVE/hello/etc/app.conf", "policy": "preserve"},
			}},
		}
		m := &schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}}
		r := New(Options{Substrate: sub, Scope: "user", LockPath: filepath.Join(dir, "apply.lock"),
			StarlarkLimits: starlarkeval.Limits{MaxSteps: 1_000_000, Timeout: time.Second, MaxMemoryBytes: 64 << 20, MaxOutputBytes: 64 << 10}})
		entries := []RunEntry{{Package: pkg, PkgRoot: pkgRoot}}

		_, err = r.Run(context.Background(), m, entries)
		Expect(err).NotTo(HaveOccurred())

		// Operator edits the live file.
		live := filepath.Join(root, "active", "hello", "etc", "app.conf")
		Expect(os.WriteFile(live, []byte("local-edit\n"), 0o644)).To(Succeed())

		// Second apply: preserve keeps the edit.
		_, err = r.Run(context.Background(), m, entries)
		Expect(err).NotTo(HaveOccurred())
		got, _ := os.ReadFile(live)
		Expect(string(got)).To(Equal("local-edit\n"))
	})
})

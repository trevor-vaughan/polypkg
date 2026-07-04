package runner

import (
	"context"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/audit"
	"github.com/trevor-vaughan/polypkg/internal/drift"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

var _ = Describe("decide", func() {
	It("refuse blocks without --heal-drift", func() {
		d := drift.Entry{
			Owned:    schema.OwnershipEntry{Path: "p", DriftPolicy: "refuse"},
			Reason:   drift.ReasonContent,
			Observed: "blake3:obs",
		}
		Expect(decide(d, false, nil)).To(Equal("refused"))
	})

	It("refuse heals when --heal-drift is set", func() {
		d := drift.Entry{
			Owned:  schema.OwnershipEntry{Path: "p", DriftPolicy: "refuse"},
			Reason: drift.ReasonContent,
		}
		Expect(decide(d, true, nil)).To(Equal("healed"))
	})

	It("notify_heal heals", func() {
		d := drift.Entry{Owned: schema.OwnershipEntry{Path: "p", DriftPolicy: "notify_heal"}}
		Expect(decide(d, false, nil)).To(Equal("healed"))
	})

	It("silent_heal heals", func() {
		d := drift.Entry{Owned: schema.OwnershipEntry{Path: "p", DriftPolicy: "silent_heal"}}
		Expect(decide(d, false, nil)).To(Equal("healed"))
	})

	It("notify_preserve preserves", func() {
		d := drift.Entry{Owned: schema.OwnershipEntry{Path: "p", DriftPolicy: "notify_preserve"}}
		Expect(decide(d, false, nil)).To(Equal("preserved"))
	})

	It("accepted-drift snapshot matching observed content yields accepted", func() {
		d := drift.Entry{
			Owned:    schema.OwnershipEntry{Path: "p", Action: "install", DriftPolicy: "refuse"},
			Reason:   drift.ReasonContent,
			Observed: "blake3:obs",
		}
		accepted := &schema.AcceptedDrift{Generation: 1, Paths: map[string]schema.AcceptedPath{
			"p": {Expected: schema.Expected{ContentHash: "blake3:obs"}},
		}}
		Expect(decide(d, false, accepted)).To(Equal("accepted"))
	})

	It("accepted-drift snapshot mismatched falls through to policy", func() {
		d := drift.Entry{
			Owned:    schema.OwnershipEntry{Path: "p", Action: "install", DriftPolicy: "refuse"},
			Reason:   drift.ReasonContent,
			Observed: "blake3:obs2",
		}
		accepted := &schema.AcceptedDrift{Generation: 1, Paths: map[string]schema.AcceptedPath{
			"p": {Expected: schema.Expected{ContentHash: "blake3:obs1"}}, // does not match Observed
		}}
		Expect(decide(d, false, accepted)).To(Equal("refused"))
	})
})

// stageGeneration begins a transaction, materializes the owned files into the
// staging tree to match the given ownership, and commits. Returns the substrate.
func stageGeneration(root string, own *schema.Ownership) substrate.Substrate {
	GinkgoHelper()
	sub, err := substrate.NewOwnStore(root)
	Expect(err).NotTo(HaveOccurred())
	Expect(sub.BeginTransaction("setup")).To(Succeed())
	stagingRoot, err := sub.StagingRoot("setup")
	Expect(err).NotTo(HaveOccurred())
	for _, e := range own.Entries {
		full := filepath.Join(stagingRoot, e.Path)
		Expect(os.MkdirAll(filepath.Dir(full), 0o755)).To(Succeed())
		switch e.Action {
		case "dir":
			Expect(os.MkdirAll(full, 0o755)).To(Succeed())
		case "install":
			Expect(os.WriteFile(full, []byte("payload"), 0o644)).To(Succeed())
		case "symlink":
			Expect(os.Symlink(e.Expected.Target, full)).To(Succeed())
		}
	}
	m := &schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}}
	_, err = sub.CommitGeneration("setup", m, own, nil)
	Expect(err).NotTo(HaveOccurred())
	return sub
}

var _ = Describe("Run drift handling", func() {
	It("refuse blocks apply when content drifts", func() {
		root := GinkgoT().TempDir()
		own := &schema.Ownership{
			Schema: "polypkg.ownership/v1", Scope: "user",
			Entries: []schema.OwnershipEntry{{
				Path: "hello/bin", Package: "hello", Version: "1.0.0", Action: "dir",
				Expected:    schema.Expected{FileType: "dir", Mode: "0755"},
				DriftPolicy: "refuse",
			}},
		}
		sub := stageGeneration(root, own)
		// Cause drift: chmod to 0o700.
		Expect(os.Chmod(filepath.Join(root, "generations/1/active/hello/bin"), 0o700)).To(Succeed())

		w, err := audit.NewFileWriter(filepath.Join(root, "audit.log"))
		Expect(err).NotTo(HaveOccurred())
		defer w.Close()
		r := New(Options{Substrate: sub, AuditWriter: w, Scope: "user",
			LockPath: filepath.Join(root, "apply.lock")})
		_, err = r.Run(context.Background(),
			&schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}},
			nil)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("apply refused"))
		// No new generation: still at 1.
		cur, err := sub.CurrentGeneration()
		Expect(err).NotTo(HaveOccurred())
		Expect(cur).To(Equal(1))
	})

	It("--heal-drift overrides refuse policy", func() {
		root := GinkgoT().TempDir()
		own := &schema.Ownership{
			Schema: "polypkg.ownership/v1", Scope: "user",
			Entries: []schema.OwnershipEntry{{
				Path: "hello/bin", Package: "hello", Version: "1.0.0", Action: "dir",
				Expected:    schema.Expected{FileType: "dir", Mode: "0755"},
				DriftPolicy: "refuse",
			}},
		}
		sub := stageGeneration(root, own)
		Expect(os.Chmod(filepath.Join(root, "generations/1/active/hello/bin"), 0o700)).To(Succeed())

		w, err := audit.NewFileWriter(filepath.Join(root, "audit.log"))
		Expect(err).NotTo(HaveOccurred())
		defer w.Close()
		r := New(Options{Substrate: sub, AuditWriter: w, Scope: "user",
			LockPath: filepath.Join(root, "apply.lock"), HealDrift: true})
		gen, err := r.Run(context.Background(),
			&schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}},
			nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(gen).To(Equal(2))
	})

	It("silent_heal suppresses the per-path drift.detected event", func() {
		root := GinkgoT().TempDir()
		own := &schema.Ownership{
			Schema: "polypkg.ownership/v1", Scope: "user",
			Entries: []schema.OwnershipEntry{{
				Path: "hello/bin", Package: "hello", Version: "1.0.0", Action: "dir",
				Expected:    schema.Expected{FileType: "dir", Mode: "0755"},
				DriftPolicy: "silent_heal",
			}},
		}
		sub := stageGeneration(root, own)
		Expect(os.Chmod(filepath.Join(root, "generations/1/active/hello/bin"), 0o700)).To(Succeed())

		auditPath := filepath.Join(root, "audit.log")
		w, err := audit.NewFileWriter(auditPath)
		Expect(err).NotTo(HaveOccurred())
		defer w.Close()
		r := New(Options{Substrate: sub, AuditWriter: w, Scope: "user",
			LockPath: filepath.Join(root, "apply.lock")})
		_, err = r.Run(context.Background(),
			&schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}},
			nil)
		Expect(err).NotTo(HaveOccurred())
		// The healed silent_heal entry must not produce a per-path drift.detected
		// event; only apply.start / apply.complete should be in the log.
		auditBytes, err := os.ReadFile(filepath.Clean(auditPath))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(auditBytes)).NotTo(ContainSubstring(`"drift.detected"`),
			"silent_heal+healed must suppress the per-path drift.detected event")
	})

	It("silent_heal with accepted action still emits drift.detected", func() {
		// A silent_heal path whose action is "accepted" (not "healed") must still
		// emit drift.detected. The suppression rule is narrow: silent_heal+healed only.
		root := GinkgoT().TempDir()
		own := &schema.Ownership{
			Schema: "polypkg.ownership/v1", Scope: "user",
			Entries: []schema.OwnershipEntry{{
				Path: "hello/bin", Package: "hello", Version: "1.0.0", Action: "dir",
				Expected:    schema.Expected{FileType: "dir", Mode: "0755"},
				DriftPolicy: "silent_heal",
			}},
		}
		sub := stageGeneration(root, own)
		Expect(os.Chmod(filepath.Join(root, "generations/1/active/hello/bin"), 0o700)).To(Succeed())

		// Write an accepted-drift overrides file that matches the observed mode.
		acceptedPath := filepath.Join(root, "accepted-drift.json")
		Expect(os.WriteFile(acceptedPath,
			[]byte(`{"schema":"polypkg.accepted-drift/v1","generation":1,"paths":{"hello/bin":{"expected":{"file_type":"dir","mode":"0700"},"stat":{"size":0,"mtime_ns":0,"inode":0}}}}`),
			0o600)).To(Succeed())

		auditPath := filepath.Join(root, "audit.log")
		w, err := audit.NewFileWriter(auditPath)
		Expect(err).NotTo(HaveOccurred())
		defer w.Close()
		r := New(Options{Substrate: sub, AuditWriter: w, Scope: "user",
			LockPath: filepath.Join(root, "apply.lock"), AcceptedDriftPath: acceptedPath})
		_, err = r.Run(context.Background(),
			&schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}},
			nil)
		Expect(err).NotTo(HaveOccurred())

		auditBytes, err := os.ReadFile(filepath.Clean(auditPath))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(auditBytes)).To(ContainSubstring(`"drift.detected"`),
			"silent_heal+accepted must still emit drift.detected (only silent_heal+healed is suppressed)")
		Expect(string(auditBytes)).To(ContainSubstring(`"accepted"`),
			"the audit event must record action_taken=accepted")
	})

	It("--no-drift-check skips inspection and applies", func() {
		root := GinkgoT().TempDir()
		own := &schema.Ownership{
			Schema: "polypkg.ownership/v1", Scope: "user",
			Entries: []schema.OwnershipEntry{{
				Path: "hello/bin", Package: "hello", Version: "1.0.0", Action: "dir",
				Expected:    schema.Expected{FileType: "dir", Mode: "0755"},
				DriftPolicy: "refuse",
			}},
		}
		sub := stageGeneration(root, own)
		Expect(os.Chmod(filepath.Join(root, "generations/1/active/hello/bin"), 0o700)).To(Succeed())

		w, err := audit.NewFileWriter(filepath.Join(root, "audit.log"))
		Expect(err).NotTo(HaveOccurred())
		defer w.Close()
		r := New(Options{Substrate: sub, AuditWriter: w, Scope: "user",
			LockPath: filepath.Join(root, "apply.lock"), NoDriftCheck: true})
		gen, err := r.Run(context.Background(),
			&schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}},
			nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(gen).To(Equal(2))
	})
})

package substrate

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// commitGen commits one generation through a fresh transaction.
func commitGen(s *OwnStore, txID string) int {
	Expect(s.BeginTransaction(txID)).To(Succeed())
	m := &schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}}
	gen, err := s.CommitGeneration(txID, m, emptyOwnership(), nil)
	Expect(err).NotTo(HaveOccurred())
	return gen
}

// leaveCrashedGen begins a transaction on a separate store handle and never
// commits or aborts it: exactly the generations/<n>/active/ skeleton a
// SIGKILLed or power-lost apply leaves behind. It returns the generation id.
func leaveCrashedGen(root string) int {
	crashed, err := NewOwnStore(root)
	Expect(err).NotTo(HaveOccurred())
	Expect(crashed.BeginTransaction("tx-crashed")).To(Succeed())
	staging, err := crashed.StagingRoot("tx-crashed")
	Expect(err).NotTo(HaveOccurred())
	Expect(os.WriteFile(filepath.Join(staging, "partial"), []byte("x"), 0o600)).To(Succeed())
	return crashed.pending["tx-crashed"]
}

var _ = Describe("incomplete generations", func() {
	It("ListGenerations marks a missing manifest incomplete and a present but unusable one damaged", func() {
		root := GinkgoT().TempDir()
		s, err := NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		commitGen(s, "tx-1")
		Expect(leaveCrashedGen(root)).To(Equal(2))
		// Commits rename the manifest into place only after fsyncing it, so a
		// crash leaves it missing, never torn. Present but unusable bytes mean
		// corruption or tampering.
		for id, body := range map[int]string{
			3: "",                                 // empty
			4: "not json",                         // garbage
			5: `{"schema":"polypkg.manifest/v2"}`, // schema-invalid
		} {
			dir := filepath.Join(root, "generations", strconv.Itoa(id))
			Expect(os.MkdirAll(filepath.Join(dir, "active"), 0o700)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(body), 0o600)).To(Succeed())
		}

		gens, err := s.ListGenerations()
		Expect(err).NotTo(HaveOccurred())
		byID := map[int]GenInfo{}
		for _, g := range gens {
			byID[g.ID] = g
		}
		Expect(byID).To(HaveLen(5))
		Expect(byID[1]).To(SatisfyAll(HaveField("Incomplete", false), HaveField("Damaged", false)))
		Expect(byID[2]).To(SatisfyAll(HaveField("Incomplete", true), HaveField("Damaged", false)))
		for _, id := range []int{3, 4, 5} {
			Expect(byID[id]).To(SatisfyAll(HaveField("Incomplete", false), HaveField("Damaged", true)), "generation %d", id)
			_, rerr := s.ReadManifest(id)
			Expect(errors.Is(rerr, ErrDamagedGeneration)).To(BeTrue(), "generation %d: %v", id, rerr)
			Expect(errors.Is(rerr, ErrIncompleteGeneration)).To(BeFalse(), "generation %d", id)
		}
		_, rerr := s.ReadManifest(2)
		Expect(errors.Is(rerr, ErrIncompleteGeneration)).To(BeTrue(), "got %v", rerr)
		Expect(errors.Is(rerr, ErrDamagedGeneration)).To(BeFalse())
	})

	It("Rollback and PinGeneration refuse a damaged generation with ErrDamagedGeneration", func() {
		root := GinkgoT().TempDir()
		s, err := NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		commitGen(s, "tx-1")
		commitGen(s, "tx-2")
		Expect(os.WriteFile(filepath.Join(root, "generations", "1", "manifest.json"), []byte("not json"), 0o600)).To(Succeed())

		err = s.Rollback(1)
		Expect(errors.Is(err, ErrDamagedGeneration)).To(BeTrue(), "got %v", err)
		Expect(errors.Is(err, ErrIncompleteGeneration)).To(BeFalse())
		err = s.PinGeneration(1, "keep")
		Expect(errors.Is(err, ErrDamagedGeneration)).To(BeTrue(), "got %v", err)
		cur, err := s.CurrentGeneration()
		Expect(err).NotTo(HaveOccurred())
		Expect(cur).To(Equal(2))
	})

	It("writes a parseable manifest even when the caller passes nil entries", func() {
		root := GinkgoT().TempDir()
		s, err := NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		Expect(s.BeginTransaction("tx-1")).To(Succeed())
		m := &schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user"}
		gen, err := s.CommitGeneration("tx-1", m, emptyOwnership(), nil)
		Expect(err).NotTo(HaveOccurred())

		got, err := s.ReadManifest(gen)
		Expect(err).NotTo(HaveOccurred(), "the manifest is the completeness marker, so it must always parse")
		Expect(got.Entries).To(BeEmpty())
		Expect(m.Entries).To(BeNil(), "the caller's manifest must not be mutated")
	})

	It("Rollback refuses an incomplete generation and leaves active untouched", func() {
		root := GinkgoT().TempDir()
		s, err := NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		commitGen(s, "tx-1")
		crashedID := leaveCrashedGen(root)
		commitGen(s, "tx-3")

		err = s.Rollback(crashedID)
		Expect(errors.Is(err, ErrIncompleteGeneration)).To(BeTrue(), "got %v", err)
		cur, cerr := s.CurrentGeneration()
		Expect(cerr).NotTo(HaveOccurred())
		Expect(cur).To(Equal(3))
	})

	It("Rollback still reports a missing generation as not existing", func() {
		root := GinkgoT().TempDir()
		s, err := NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		commitGen(s, "tx-1")

		err = s.Rollback(99)
		Expect(errors.Is(err, fs.ErrNotExist)).To(BeTrue(), "got %v", err)
		Expect(errors.Is(err, ErrIncompleteGeneration)).To(BeFalse())
	})

	// An unreadable manifest is not proof of an interrupted apply: EACCES, EIO
	// or EMFILE can hit a complete generation. Reporting it incomplete would let
	// gc delete a valid generation, so the error must surface instead.
	Context("when a manifest exists but cannot be read", func() {
		var (
			root string
			s    *OwnStore
		)
		BeforeEach(func() {
			if os.Getuid() == 0 {
				Skip("root reads a mode-000 file, so the read error cannot be provoked")
			}
			root = GinkgoT().TempDir()
			var err error
			s, err = NewOwnStore(root)
			Expect(err).NotTo(HaveOccurred())
			commitGen(s, "tx-1")
			commitGen(s, "tx-2")
			manifest := filepath.Join(root, "generations", "1", "manifest.json")
			Expect(os.Chmod(manifest, 0)).To(Succeed())
			DeferCleanup(func() { _ = os.Chmod(manifest, 0o600) })
		})

		It("ListGenerations returns the error rather than marking the generation incomplete", func() {
			_, err := s.ListGenerations()
			Expect(err).To(HaveOccurred())
			Expect(errors.Is(err, fs.ErrPermission)).To(BeTrue(), "got %v", err)
		})

		It("Rollback reports the read error, not ErrIncompleteGeneration", func() {
			err := s.Rollback(1)
			Expect(err).To(HaveOccurred())
			Expect(errors.Is(err, ErrIncompleteGeneration)).To(BeFalse(), "got %v", err)
			Expect(errors.Is(err, fs.ErrPermission)).To(BeTrue(), "got %v", err)
			cur, cerr := s.CurrentGeneration()
			Expect(cerr).NotTo(HaveOccurred())
			Expect(cur).To(Equal(2))
		})
	})

	// The manifest records the id of the generation it vouches for, so a
	// manifest that ends up in another generation's directory (a copy, a
	// botched restore) does not make that directory look complete.
	Context("generation id stamping", func() {
		It("stamps the committed generation id, whatever the caller set, without mutating the caller", func() {
			root := GinkgoT().TempDir()
			s, err := NewOwnStore(root)
			Expect(err).NotTo(HaveOccurred())
			Expect(s.BeginTransaction("tx-1")).To(Succeed())
			m := &schema.Manifest{Schema: "polypkg.manifest/v2", Generation: 7, Scope: "user", Entries: []schema.ManifestEntry{}}
			gen, err := s.CommitGeneration("tx-1", m, emptyOwnership(), nil)
			Expect(err).NotTo(HaveOccurred())

			got, err := s.ReadManifest(gen)
			Expect(err).NotTo(HaveOccurred())
			Expect(got.Generation).To(Equal(gen))
			Expect(m.Generation).To(Equal(7), "the caller's manifest must not be mutated")
		})

		It("treats a manifest copied into another generation's directory as damaged", func() {
			root := GinkgoT().TempDir()
			s, err := NewOwnStore(root)
			Expect(err).NotTo(HaveOccurred())
			commitGen(s, "tx-1")
			commitGen(s, "tx-2")
			gen3 := filepath.Join(root, "generations", "3")
			Expect(os.MkdirAll(filepath.Join(gen3, "active"), 0o700)).To(Succeed())
			for _, name := range []string{"manifest.json", "ownership.json"} {
				data, rerr := os.ReadFile(filepath.Join(root, "generations", "1", name))
				Expect(rerr).NotTo(HaveOccurred())
				Expect(os.WriteFile(filepath.Join(gen3, name), data, 0o600)).To(Succeed())
			}

			_, err = s.ReadManifest(3)
			Expect(errors.Is(err, ErrDamagedGeneration)).To(BeTrue(), "got %v", err)
			gens, err := s.ListGenerations()
			Expect(err).NotTo(HaveOccurred())
			for _, g := range gens {
				Expect(g.Damaged).To(Equal(g.ID == 3), "generation %d", g.ID)
				Expect(g.Incomplete).To(BeFalse(), "generation %d", g.ID)
			}
			Expect(errors.Is(s.Rollback(3), ErrDamagedGeneration)).To(BeTrue())
			cur, err := s.CurrentGeneration()
			Expect(err).NotTo(HaveOccurred())
			Expect(cur).To(Equal(2))
		})

		It("accepts an unstamped (generation 0) manifest written by an older binary", func() {
			root := GinkgoT().TempDir()
			s, err := NewOwnStore(root)
			Expect(err).NotTo(HaveOccurred())
			commitGen(s, "tx-1")
			path := filepath.Join(root, "generations", "1", "manifest.json")
			m, err := s.ReadManifest(1)
			Expect(err).NotTo(HaveOccurred())
			m.Generation = 0
			data, err := json.Marshal(m)
			Expect(err).NotTo(HaveOccurred())
			Expect(os.WriteFile(path, data, 0o600)).To(Succeed())

			_, err = s.ReadManifest(1)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	// os.RemoveAll is not atomic. Interrupted part-way, it could leave
	// manifest.json over a half-deleted payload, which would look complete.
	// Removal therefore deletes the manifest durably before anything else.
	Context("removing a generation invalidates its manifest first", func() {
		// failSyncOnceManifestGone makes fsync of dir fail once its manifest
		// has been removed: the interruption point right after invalidation.
		failSyncOnceManifestGone := func(s *OwnStore, dir string) {
			s.fsync = func(f *os.File) error {
				if f.Name() == dir {
					if _, err := os.Stat(filepath.Join(dir, "manifest.json")); errors.Is(err, fs.ErrNotExist) {
						return errors.New("injected EIO")
					}
				}
				return f.Sync()
			}
		}

		It("RemoveGeneration leaves an incomplete generation when interrupted after the manifest removal", func() {
			root := GinkgoT().TempDir()
			s, err := NewOwnStore(root)
			Expect(err).NotTo(HaveOccurred())
			commitGen(s, "tx-1")
			commitGen(s, "tx-2")
			gen1 := filepath.Join(root, "generations", "1")
			failSyncOnceManifestGone(s, gen1)

			Expect(s.RemoveGeneration(1)).To(MatchError(ContainSubstring("injected EIO")))
			gens, err := s.ListGenerations()
			Expect(err).NotTo(HaveOccurred())
			Expect(gens).To(ContainElement(SatisfyAll(
				HaveField("ID", 1), HaveField("Incomplete", true))))
			Expect(errors.Is(s.Rollback(1), ErrIncompleteGeneration)).To(BeTrue())
			cur, err := s.CurrentGeneration()
			Expect(err).NotTo(HaveOccurred())
			Expect(cur).To(Equal(2))
		})

		It("Abort leaves an incomplete generation when interrupted after the manifest removal", func() {
			root := GinkgoT().TempDir()
			s, err := NewOwnStore(root)
			Expect(err).NotTo(HaveOccurred())
			commitGen(s, "tx-1")
			Expect(s.BeginTransaction("tx-2")).To(Succeed())
			gen2 := filepath.Join(root, "generations", "2")
			// Fail the commit after its manifest is in place, so Abort has a
			// complete-looking directory to remove.
			s.fsync = func(f *os.File) error {
				if f.Name() == gen2 {
					if _, err := os.Stat(filepath.Join(gen2, "manifest.json")); err == nil {
						return errors.New("injected commit EIO")
					}
				}
				return f.Sync()
			}
			m := &schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}}
			_, err = s.CommitGeneration("tx-2", m, emptyOwnership(), nil)
			Expect(err).To(MatchError(ContainSubstring("injected commit EIO")))
			failSyncOnceManifestGone(s, gen2)

			Expect(s.Abort("tx-2")).To(MatchError(ContainSubstring("injected EIO")))
			_, err = s.ReadManifest(2)
			Expect(errors.Is(err, ErrIncompleteGeneration)).To(BeTrue(), "got %v", err)
			Expect(errors.Is(s.Rollback(2), ErrIncompleteGeneration)).To(BeTrue())
			cur, err := s.CurrentGeneration()
			Expect(err).NotTo(HaveOccurred())
			Expect(cur).To(Equal(1))
		})

		It("Abort of a staged generation whose directory is already gone succeeds", func() {
			root := GinkgoT().TempDir()
			s, err := NewOwnStore(root)
			Expect(err).NotTo(HaveOccurred())
			Expect(s.BeginTransaction("tx-1")).To(Succeed())
			Expect(os.RemoveAll(filepath.Join(root, "generations", "1"))).To(Succeed())
			Expect(s.Abort("tx-1")).To(Succeed())
		})
	})

	It("PinGeneration refuses an incomplete generation and writes no pin", func() {
		root := GinkgoT().TempDir()
		s, err := NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		commitGen(s, "tx-1")
		crashedID := leaveCrashedGen(root)

		err = s.PinGeneration(crashedID, "keep")
		Expect(errors.Is(err, ErrIncompleteGeneration)).To(BeTrue(), "got %v", err)
		_, statErr := os.Stat(filepath.Join(root, "generations", strconv.Itoa(crashedID), "pin.json"))
		Expect(errors.Is(statErr, fs.ErrNotExist)).To(BeTrue(), "an incomplete generation must not be pinned")
	})
})

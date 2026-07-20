package substrate

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func emptyOwnership() *schema.Ownership {
	return &schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user", Entries: []schema.OwnershipEntry{}}
}

var _ = Describe("ActiveDesktopDir", func() {
	It("is <root>/active/applications", func() {
		root := GinkgoT().TempDir()
		s, err := NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		Expect(s.ActiveDesktopDir()).To(Equal(filepath.Join(root, "active", "applications")))
	})
})

var _ = Describe("ActiveCompletionsDir", func() {
	It("is <root>/active/completions", func() {
		root := GinkgoT().TempDir()
		s, err := NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		Expect(s.ActiveCompletionsDir()).To(Equal(filepath.Join(root, "active", "completions")))
	})
})

var _ = Describe("ActiveMimeDir", func() {
	It("is <root>/active/mime", func() {
		root := GinkgoT().TempDir()
		s, err := NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		Expect(s.ActiveMimeDir()).To(Equal(filepath.Join(root, "active", "mime")))
	})
})

var _ = Describe("ActiveManDir", func() {
	It("is <root>/active/man", func() {
		root := GinkgoT().TempDir()
		s, err := NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		Expect(s.ActiveManDir()).To(Equal(filepath.Join(root, "active", "man")))
	})
})

var _ = Describe("alternatives area", func() {
	It("exposes a stable alternatives root path, created lazily (absent at open)", func() {
		dir := GinkgoT().TempDir()
		sub, err := NewOwnStore(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(sub.AltRoot()).To(Equal(filepath.Join(dir, "alternatives")))
		_, statErr := os.Stat(sub.AltRoot())
		Expect(os.IsNotExist(statErr)).To(BeTrue(), "alternatives area is created on first materialize, not at open")
	})

	It("reports ActiveBinDir as <root>/active/bin", func() {
		dir := GinkgoT().TempDir()
		s, err := NewOwnStore(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(s.ActiveBinDir()).To(Equal(filepath.Join(dir, "active", "bin")))
	})
})

var _ = Describe("state area", func() {
	It("reports StateRoot (created lazily) and purges by package", func() {
		dir := GinkgoT().TempDir()
		s, err := NewOwnStore(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(s.StateRoot()).To(Equal(filepath.Join(dir, "state")))
		_, statErr := os.Stat(filepath.Join(dir, "state"))
		Expect(os.IsNotExist(statErr)).To(BeTrue(), "state area is created on demand, not at open")

		pkgState := filepath.Join(dir, "state", "hello", "var", "lib")
		Expect(os.MkdirAll(pkgState, 0o700)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(pkgState, "db"), []byte("x"), 0o600)).To(Succeed())

		Expect(s.PurgeState("hello")).To(Succeed())
		_, statErr = os.Stat(filepath.Join(dir, "state", "hello"))
		Expect(os.IsNotExist(statErr)).To(BeTrue())

		// Idempotent: purging an absent package's state is a nil success.
		Expect(s.PurgeState("nope")).To(Succeed())
	})
})

var _ = Describe("PurgeState rejects unsafe package names", func() {
	It("refuses traversal and separator names without deleting anything outside state/<pkg>", func() {
		dir := GinkgoT().TempDir()
		s, err := NewOwnStore(dir)
		Expect(err).NotTo(HaveOccurred())
		// Seed a sibling generations dir and a second package's state to prove they survive.
		Expect(os.MkdirAll(filepath.Join(dir, "generations", "1"), 0o700)).To(Succeed())
		Expect(os.MkdirAll(filepath.Join(dir, "state", "other"), 0o700)).To(Succeed())

		for _, bad := range []string{"..", "../generations", "../../..", "a/b", "/etc", "", ".", "x/../.."} {
			Expect(s.PurgeState(bad)).NotTo(Succeed(), "expected %q to be rejected", bad)
		}
		// Nothing outside state/<pkg> was touched.
		_, e1 := os.Stat(filepath.Join(dir, "generations", "1"))
		Expect(e1).NotTo(HaveOccurred())
		_, e2 := os.Stat(filepath.Join(dir, "state", "other"))
		Expect(e2).NotTo(HaveOccurred())
		_, e3 := os.Stat(dir) // substrate root still exists
		Expect(e3).NotTo(HaveOccurred())
	})

	It("still purges a valid package name", func() {
		dir := GinkgoT().TempDir()
		s, err := NewOwnStore(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.MkdirAll(filepath.Join(dir, "state", "hello", "x"), 0o700)).To(Succeed())
		Expect(s.PurgeState("hello")).To(Succeed())
		_, statErr := os.Stat(filepath.Join(dir, "state", "hello"))
		Expect(os.IsNotExist(statErr)).To(BeTrue())
		Expect(s.PurgeState("hello")).To(Succeed()) // idempotent
	})
})

var _ = Describe("OwnStore", func() {
	Describe("CommitGeneration", func() {
		It("writes ownership.json under the committed generation", func() {
			root := GinkgoT().TempDir()
			s, err := NewOwnStore(root)
			Expect(err).NotTo(HaveOccurred())
			Expect(s.BeginTransaction("tx-1")).To(Succeed())

			m := &schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}}
			own := &schema.Ownership{
				Schema: "polypkg.ownership/v1", Scope: "user",
				Entries: []schema.OwnershipEntry{{
					Path: "hello/bin/hi", Package: "hello", Version: "1.0.0", Action: "install",
					Expected:    schema.Expected{FileType: "symlink", ContentHash: "blake3:abc"},
					DriftPolicy: "notify_heal", Stat: schema.StatInfo{Size: 1, MtimeNs: 2, Inode: 3},
				}},
			}
			gen, err := s.CommitGeneration("tx-1", m, own, nil)
			Expect(err).NotTo(HaveOccurred())

			f, err := os.Open(filepath.Join(root, "generations", strconv.Itoa(gen), "ownership.json"))
			Expect(err).NotTo(HaveOccurred())
			defer f.Close()
			got, err := schema.ParseOwnership(f)
			Expect(err).NotTo(HaveOccurred())
			Expect(got.Entries).To(HaveLen(1))
			Expect(got.Entries[0].Path).To(Equal("hello/bin/hi"))
		})

		It("returns generation 1 and points active at it", func() {
			root := GinkgoT().TempDir()
			s, err := NewOwnStore(root)
			Expect(err).NotTo(HaveOccurred())

			m := &schema.Manifest{
				Schema:     "polypkg.manifest/v2",
				Generation: 1,
				Scope:      "user",
				Entries:    []schema.ManifestEntry{},
			}
			Expect(s.BeginTransaction("tx-1")).To(Succeed())
			gen, err := s.CommitGeneration("tx-1", m, emptyOwnership(), nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(gen).To(Equal(1))

			active := filepath.Join(root, "active")
			target, err := os.Readlink(active)
			Expect(err).NotTo(HaveOccurred())
			Expect(target).To(ContainSubstring("generations/1"))
		})

		It("keeps a committed generation alive across a late Abort of its transaction", func() {
			root := GinkgoT().TempDir()
			s, err := NewOwnStore(root)
			Expect(err).NotTo(HaveOccurred())

			m := &schema.Manifest{Schema: "polypkg.manifest/v2", Generation: 1, Scope: "user"}
			Expect(s.BeginTransaction("tx-1")).To(Succeed())
			gen, err := s.CommitGeneration("tx-1", m, emptyOwnership(), nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(gen).To(Equal(1))

			target, err := os.Readlink(filepath.Join(root, "active"))
			Expect(err).NotTo(HaveOccurred())
			Expect(target).To(ContainSubstring("generations/1"))

			// A late Abort of the now-committed tx must be a no-op and must NOT delete
			// the live generation directory (the data-corruption scenario).
			Expect(s.Abort("tx-1")).To(Succeed())
			_, err = os.Stat(filepath.Join(root, "generations", "1", "active"))
			Expect(err).NotTo(HaveOccurred(), "committed generation must survive a post-commit Abort")

			cur, err := s.CurrentGeneration()
			Expect(err).NotTo(HaveOccurred())
			Expect(cur).To(Equal(1))
		})

		It("reports the live active symlink, ignoring a stale current-gen file", func() {
			root := GinkgoT().TempDir()
			s, err := NewOwnStore(root)
			Expect(err).NotTo(HaveOccurred())

			m1 := &schema.Manifest{Schema: "polypkg.manifest/v2", Generation: 1, Scope: "user"}
			Expect(s.BeginTransaction("tx-1")).To(Succeed())
			_, err = s.CommitGeneration("tx-1", m1, emptyOwnership(), nil)
			Expect(err).NotTo(HaveOccurred())

			m2 := &schema.Manifest{Schema: "polypkg.manifest/v2", Generation: 2, Scope: "user"}
			Expect(s.BeginTransaction("tx-2")).To(Succeed())
			_, err = s.CommitGeneration("tx-2", m2, emptyOwnership(), nil)
			Expect(err).NotTo(HaveOccurred())

			// active now points at gen 2. Plant a stale, readable current-gen file
			// naming gen 1 — the situation a failed cache write (or a crash between
			// the swap and the cache write) leaves behind. CurrentGeneration must
			// trust the authoritative active symlink, not the stale file; otherwise
			// GC would treat the live generation as non-current and could delete it.
			Expect(os.WriteFile(filepath.Join(root, "current-gen"), []byte("1"), 0o600)).To(Succeed())

			cur, err := s.CurrentGeneration()
			Expect(err).NotTo(HaveOccurred())
			Expect(cur).To(Equal(2), "must reflect the live active symlink, not a stale current-gen file")
		})

		It("writes content-addressed config-base snapshots and dedupes identical bytes", func() {
			dir := GinkgoT().TempDir()
			s, err := NewOwnStore(dir)
			Expect(err).NotTo(HaveOccurred())
			Expect(s.BeginTransaction("tx-1")).To(Succeed())
			m := &schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user"}
			bases := map[string][]byte{
				"blake3:aa": []byte("same\n"),
				"blake3:bb": []byte("same\n"),
			}
			gen, err := s.CommitGeneration("tx-1", m, emptyOwnership(), bases)
			Expect(err).NotTo(HaveOccurred())

			genDir := filepath.Join(dir, "generations", strconv.Itoa(gen))
			aa := filepath.Join(genDir, schema.ConfigBaseRelPath("blake3:aa"))
			bb := filepath.Join(genDir, schema.ConfigBaseRelPath("blake3:bb"))
			gotAA, err := os.ReadFile(aa)
			Expect(err).NotTo(HaveOccurred())
			Expect(gotAA).To(Equal([]byte("same\n")))
			gotBB, err := os.ReadFile(bb)
			Expect(err).NotTo(HaveOccurred())
			Expect(gotBB).To(Equal([]byte("same\n")))
		})
	})

	Describe("Abort", func() {
		It("leaves no active symlink when no prior commits exist", func() {
			root := GinkgoT().TempDir()
			s, err := NewOwnStore(root)
			Expect(err).NotTo(HaveOccurred())

			Expect(s.BeginTransaction("tx-1")).To(Succeed())
			Expect(s.Abort("tx-1")).To(Succeed())

			active := filepath.Join(root, "active")
			_, err = os.Readlink(active)
			Expect(err).To(HaveOccurred(), "active should not exist after abort with no prior commits")
		})
	})

	Describe("Rollback", func() {
		It("repoints active at the requested earlier generation", func() {
			root := GinkgoT().TempDir()
			s, err := NewOwnStore(root)
			Expect(err).NotTo(HaveOccurred())

			m1 := &schema.Manifest{Schema: "polypkg.manifest/v2", Generation: 1, Scope: "user"}
			m2 := &schema.Manifest{Schema: "polypkg.manifest/v2", Generation: 2, Scope: "user"}

			Expect(s.BeginTransaction("tx-1")).To(Succeed())
			_, err = s.CommitGeneration("tx-1", m1, emptyOwnership(), nil)
			Expect(err).NotTo(HaveOccurred())

			Expect(s.BeginTransaction("tx-2")).To(Succeed())
			_, err = s.CommitGeneration("tx-2", m2, emptyOwnership(), nil)
			Expect(err).NotTo(HaveOccurred())

			Expect(s.Rollback(1)).To(Succeed())

			active := filepath.Join(root, "active")
			target, err := os.Readlink(active)
			Expect(err).NotTo(HaveOccurred())
			Expect(target).To(ContainSubstring("generations/1"))
		})
	})

	Describe("CurrentOwnership", func() {
		It("returns ErrNoCurrentGeneration when there are no commits", func() {
			root := GinkgoT().TempDir()
			s, err := NewOwnStore(root)
			Expect(err).NotTo(HaveOccurred())
			_, _, _, err = s.CurrentOwnership()
			Expect(err).To(MatchError(ErrNoCurrentGeneration))
		})

		It("returns the committed index and active staging root", func() {
			root := GinkgoT().TempDir()
			s, err := NewOwnStore(root)
			Expect(err).NotTo(HaveOccurred())
			Expect(s.BeginTransaction("tx-1")).To(Succeed())
			m := &schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}}
			own := &schema.Ownership{
				Schema: "polypkg.ownership/v1", Scope: "user",
				Entries: []schema.OwnershipEntry{{
					Path: "hello/bin/hi", Package: "hello", Version: "1.0.0", Action: "install",
					Expected:    schema.Expected{FileType: "symlink", ContentHash: "blake3:abc"},
					DriftPolicy: "notify_heal", Stat: schema.StatInfo{Size: 1, MtimeNs: 2, Inode: 3},
				}},
			}
			gen, err := s.CommitGeneration("tx-1", m, own, nil)
			Expect(err).NotTo(HaveOccurred())

			gotOwn, gotGen, activeRoot, err := s.CurrentOwnership()
			Expect(err).NotTo(HaveOccurred())
			Expect(gotOwn.Schema).To(Equal("polypkg.ownership/v1"))
			Expect(gotOwn.Entries).To(HaveLen(1))
			Expect(gotOwn.Entries[0].Path).To(Equal("hello/bin/hi"))
			Expect(gotGen).To(Equal(gen))
			Expect(activeRoot).To(Equal(filepath.Join(root, "generations", strconv.Itoa(gen), "active")))
		})
	})

	Describe("ListGenerations", func() {
		It("reports pinned, current, committed-at and bytes-on-disk", func() {
			root := GinkgoT().TempDir()
			s, err := NewOwnStore(root)
			Expect(err).NotTo(HaveOccurred())

			m := &schema.Manifest{
				Schema: "polypkg.manifest/v2", Scope: "user",
				Entries: []schema.ManifestEntry{},
				ProducedBy: schema.ProducedBy{
					Tool: "polypkg", Version: "test", Host: "h",
					Timestamp: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
				},
			}
			own := &schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user"}

			Expect(s.BeginTransaction("t1")).To(Succeed())
			_, err = s.CommitGeneration("t1", m, own, nil)
			Expect(err).NotTo(HaveOccurred())

			m2 := *m
			m2.ProducedBy.Timestamp = time.Date(2026, 5, 10, 0, 0, 0, 0, time.UTC)
			Expect(s.BeginTransaction("t2")).To(Succeed())
			_, err = s.CommitGeneration("t2", &m2, own, nil)
			Expect(err).NotTo(HaveOccurred())

			// Pin generation 1 by hand to confirm ListGenerations sees the pin.
			pin := &schema.Pin{
				Schema: "polypkg.pin/v1", Generation: 1,
				PinnedAt: time.Now().UTC(), PinnedBy: "test", PinnedReason: "fixture",
			}
			pinData, err := json.MarshalIndent(pin, "", "  ")
			Expect(err).NotTo(HaveOccurred())
			Expect(os.WriteFile(
				filepath.Join(root, "generations", "1", "pin.json"), pinData, 0o600)).To(Succeed())

			gens, err := s.ListGenerations()
			Expect(err).NotTo(HaveOccurred())
			Expect(gens).To(HaveLen(2))

			byID := map[int]GenInfo{}
			for _, g := range gens {
				byID[g.ID] = g
			}
			g1, g2 := byID[1], byID[2]

			Expect(g1.Pinned).To(BeTrue())
			Expect(g1.PinnedReason).To(Equal("fixture"))
			Expect(g1.IsCurrent).To(BeFalse())
			Expect(g1.CommittedAt.IsZero()).To(BeFalse())

			Expect(g2.Pinned).To(BeFalse())
			Expect(g2.IsCurrent).To(BeTrue())
			Expect(g2.CommittedAt.IsZero()).To(BeFalse())

			Expect(g1.BytesOnDisk).To(BeNumerically(">=", int64(0)))
			Expect(g2.BytesOnDisk).To(BeNumerically(">=", int64(0)))
		})
	})

	Describe("ReadManifest", func() {
		var store *OwnStore

		BeforeEach(func() {
			root := GinkgoT().TempDir()
			var err error
			store, err = NewOwnStore(root)
			Expect(err).NotTo(HaveOccurred())
			m := &schema.Manifest{
				Schema: "polypkg.manifest/v2", Scope: "user",
				Entries: []schema.ManifestEntry{{
					Name: "hello", Version: "1.0.0", ContentHash: "blake3:abc123",
				}},
				ProducedBy: schema.ProducedBy{Tool: "polypkg", Version: "test", Host: "h",
					Timestamp: time.Now().UTC()},
			}
			Expect(store.BeginTransaction("t1")).To(Succeed())
			_, err = store.CommitGeneration("t1", m, emptyOwnership(), nil)
			Expect(err).NotTo(HaveOccurred())
		})

		It("reads a retained generation's manifest by id", func() {
			m, err := store.ReadManifest(1)
			Expect(err).NotTo(HaveOccurred())
			Expect(m.Entries).NotTo(BeEmpty())
			Expect(m.Entries[0].Name).To(Equal("hello"))
		})

		It("errors on a missing generation", func() {
			_, err := store.ReadManifest(9999)
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("PinGeneration", func() {
		It("writes pin.json, refuses re-pin, refuses missing gen", func() {
			root := GinkgoT().TempDir()
			s, err := NewOwnStore(root)
			Expect(err).NotTo(HaveOccurred())

			m := &schema.Manifest{
				Schema: "polypkg.manifest/v2", Scope: "user",
				Entries: []schema.ManifestEntry{},
				ProducedBy: schema.ProducedBy{Tool: "polypkg", Version: "test", Host: "h",
					Timestamp: time.Now().UTC()},
			}
			Expect(s.BeginTransaction("t1")).To(Succeed())
			_, err = s.CommitGeneration("t1", m, &schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user"}, nil)
			Expect(err).NotTo(HaveOccurred())

			// Happy path: pin gen 1 with a reason.
			Expect(s.PinGeneration(1, "baseline before deploy")).To(Succeed())

			pinPath := filepath.Join(root, "generations", "1", "pin.json")
			data, err := os.ReadFile(pinPath)
			Expect(err).NotTo(HaveOccurred())
			p, err := schema.ParsePin(bytes.NewReader(data))
			Expect(err).NotTo(HaveOccurred())
			Expect(p.Generation).To(Equal(1))
			Expect(p.PinnedReason).To(Equal("baseline before deploy"))
			Expect(p.PinnedBy).NotTo(BeEmpty())
			Expect(p.PinnedAt.IsZero()).To(BeFalse())

			// Idempotency: re-pinning an already-pinned gen is an error.
			Expect(s.PinGeneration(1, "another reason")).To(HaveOccurred())

			// Nonexistent gen: error.
			Expect(s.PinGeneration(99, "")).To(HaveOccurred())
		})
	})

	Describe("UnpinGeneration", func() {
		It("removes pin.json, is a no-op when not pinned, errors on missing gen", func() {
			root := GinkgoT().TempDir()
			s, err := NewOwnStore(root)
			Expect(err).NotTo(HaveOccurred())

			m := &schema.Manifest{
				Schema: "polypkg.manifest/v2", Scope: "user",
				Entries: []schema.ManifestEntry{},
				ProducedBy: schema.ProducedBy{Tool: "polypkg", Version: "test", Host: "h",
					Timestamp: time.Now().UTC()},
			}
			Expect(s.BeginTransaction("t1")).To(Succeed())
			_, err = s.CommitGeneration("t1", m, &schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user"}, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(s.PinGeneration(1, "x")).To(Succeed())

			pinPath := filepath.Join(root, "generations", "1", "pin.json")
			_, err = os.Stat(pinPath)
			Expect(err).NotTo(HaveOccurred(), "pin.json should exist after PinGeneration")

			// Unpin removes the file.
			Expect(s.UnpinGeneration(1)).To(Succeed())
			_, err = os.Stat(pinPath)
			Expect(os.IsNotExist(err)).To(BeTrue(), "pin.json should be gone after UnpinGeneration")

			// Unpin a non-pinned gen is a no-op success.
			Expect(s.UnpinGeneration(1)).To(Succeed())

			// Unpin a nonexistent gen errors.
			Expect(s.UnpinGeneration(99)).To(HaveOccurred())
		})
	})

	Describe("RemoveGeneration", func() {
		It("refuses current, refuses pinned, removes eligible, errors on missing", func() {
			root := GinkgoT().TempDir()
			s, err := NewOwnStore(root)
			Expect(err).NotTo(HaveOccurred())

			mk := func(tx string) {
				m := &schema.Manifest{
					Schema: "polypkg.manifest/v2", Scope: "user",
					Entries: []schema.ManifestEntry{},
					ProducedBy: schema.ProducedBy{Tool: "polypkg", Version: "test", Host: "h",
						Timestamp: time.Now().UTC()},
				}
				Expect(s.BeginTransaction(tx)).To(Succeed())
				_, err := s.CommitGeneration(tx, m, &schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user"}, nil)
				Expect(err).NotTo(HaveOccurred())
			}
			mk("a") // gen 1
			mk("b") // gen 2 (current after this commit)
			mk("c") // gen 3 (current after this commit)

			// Refuse the current generation explicitly.
			err = s.RemoveGeneration(3)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("current"))

			// Refuse a pinned generation.
			Expect(s.PinGeneration(2, "keep")).To(Succeed())
			err = s.RemoveGeneration(2)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("pinned"))

			// Unpinned, non-current gen: removed.
			Expect(s.RemoveGeneration(1)).To(Succeed())
			_, err = os.Stat(filepath.Join(root, "generations", "1"))
			Expect(os.IsNotExist(err)).To(BeTrue(), "generations/1 should be gone")

			// Nonexistent gen: error.
			Expect(s.RemoveGeneration(99)).To(HaveOccurred())
		})
	})
})

var _ = Describe("read-only operations on a store with no generations dir", func() {
	// freshBare returns an OwnStore whose root has NO generations/ directory,
	// simulating a never-applied substrate (and the post-Task-2 open behavior).
	freshBare := func() (*OwnStore, string) {
		dir := GinkgoT().TempDir()
		s, err := NewOwnStore(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.RemoveAll(filepath.Join(dir, "generations"))).To(Succeed())
		return s, dir
	}

	It("ListGenerations returns empty (not an error) when generations/ is absent", func() {
		s, _ := freshBare()
		gens, err := s.ListGenerations()
		Expect(err).NotTo(HaveOccurred())
		Expect(gens).To(BeEmpty())
	})

	It("the first BeginTransaction succeeds (gen 1) when generations/ is absent", func() {
		s, dir := freshBare()
		Expect(s.BeginTransaction("tx-1")).To(Succeed())
		staging, err := s.StagingRoot("tx-1")
		Expect(err).NotTo(HaveOccurred())
		Expect(staging).To(Equal(filepath.Join(dir, "generations", "1", "active")))
	})
})

var _ = Describe("NewOwnStore is side-effect-free", func() {
	It("creates no directories under root when opened", func() {
		root := GinkgoT().TempDir()
		_, err := NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		entries, rerr := os.ReadDir(root)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(entries).To(BeEmpty(), "opening a substrate must not create any subdirectories")
	})

	It("CurrentOwnership on a fresh store reports no generation and creates nothing", func() {
		root := GinkgoT().TempDir()
		s, err := NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		_, _, _, oerr := s.CurrentOwnership()
		Expect(oerr).To(MatchError(ErrNoCurrentGeneration))
		entries, rerr := os.ReadDir(root)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(entries).To(BeEmpty())
	})
})

var _ = Describe("GenerationIDs", func() {
	writeGenDir := func(root string, id int) {
		genDir := filepath.Join(root, "generations", strconv.Itoa(id))
		Expect(os.MkdirAll(genDir, 0o700)).To(Succeed())
	}

	It("enumerates numeric generation directory names and ignores the rest", func() {
		root := GinkgoT().TempDir()
		s, err := NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		writeGenDir(root, 3)
		writeGenDir(root, 1)
		writeGenDir(root, 2)
		// Non-numeric dir and a stray file must be ignored.
		Expect(os.MkdirAll(filepath.Join(root, "generations", "scratch"), 0o700)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(root, "generations", "README"), []byte("x"), 0o600)).To(Succeed())

		ids, err := s.GenerationIDs()
		Expect(err).NotTo(HaveOccurred())
		sort.Ints(ids)
		Expect(ids).To(Equal([]int{1, 2, 3}))
	})

	It("returns an empty slice (no error) when generations/ does not exist", func() {
		root := GinkgoT().TempDir()
		s, err := NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		ids, err := s.GenerationIDs()
		Expect(err).NotTo(HaveOccurred())
		Expect(ids).To(Equal([]int{}))
	})

	It("does not require a parseable manifest to enumerate an id", func() {
		root := GinkgoT().TempDir()
		s, err := NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		writeGenDir(root, 7) // no manifest.json at all
		ids, err := s.GenerationIDs()
		Expect(err).NotTo(HaveOccurred())
		Expect(ids).To(Equal([]int{7}))
	})
})

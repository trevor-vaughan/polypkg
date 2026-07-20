package trust

import (
	"os"
	"path/filepath"
	"sort"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Seen", func() {
	It("returns zero on first read (trust-on-first-use) and roundtrips after store", func() {
		dir := GinkgoT().TempDir()

		s, err := LoadSeen(dir, "native")
		Expect(err).NotTo(HaveOccurred())
		Expect(s).To(Equal(Seen{}))

		Expect(StoreSeen(dir, "native", Seen{TrustSerial: 7, IndexSerial: 42})).To(Succeed())
		got, err := LoadSeen(dir, "native")
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(Seen{TrustSerial: 7, IndexSerial: 42}))
	})

	It("round-trips the per-package version high-water marks", func() {
		dir := GinkgoT().TempDir()
		s := Seen{
			TrustSerial: 3,
			IndexSerial: 4,
			Packages:    map[string]string{"hello": "2.0.0", "lib": "1.4.7"},
		}
		Expect(StoreSeen(dir, "native", s)).To(Succeed())
		got, err := LoadSeen(dir, "native")
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(s))
	})

	It("isolates state per source", func() {
		dir := GinkgoT().TempDir()
		Expect(StoreSeen(dir, "native", Seen{TrustSerial: 1, IndexSerial: 1})).To(Succeed())
		Expect(StoreSeen(dir, "rpm", Seen{TrustSerial: 9, IndexSerial: 9})).To(Succeed())
		a, err := LoadSeen(dir, "native")
		Expect(err).NotTo(HaveOccurred())
		b, err := LoadSeen(dir, "rpm")
		Expect(err).NotTo(HaveOccurred())
		Expect(a.TrustSerial).To(Equal(uint64(1)))
		Expect(b.TrustSerial).To(Equal(uint64(9)))
	})
})

var _ = Describe("Seen bundle/revocation serials", func() {
	It("round-trips BundleSerial and RevocationSerial through Store/Load", func() {
		dir := GinkgoT().TempDir()
		want := Seen{
			TrustSerial:      7,
			IndexSerial:      9,
			BundleSerial:     4,
			RevocationSerial: 2,
			Packages:         map[string]string{"hello": "1.2.0"},
		}
		Expect(StoreSeen(dir, "native", want)).To(Succeed())

		got, err := LoadSeen(dir, "native")
		Expect(err).NotTo(HaveOccurred())
		Expect(got.BundleSerial).To(Equal(uint64(4)))
		Expect(got.RevocationSerial).To(Equal(uint64(2)))
	})

	It("defaults the new serials to zero for a pre-existing state file without them", func() {
		dir := GinkgoT().TempDir()
		Expect(os.MkdirAll(filepath.Join(dir, "trust"), 0o700)).To(Succeed())
		legacy := []byte(`{"trust_serial":3,"index_serial":5}`)
		Expect(os.WriteFile(filepath.Join(dir, "trust", "native.json"), legacy, 0o600)).To(Succeed())

		got, err := LoadSeen(dir, "native")
		Expect(err).NotTo(HaveOccurred())
		Expect(got.TrustSerial).To(Equal(uint64(3)))
		Expect(got.BundleSerial).To(Equal(uint64(0)))
		Expect(got.RevocationSerial).To(Equal(uint64(0)))
	})
})

var _ = Describe("ForgetSeen", func() {
	It("deletes the source's persisted state so a re-add is a fresh TOFU baseline", func() {
		dir := GinkgoT().TempDir()
		Expect(StoreSeen(dir, "native", Seen{TrustSerial: 5, BundleSerial: 3})).To(Succeed())

		Expect(ForgetSeen(dir, "native")).To(Succeed())

		got, err := LoadSeen(dir, "native")
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(Seen{})) // zeroed ⇒ never-seen
	})

	It("is a no-op (no error) when the source has no persisted state", func() {
		dir := GinkgoT().TempDir()
		Expect(ForgetSeen(dir, "never-stored")).To(Succeed())
	})
})

var _ = Describe("Seen grace marker", func() {
	It("round-trips a SeenGrace through StoreSeen/LoadSeen", func() {
		dir := GinkgoT().TempDir()
		in := Seen{
			TrustSerial: 3, IndexSerial: 4,
			Graced: &SeenGrace{AcceptUntil: "2999-01-01T00:00:00Z", Docs: []string{"index", "trust document"}},
		}
		Expect(StoreSeen(dir, "native", in)).To(Succeed())
		got, err := LoadSeen(dir, "native")
		Expect(err).NotTo(HaveOccurred())
		Expect(got.Graced).NotTo(BeNil())
		Expect(got.Graced.AcceptUntil).To(Equal("2999-01-01T00:00:00Z"))
		Expect(got.Graced.Docs).To(Equal([]string{"index", "trust document"}))
	})

	It("omits graced from the file and reloads nil when unset", func() {
		dir := GinkgoT().TempDir()
		Expect(StoreSeen(dir, "native", Seen{TrustSerial: 1, IndexSerial: 1})).To(Succeed())
		raw, err := os.ReadFile(filepath.Join(dir, "trust", "native.json"))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(raw)).NotTo(ContainSubstring("graced"))
		got, err := LoadSeen(dir, "native")
		Expect(err).NotTo(HaveOccurred())
		Expect(got.Graced).To(BeNil())
	})

	It("clears a prior grace marker when an ungraced Seen is stored over it", func() {
		dir := GinkgoT().TempDir()
		Expect(StoreSeen(dir, "native", Seen{Graced: &SeenGrace{AcceptUntil: "2999-01-01T00:00:00Z", Docs: []string{"index"}}})).To(Succeed())
		Expect(StoreSeen(dir, "native", Seen{TrustSerial: 2})).To(Succeed())
		got, err := LoadSeen(dir, "native")
		Expect(err).NotTo(HaveOccurred())
		Expect(got.Graced).To(BeNil())
	})
})

var _ = Describe("Seen revoked builder keys", func() {
	It("round-trips RevokedBuilderKeys and clears them on an overwrite with none", func() {
		dir := GinkgoT().TempDir()
		Expect(StoreSeen(dir, "native", Seen{RevokedBuilderKeys: []string{"builder-a", "builder-b"}})).To(Succeed())
		got, err := LoadSeen(dir, "native")
		Expect(err).NotTo(HaveOccurred())
		Expect(got.RevokedBuilderKeys).To(Equal([]string{"builder-a", "builder-b"}))
		Expect(StoreSeen(dir, "native", Seen{TrustSerial: 2})).To(Succeed())
		got, err = LoadSeen(dir, "native")
		Expect(err).NotTo(HaveOccurred())
		Expect(got.RevokedBuilderKeys).To(BeEmpty())
	})
})

var _ = Describe("Revocations.RevokedBuilderKeyIDs", func() {
	It("is nil-safe on a nil receiver", func() {
		var r *Revocations
		Expect(r.RevokedBuilderKeyIDs()).To(BeNil())
	})
})

var _ = Describe("ListSeenSources", func() {
	It("lists source names from <stateHome>/trust/*.json and ignores the rest", func() {
		dir := GinkgoT().TempDir()
		Expect(StoreSeen(dir, "native", Seen{TrustSerial: 1})).To(Succeed())
		Expect(StoreSeen(dir, "rpm", Seen{TrustSerial: 1})).To(Succeed())
		trustDir := filepath.Join(dir, "trust")
		Expect(os.WriteFile(filepath.Join(trustDir, "notes.txt"), []byte("x"), 0o600)).To(Succeed())
		Expect(os.MkdirAll(filepath.Join(trustDir, "sub"), 0o700)).To(Succeed())
		got, err := ListSeenSources(dir)
		Expect(err).NotTo(HaveOccurred())
		sort.Strings(got)
		Expect(got).To(Equal([]string{"native", "rpm"}))
	})

	It("returns empty (no error) when the trust dir does not exist", func() {
		got, err := ListSeenSources(GinkgoT().TempDir())
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(BeEmpty())
	})
})

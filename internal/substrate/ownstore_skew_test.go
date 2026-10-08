package substrate

import (
	"errors"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("OwnStore version skew", func() {
	var (
		root string
		s    *OwnStore
	)

	BeforeEach(func() {
		root = GinkgoT().TempDir()
		var err error
		s, err = NewOwnStore(root)
		Expect(err).NotTo(HaveOccurred())
		m := &schema.Manifest{Schema: "polypkg.manifest/v2", Generation: 1, Scope: "user", Entries: []schema.ManifestEntry{}}
		Expect(s.BeginTransaction("t1")).To(Succeed())
		_, err = s.CommitGeneration("t1", m, emptyOwnership(), nil)
		Expect(err).NotTo(HaveOccurred())
	})

	writeGenFile := func(name, body string) string {
		GinkgoHelper()
		p := filepath.Join(root, "generations", "1", name)
		Expect(os.WriteFile(p, []byte(body), 0o600)).To(Succeed())
		return p
	}

	It("CurrentOwnership names ownership.json when a newer polypkg wrote it", func() {
		p := writeGenFile("ownership.json", `{"schema":"polypkg.ownership/v2","scope":"user","entries":[]}`)
		_, _, _, err := s.CurrentOwnership()
		var ne *schema.NewerSchemaError
		Expect(errors.As(err, &ne)).To(BeTrue(), "got %v", err)
		Expect(ne.Path).To(Equal(p))
	})

	It("ReadManifest names manifest.json when a newer polypkg wrote it", func() {
		p := writeGenFile("manifest.json", `{"schema":"polypkg.manifest/v3"}`)
		_, err := s.ReadManifest(1)
		var ne *schema.NewerSchemaError
		Expect(errors.As(err, &ne)).To(BeTrue(), "got %v", err)
		Expect(ne.Path).To(Equal(p))
	})

	It("ReadManifest reports a newer manifest as neither damaged nor incomplete", func() {
		// A newer polypkg's manifest is not corruption: calling it damaged
		// would tell the operator to inspect it and delete it by hand.
		writeGenFile("manifest.json", `{"schema":"polypkg.manifest/v3"}`)
		_, err := s.ReadManifest(1)
		Expect(errors.Is(err, ErrDamagedGeneration)).To(BeFalse(), "got %v", err)
		Expect(errors.Is(err, ErrIncompleteGeneration)).To(BeFalse(), "got %v", err)
	})

	It("ReadManifest still reports a manifest of the current version that fails its schema as damaged", func() {
		writeGenFile("manifest.json", `{"schema":"polypkg.manifest/v2","bogus":1}`)
		_, err := s.ReadManifest(1)
		Expect(errors.Is(err, ErrDamagedGeneration)).To(BeTrue(), "got %v", err)
		var ne *schema.NewerSchemaError
		Expect(errors.As(err, &ne)).To(BeFalse())
	})

	It("ListGenerations fails naming a newer manifest rather than listing it, so gc removes nothing", func() {
		// Neither Incomplete (gc would remove it) nor Damaged (gc would tell
		// the operator to delete it by hand): this binary cannot judge the
		// generation at all.
		p := writeGenFile("manifest.json", `{"schema":"polypkg.manifest/v3"}`)
		gens, err := s.ListGenerations()
		Expect(gens).To(BeNil())
		var ne *schema.NewerSchemaError
		Expect(errors.As(err, &ne)).To(BeTrue(), "got %v", err)
		Expect(ne.Path).To(Equal(p))
	})

	It("Rollback and PinGeneration refuse a newer generation", func() {
		Expect(s.BeginTransaction("t2")).To(Succeed())
		_, err := s.CommitGeneration("t2", &schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}}, emptyOwnership(), nil)
		Expect(err).NotTo(HaveOccurred())
		writeGenFile("manifest.json", `{"schema":"polypkg.manifest/v3"}`)
		var ne *schema.NewerSchemaError
		Expect(errors.As(s.Rollback(1), &ne)).To(BeTrue())
		Expect(errors.As(s.PinGeneration(1, "keep"), &ne)).To(BeTrue())
		Expect(filepath.Join(root, "generations", "1", "pin.json")).NotTo(BeAnExistingFile())
	})

	It("ListGenerations honours a pin a newer polypkg wrote", func() {
		writeGenFile("pin.json", `{"schema":"polypkg.pin/v2","generation":1}`)
		gens, err := s.ListGenerations()
		Expect(err).NotTo(HaveOccurred())
		Expect(gens).To(HaveLen(1))
		Expect(gens[0].Pinned).To(BeTrue(), "gc must not collect a generation a newer polypkg pinned")
	})

	It("ListGenerations still treats a corrupt pin.json as unpinned", func() {
		writeGenFile("pin.json", `{not json`)
		gens, err := s.ListGenerations()
		Expect(err).NotTo(HaveOccurred())
		Expect(gens).To(HaveLen(1))
		Expect(gens[0].Pinned).To(BeFalse())
	})
})

package cli

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

var _ = Describe("pin/unpin command errors", func() {
	setup := func() (string, string) {
		dir := sandboxUserEnv(GinkgoTB())
		return dir, filepath.Join(dir, "data", "polypkg")
	}

	// makeGen1State creates a minimal generation-1 substrate so that the
	// substrate opens and CurrentGeneration returns 1; generation 999 is
	// therefore nonexistent.
	makeGen1State := func(storeRoot string) {
		gen1Dir := filepath.Join(storeRoot, "generations", "1", "active")
		Expect(os.MkdirAll(gen1Dir, 0o700)).To(Succeed())
		activeLink := filepath.Join(storeRoot, "active")
		Expect(os.Symlink(filepath.Join("generations", "1", "active"), activeLink)).To(Succeed())
		own := filepath.Join(storeRoot, "generations", "1", "ownership.json")
		Expect(os.WriteFile(own,
			[]byte(`{"schema":"polypkg.ownership/v1","scope":"user","entries":[]}`),
			0o600)).To(Succeed())
	}

	It("pin returns CLIError for non-numeric generation id", func() {
		setup()
		root := NewRootCmd()
		root.SetArgs([]string{"generation", "pin", "abc"})
		err := root.Execute()
		Expect(err).To(HaveOccurred())
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(cliErr.Msg).To(ContainSubstring(`invalid generation id "abc"`))
		Expect(cliErr.Msg).To(ContainSubstring("expected a number"))
		Expect(cliErr.Hint).To(Equal("run `polypkg status -v` to list generation ids"))
	})

	It("unpin returns CLIError for non-numeric generation id", func() {
		setup()
		root := NewRootCmd()
		root.SetArgs([]string{"generation", "unpin", "abc"})
		err := root.Execute()
		Expect(err).To(HaveOccurred())
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(cliErr.Msg).To(ContainSubstring(`invalid generation id "abc"`))
		Expect(cliErr.Msg).To(ContainSubstring("expected a number"))
		Expect(cliErr.Hint).To(Equal("run `polypkg status -v` to list generation ids"))
	})

	It("pin returns CLIError for nonexistent numeric generation id", func() {
		_, storeRoot := setup()
		makeGen1State(storeRoot)
		root := NewRootCmd()
		root.SetArgs([]string{"generation", "pin", "999"})
		err := root.Execute()
		Expect(err).To(HaveOccurred())
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(cliErr.Msg).To(ContainSubstring("generation 999 does not exist"))
		Expect(cliErr.Msg).NotTo(ContainSubstring("stat "), "syscall text must not leak to user")
		Expect(cliErr.Hint).To(ContainSubstring("polypkg status -v"))
		Expect(cliErr.Err).NotTo(BeNil(), "wrapped cause must be preserved")
	})

	It("unpin returns CLIError for nonexistent numeric generation id", func() {
		_, storeRoot := setup()
		makeGen1State(storeRoot)
		root := NewRootCmd()
		root.SetArgs([]string{"generation", "unpin", "999"})
		err := root.Execute()
		Expect(err).To(HaveOccurred())
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(cliErr.Msg).To(ContainSubstring("generation 999 does not exist"))
		Expect(cliErr.Msg).NotTo(ContainSubstring("stat "), "syscall text must not leak to user")
		Expect(cliErr.Hint).To(ContainSubstring("polypkg status -v"))
		Expect(cliErr.Err).NotTo(BeNil(), "wrapped cause must be preserved")
	})

	It("pin refuses an incomplete generation with a CLIError pointing at gc", func() {
		_, storeRoot := setup()
		makeGen1State(storeRoot)
		// generations/2 is the skeleton an interrupted apply leaves: no manifest.
		Expect(os.MkdirAll(filepath.Join(storeRoot, "generations", "2", "active"), 0o700)).To(Succeed())

		root := NewRootCmd()
		root.SetArgs([]string{"generation", "pin", "2"})
		err := root.Execute()
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(cliErr.Msg).To(Equal("generation 2 is incomplete: an interrupted apply left it without a manifest, so it cannot be pinned"))
		Expect(cliErr.Hint).To(ContainSubstring("polypkg gc"))
		Expect(errors.Is(cliErr.Err, substrate.ErrIncompleteGeneration)).To(BeTrue())
		_, statErr := os.Stat(filepath.Join(storeRoot, "generations", "2", "pin.json"))
		Expect(os.IsNotExist(statErr)).To(BeTrue())
	})

	It("pin refuses a damaged generation with its own CLIError, without pointing at gc", func() {
		_, storeRoot := setup()
		makeGen1State(storeRoot)
		Expect(os.WriteFile(filepath.Join(storeRoot, "generations", "1", "manifest.json"), []byte("not json"), 0o600)).To(Succeed())

		root := NewRootCmd()
		root.SetArgs([]string{"generation", "pin", "1"})
		err := root.Execute()
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(cliErr.Msg).To(Equal("generation 1's manifest is damaged: it does not parse or names another generation, so it cannot be pinned"))
		Expect(cliErr.Hint).NotTo(ContainSubstring("polypkg gc"))
		Expect(errors.Is(cliErr.Err, substrate.ErrDamagedGeneration)).To(BeTrue())
	})

	It("pin reports an unreadable manifest as a CLIError about permissions", func() {
		if os.Getuid() == 0 {
			Skip("root reads a mode-000 file, so the read error cannot be provoked")
		}
		_, storeRoot := setup()
		sub, err := substrate.New("store", storeRoot)
		Expect(err).NotTo(HaveOccurred())
		Expect(sub.BeginTransaction("tx-1")).To(Succeed())
		m := &schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}}
		_, err = sub.CommitGeneration("tx-1", m, &schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user"}, nil)
		Expect(err).NotTo(HaveOccurred())
		manifest := filepath.Join(storeRoot, "generations", "1", "manifest.json")
		Expect(os.Chmod(manifest, 0)).To(Succeed())
		DeferCleanup(func() { _ = os.Chmod(manifest, 0o600) })

		root := NewRootCmd()
		root.SetArgs([]string{"generation", "pin", "1"})
		err = root.Execute()
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(cliErr.Msg).To(Equal("cannot read generation 1's manifest"))
		Expect(cliErr.Hint).To(ContainSubstring(manifest))
		Expect(errors.Is(cliErr.Err, fs.ErrPermission)).To(BeTrue(), "got %v", cliErr.Err)
		_, statErr := os.Stat(filepath.Join(storeRoot, "generations", "1", "pin.json"))
		Expect(os.IsNotExist(statErr)).To(BeTrue())
	})
})

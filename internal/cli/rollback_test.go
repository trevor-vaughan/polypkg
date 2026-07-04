package cli

import (
	"errors"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("rollback command errors", func() {
	setup := func() (string, string) {
		dir := GinkgoT().TempDir()
		GinkgoT().Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
		GinkgoT().Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
		return dir, filepath.Join(dir, "data", "polypkg")
	}

	// makeGen1State creates a minimal generation-1 substrate under storeRoot so
	// that CurrentGeneration returns 1 (target = 1-1 = 0 → "first generation").
	// The active symlink is the authoritative source of truth for the current
	// generation, so it is all the substrate needs.
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

	It("returns a CLIError with hint when no generation has been applied", func() {
		setup()
		root := NewRootCmd()
		root.SetArgs([]string{"rollback"})
		err := root.Execute()
		Expect(err).To(HaveOccurred())
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(cliErr.Msg).To(Equal("nothing to roll back: no generation has been applied yet"))
		Expect(cliErr.Hint).To(Equal("run `polypkg apply` first"))
	})

	It("returns a CLIError with status hint when current generation is 1 (first generation)", func() {
		_, storeRoot := setup()
		makeGen1State(storeRoot)
		root := NewRootCmd()
		root.SetArgs([]string{"rollback"})
		err := root.Execute()
		Expect(err).To(HaveOccurred())
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(cliErr.Msg).To(Equal("nothing to roll back: this is the first generation"))
		Expect(cliErr.Hint).To(ContainSubstring("polypkg status -v"))
	})

	It("rollback --to returns CLIError for nonexistent numeric generation id", func() {
		_, storeRoot := setup()
		makeGen1State(storeRoot)
		root := NewRootCmd()
		root.SetArgs([]string{"rollback", "--to", "999"})
		err := root.Execute()
		Expect(err).To(HaveOccurred())
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(cliErr.Msg).To(ContainSubstring("generation 999 does not exist"))
		Expect(cliErr.Msg).NotTo(ContainSubstring("stat "), "syscall text must not leak to user")
		Expect(cliErr.Hint).To(ContainSubstring("polypkg status -v"))
		Expect(cliErr.Err).NotTo(BeNil(), "wrapped cause must be preserved")
	})
})

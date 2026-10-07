package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/alternatives"
	"github.com/trevor-vaughan/polypkg/internal/lock"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

var _ = Describe("rollback command errors", func() {
	setup := func() (string, string) {
		dir := sandboxUserEnv(GinkgoTB())
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

// A crashed apply leaves generations/<n>/ without a manifest. rollback used
// to pick current-1 blindly and could activate it; it also took no lock, so a
// concurrent apply's GC could delete the target mid-switch.
var _ = Describe("rollback and incomplete generations", func() {
	var storeRoot, stateRoot string

	BeforeEach(func() {
		dir := sandboxUserEnv(GinkgoTB())
		storeRoot = filepath.Join(dir, "data", "polypkg")
		stateRoot = filepath.Join(dir, "state", "polypkg")
	})

	commit := func(txID string) {
		s, err := substrate.New("store", storeRoot)
		Expect(err).NotTo(HaveOccurred())
		Expect(s.BeginTransaction(txID)).To(Succeed())
		m := &schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}}
		_, err = s.CommitGeneration(txID, m, &schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user"}, nil)
		Expect(err).NotTo(HaveOccurred())
	}
	// crash leaves the next generation exactly as a SIGKILLed apply does:
	// BeginTransaction ran, CommitGeneration and Abort never did.
	crash := func() {
		s, err := substrate.New("store", storeRoot)
		Expect(err).NotTo(HaveOccurred())
		Expect(s.BeginTransaction("tx-crashed")).To(Succeed())
	}
	activeTarget := func() string {
		t, err := os.Readlink(filepath.Join(storeRoot, "active"))
		Expect(err).NotTo(HaveOccurred())
		return t
	}
	runRollbackCmd := func(args ...string) (string, error) {
		var out bytes.Buffer
		root := NewRootCmd()
		root.SetArgs(append([]string{"rollback"}, args...))
		root.SetOut(&out)
		root.SetErr(&out)
		err := root.Execute()
		return out.String(), err
	}

	It("skips an incomplete generation and activates the newest complete older one", func() {
		commit("tx-1")
		crash() // gen 2
		commit("tx-3")

		out, err := runRollbackCmd()
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(out).To(ContainSubstring("rolled back to generation 1"))
		Expect(activeTarget()).To(Equal(filepath.Join("generations", "1", "active")))
	})

	It("refuses an explicit incomplete target with a CLIError and leaves active untouched", func() {
		commit("tx-1")
		crash() // gen 2
		commit("tx-3")

		_, err := runRollbackCmd("--to", "2")
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(cliErr.Msg).To(Equal("generation 2 is incomplete: an interrupted apply left it without a manifest, so it cannot be activated"))
		Expect(cliErr.Hint).To(ContainSubstring("polypkg gc"))
		Expect(errors.Is(cliErr.Err, substrate.ErrIncompleteGeneration)).To(BeTrue())
		Expect(activeTarget()).To(Equal(filepath.Join("generations", "3", "active")))
	})

	It("refuses when no complete generation older than the current one is retained", func() {
		commit("tx-1")
		crash() // gen 2
		commit("tx-3")
		s, err := substrate.New("store", storeRoot)
		Expect(err).NotTo(HaveOccurred())
		Expect(s.RemoveGeneration(1)).To(Succeed())

		_, err = runRollbackCmd()
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(cliErr.Msg).To(Equal("nothing to roll back: no complete generation older than generation 3 is retained"))
		Expect(cliErr.Hint).To(ContainSubstring("polypkg status -v"))
		Expect(activeTarget()).To(Equal(filepath.Join("generations", "3", "active")))
	})

	It("reports an unreadable target manifest as a read error, not as incomplete", func() {
		if os.Getuid() == 0 {
			Skip("root reads a mode-000 file, so the read error cannot be provoked")
		}
		commit("tx-1")
		commit("tx-2")
		manifest := filepath.Join(storeRoot, "generations", "1", "manifest.json")
		Expect(os.Chmod(manifest, 0)).To(Succeed())
		DeferCleanup(func() { _ = os.Chmod(manifest, 0o600) })

		for _, args := range [][]string{{"--to", "1"}, {}} {
			_, err := runRollbackCmd(args...)
			Expect(err).To(HaveOccurred(), "args %v", args)
			Expect(errors.Is(err, substrate.ErrIncompleteGeneration)).To(BeFalse(), "args %v: %v", args, err)
			var cliErr *CLIError
			Expect(errors.As(err, &cliErr)).To(BeTrue(), "args %v: expected *CLIError, got %T: %v", args, err, err)
			Expect(cliErr.Msg).To(Equal("cannot read generation 1's manifest"), "args %v", args)
			Expect(cliErr.Hint).To(ContainSubstring("permissions"), "args %v", args)
			Expect(cliErr.Hint).To(ContainSubstring(manifest), "args %v", args)
			Expect(cliErr.Hint).NotTo(ContainSubstring("polypkg gc"), "args %v", args)
			Expect(errors.Is(cliErr.Err, fs.ErrPermission)).To(BeTrue(), "args %v: %v", args, cliErr.Err)
			Expect(activeTarget()).To(Equal(filepath.Join("generations", "2", "active")))
		}
	})

	It("refuses an explicit damaged target with its own CLIError, without pointing at gc", func() {
		commit("tx-1")
		commit("tx-2")
		Expect(os.WriteFile(filepath.Join(storeRoot, "generations", "1", "manifest.json"), []byte("not json"), 0o600)).To(Succeed())

		_, err := runRollbackCmd("--to", "1")
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(cliErr.Msg).To(Equal("generation 1's manifest is damaged: it does not parse or names another generation, so it cannot be activated"))
		Expect(cliErr.Hint).To(ContainSubstring(filepath.Join(storeRoot, "generations", "1")))
		Expect(cliErr.Hint).NotTo(ContainSubstring("polypkg gc"))
		Expect(errors.Is(cliErr.Err, substrate.ErrDamagedGeneration)).To(BeTrue())
		Expect(activeTarget()).To(Equal(filepath.Join("generations", "2", "active")))
	})

	It("skips a damaged generation for the default target and says so on stderr", func() {
		commit("tx-1")
		commit("tx-2")
		commit("tx-3")
		Expect(os.WriteFile(filepath.Join(storeRoot, "generations", "2", "manifest.json"), []byte("not json"), 0o600)).To(Succeed())

		var stdout, stderr bytes.Buffer
		root := NewRootCmd()
		root.SetArgs([]string{"rollback"})
		root.SetOut(&stdout)
		root.SetErr(&stderr)
		Expect(root.Execute()).To(Succeed(), stderr.String())
		Expect(activeTarget()).To(Equal(filepath.Join("generations", "1", "active")))
		Expect(stderr.String()).To(ContainSubstring("warning: skipping generation 2: its manifest is damaged"))
	})

	It("stops at the newest complete older generation without reading older manifests", func() {
		if os.Getuid() == 0 {
			Skip("root reads a mode-000 file, so the read error cannot be provoked")
		}
		commit("tx-1")
		commit("tx-2")
		commit("tx-3")
		manifest := filepath.Join(storeRoot, "generations", "1", "manifest.json")
		Expect(os.Chmod(manifest, 0)).To(Succeed())
		DeferCleanup(func() { _ = os.Chmod(manifest, 0o600) })

		out, err := runRollbackCmd()
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(activeTarget()).To(Equal(filepath.Join("generations", "2", "active")))
	})

	// The swap commits before rollback reads the activated generation's
	// ownership and reconciles alternatives. A failure there must say the
	// rollback itself happened, so the user re-runs a reconcile instead of
	// assuming the old generation is still live.
	It("reports a post-swap ownership read failure as a succeeded rollback", func() {
		commit("tx-1")
		commit("tx-2")
		Expect(os.WriteFile(filepath.Join(storeRoot, "generations", "1", "ownership.json"), []byte("not json"), 0o600)).To(Succeed())

		_, err := runRollbackCmd()
		Expect(err).To(MatchError(ContainSubstring("rollback to generation 1 succeeded but reading its ownership failed")))
		Expect(activeTarget()).To(Equal(filepath.Join("generations", "1", "active")),
			"the swap committed before the ownership read, so generation 1 is live")
	})

	It("reports a post-swap alternatives reconcile failure as a succeeded rollback", func() {
		commit("tx-1")
		commit("tx-2")
		selections := alternatives.SelectionsPath(filepath.Join(storeRoot, "state"))
		Expect(os.MkdirAll(filepath.Dir(selections), 0o700)).To(Succeed())
		Expect(os.WriteFile(selections, []byte("not json"), 0o600)).To(Succeed())

		_, err := runRollbackCmd()
		Expect(err).To(MatchError(ContainSubstring("rollback to generation 1 succeeded but reconciling alternatives failed")))
		Expect(err).To(MatchError(ContainSubstring("re-run apply or rollback to reconcile")))
		Expect(activeTarget()).To(Equal(filepath.Join("generations", "1", "active")),
			"the swap committed before the reconcile, so generation 1 is live")
	})

	It("fails fast naming the holder while another command holds the apply lock", func() {
		if os.Getuid() == 0 {
			Skip("flock EWOULDBLOCK tests do not apply when running as root")
		}
		commit("tx-1")
		commit("tx-2")
		lockPath := filepath.Join(stateRoot, "apply.lock")
		Expect(os.MkdirAll(stateRoot, 0o700)).To(Succeed())
		meta, err := json.Marshal(&lock.Metadata{PID: os.Getpid(), Command: "polypkg apply"})
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(lockPath, meta, 0o600)).To(Succeed())
		f, err := os.OpenFile(lockPath, os.O_RDWR, 0o600)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(f.Close)
		Expect(syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)).To(Succeed())
		DeferCleanup(func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) })

		_, err = runRollbackCmd()
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(cliErr.Msg).To(ContainSubstring("another polypkg command is already running"))
		Expect(cliErr.Msg).To(ContainSubstring("polypkg apply"))
		Expect(activeTarget()).To(Equal(filepath.Join("generations", "2", "active")),
			"rollback must not switch generations without the lock")
	})
})

var _ = Describe("rollback help", func() {
	It("says that rollback leaves the profile as it is", func() {
		Expect(newRollbackCmd().Long).To(ContainSubstring("rollback does not edit your profile"))
	})
})

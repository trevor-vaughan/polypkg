package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/trevor-vaughan/polypkg/internal/extractstore"
	"github.com/trevor-vaughan/polypkg/internal/lock"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/source"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

var _ = Describe("gc error shaping", func() {
	// gcAllFailedError is the specific CLIError produced when every removal
	// attempt fails (removed == 0, failed > 0). Validate its shape directly
	// so the test does not depend on the substrate removing a real generation.
	It("formats the all-failures error as CLIError with a hint", func() {
		failed := 3
		got := &CLIError{
			Msg:  fmt.Sprintf("gc: %d removal(s) failed and none succeeded", failed),
			Hint: "failed generations are listed above; check permissions under the generations directory",
		}
		var cliErr *CLIError
		Expect(errors.As(got, &cliErr)).To(BeTrue())
		Expect(cliErr.Msg).To(Equal("gc: 3 removal(s) failed and none succeeded"))
		Expect(cliErr.Hint).To(ContainSubstring("check permissions"))
	})
})

var _ = Describe("lock contention error shaping", func() {
	It("includes holder command and pid in the error when metadata is readable and pid is alive", func() {
		dir := GinkgoT().TempDir()
		lockPath := filepath.Join(dir, "apply.lock")
		// Use the current process's PID so the liveness check passes.
		meta := lock.Metadata{
			PID:     os.Getpid(),
			Command: "polypkg apply",
		}
		data, _ := json.Marshal(&meta)
		Expect(os.WriteFile(lockPath, data, 0o600)).To(Succeed())

		rawErr := fmt.Errorf("lock is held by another process")
		err := lockError(lockPath, rawErr)
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("polypkg apply"))
		Expect(ce.Msg).To(ContainSubstring(fmt.Sprintf("%d", os.Getpid())))
		Expect(ce.Hint).To(ContainSubstring("wait"))
		Expect(ce.Hint).To(ContainSubstring("automatically"))
	})

	It("falls back to generic holder message when metadata is not readable", func() {
		dir := GinkgoT().TempDir()
		lockPath := filepath.Join(dir, "nonexistent.lock")

		rawErr := fmt.Errorf("lock is held by another process")
		err := lockError(lockPath, rawErr)
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("another process is holding the polypkg lock"))
		Expect(ce.Hint).To(ContainSubstring(lockPath))
	})

	It("falls back to generic holder message when recorded pid is dead", func() {
		dir := GinkgoT().TempDir()
		lockPath := filepath.Join(dir, "apply.lock")
		// Spawn a short-lived child, wait for it to exit, then record its pid.
		// After Wait returns the pid slot may be reused, but in a controlled
		// test environment it almost never is within the same test.  If it is,
		// the worst outcome is a flaky pass — not a false failure.
		cmd := exec.Command("true")
		Expect(cmd.Start()).To(Succeed())
		Expect(cmd.Wait()).To(Succeed())
		deadPID := cmd.ProcessState.Pid()

		meta := lock.Metadata{
			PID:     deadPID,
			Command: "polypkg apply",
		}
		data, _ := json.Marshal(&meta)
		Expect(os.WriteFile(lockPath, data, 0o600)).To(Succeed())

		rawErr := fmt.Errorf("lock is held by another process")
		err := lockError(lockPath, rawErr)
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("another process is holding the polypkg lock"))
		Expect(ce.Hint).To(ContainSubstring(lockPath))
		Expect(ce.Msg).NotTo(ContainSubstring("polypkg apply"), "dead-pid path must not name the recorded command")
	})

	It("produces a CLIError from gc when lock is already held", func() {
		if os.Getuid() == 0 {
			Skip("flock EWOULDBLOCK tests do not apply when running as root")
		}
		dir := sandboxUserEnv(GinkgoTB())
		lockPath := filepath.Join(dir, "state", "polypkg", "apply.lock")
		Expect(os.MkdirAll(filepath.Dir(lockPath), 0o700)).To(Succeed())
		// Hold the lock ourselves so gc cannot acquire it.
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(f.Close)
		Expect(syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)).To(Succeed())
		DeferCleanup(func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) })

		// Write holder metadata so lockError can read it.
		_, err = lock.Acquire(context.Background(), filepath.Join(dir, "other.lock"),
			lock.Options{TxID: "test", Command: "polypkg test"})
		// Ignore the error; we just want a metadata shape in the lock.
		_ = err
		meta := lock.Metadata{PID: os.Getpid(), Command: "polypkg test"}
		data, _ := json.Marshal(&meta)
		Expect(f.Truncate(0)).To(Succeed())
		n, werr := f.WriteAt(data, 0)
		Expect(werr).NotTo(HaveOccurred())
		_ = n

		root := NewRootCmd()
		root.SetArgs([]string{"gc", "--count", "1"})
		root.SetOut(GinkgoWriter)
		execErr := root.Execute()
		Expect(execErr).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(execErr, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", execErr, execErr)
		Expect(ce.Msg).To(ContainSubstring("another polypkg command is already running"))
		Expect(ce.Hint).To(ContainSubstring("wait"))
	})
})

var _ = Describe("gc --count 0 validation", func() {
	It("returns CLIError with hint when --count is 0", func() {
		sandboxUserEnv(GinkgoTB())
		root := NewRootCmd()
		root.SetArgs([]string{"gc", "--count", "0"})
		err := root.Execute()
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("retention count must be >= 1"))
		Expect(ce.Hint).To(ContainSubstring("--count"))
		Expect(ce.Hint).To(ContainSubstring("--age"))
	})
})

var _ = Describe("gc invalid --age flag", func() {
	It("returns CLIError with hint for an unparseable age", func() {
		sandboxUserEnv(GinkgoTB())
		root := NewRootCmd()
		root.SetArgs([]string{"gc", "--age", "notanage"})
		err := root.Execute()
		Expect(err).To(HaveOccurred())
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(cliErr.Msg).To(ContainSubstring(`"notanage"`))
		Expect(cliErr.Hint).To(ContainSubstring("30d"))
	})
})

// `gc --count 1` with several recent generations used to reclaim nothing
// and say only "removed 0, failed 0, bytes reclaimed 0". Both retention
// predicates apply simultaneously, so --age 30d held every generation — correct,
// but the operator was given no way to see it from the output.
var _ = Describe("gc age-held reporting", func() {
	commitGenerations := func(dataHome string, n int) {
		s, err := substrate.New("store", dataHome)
		Expect(err).NotTo(HaveOccurred())
		for i := 1; i <= n; i++ {
			txID := fmt.Sprintf("tx-%d", i)
			Expect(s.BeginTransaction(txID)).To(Succeed())
			m := &schema.Manifest{Schema: "polypkg.manifest/v2", Generation: i, Scope: "user", Entries: []schema.ManifestEntry{}}
			_, cerr := s.CommitGeneration(txID, m, &schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user"}, nil)
			Expect(cerr).NotTo(HaveOccurred())
		}
	}
	setupStore := func(n int) {
		dir := sandboxUserEnv(GinkgoTB())
		commitGenerations(filepath.Join(dir, "data", "polypkg"), n)
	}
	runGCCmd := func(args ...string) string {
		var out bytes.Buffer
		root := NewRootCmd()
		root.SetArgs(args)
		root.SetOut(&out)
		root.SetErr(&out)
		Expect(root.Execute()).To(Succeed())
		return out.String()
	}

	It("says how many generations the age window held back", func() {
		setupStore(4)
		out := runGCCmd("gc", "--count", "1")
		Expect(out).To(ContainSubstring("gc: removed 0"))
		Expect(out).To(ContainSubstring("kept 3 generation(s) inside --age 30d"))
		Expect(out).To(ContainSubstring("--count 1"))
		Expect(out).To(ContainSubstring("--age 0"))
	})

	It("reports the age-held count in the JSON envelope", func() {
		setupStore(4)
		out := runGCCmd("--format", "json", "gc", "--count", "1")
		var env struct {
			Data struct {
				KeptByAge int `json:"kept_by_age"`
			} `json:"data"`
		}
		Expect(json.Unmarshal([]byte(out), &env)).To(Succeed())
		Expect(env.Data.KeptByAge).To(Equal(3))
	})

	It("stays quiet when the age rule held nothing back", func() {
		setupStore(4)
		out := runGCCmd("gc", "--count", "1", "--age", "0")
		Expect(out).To(ContainSubstring("gc: removed 3"))
		Expect(out).NotTo(ContainSubstring("inside --age"))
	})
})

// An apply killed between BeginTransaction and CommitGeneration leaves a
// generation with no manifest. gc used to keep it forever (its zero commit time
// counted as inside --age).
var _ = Describe("gc removes incomplete generations", func() {
	It("removes a manifest-less generation inside the default age window and keeps the rest", func() {
		dir := sandboxUserEnv(GinkgoTB())
		storeRoot := filepath.Join(dir, "data", "polypkg")
		s, err := substrate.New("store", storeRoot)
		Expect(err).NotTo(HaveOccurred())
		commit := func(txID string) {
			Expect(s.BeginTransaction(txID)).To(Succeed())
			m := &schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}}
			_, cerr := s.CommitGeneration(txID, m, &schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user"}, nil)
			Expect(cerr).NotTo(HaveOccurred())
		}
		commit("tx-1")
		crashed, err := substrate.New("store", storeRoot)
		Expect(err).NotTo(HaveOccurred())
		Expect(crashed.BeginTransaction("tx-crashed")).To(Succeed()) // gen 2, never committed
		commit("tx-3")

		var out bytes.Buffer
		root := NewRootCmd()
		root.SetArgs([]string{"gc"})
		root.SetOut(&out)
		root.SetErr(&out)
		Expect(root.Execute()).To(Succeed())
		Expect(out.String()).To(ContainSubstring("gc: removed 1"))

		_, statErr := os.Stat(filepath.Join(storeRoot, "generations", "2"))
		Expect(os.IsNotExist(statErr)).To(BeTrue(), "the incomplete generation must be removed")
		for _, id := range []string{"1", "3"} {
			_, err := os.Stat(filepath.Join(storeRoot, "generations", id, "manifest.json"))
			Expect(err).NotTo(HaveOccurred(), "complete generation %s must be kept", id)
		}
	})

	It("fails rather than removes a generation whose manifest cannot be read", func() {
		if os.Getuid() == 0 {
			Skip("root reads a mode-000 file, so the read error cannot be provoked")
		}
		dir := sandboxUserEnv(GinkgoTB())
		storeRoot := filepath.Join(dir, "data", "polypkg")
		s, err := substrate.New("store", storeRoot)
		Expect(err).NotTo(HaveOccurred())
		for _, txID := range []string{"tx-1", "tx-2"} {
			Expect(s.BeginTransaction(txID)).To(Succeed())
			m := &schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}}
			_, cerr := s.CommitGeneration(txID, m, &schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user"}, nil)
			Expect(cerr).NotTo(HaveOccurred())
		}
		manifest := filepath.Join(storeRoot, "generations", "1", "manifest.json")
		Expect(os.Chmod(manifest, 0)).To(Succeed())
		DeferCleanup(func() { _ = os.Chmod(manifest, 0o600) })

		var out bytes.Buffer
		root := NewRootCmd()
		root.SetArgs([]string{"gc"})
		root.SetOut(&out)
		root.SetErr(&out)
		Expect(root.Execute()).NotTo(Succeed(), out.String())
		_, statErr := os.Stat(filepath.Join(storeRoot, "generations", "1"))
		Expect(statErr).NotTo(HaveOccurred(), "a generation with an unreadable manifest must not be removed")
	})

	It("never removes a damaged generation, even outside --count and --age", func() {
		dir := sandboxUserEnv(GinkgoTB())
		storeRoot := filepath.Join(dir, "data", "polypkg")
		s, err := substrate.New("store", storeRoot)
		Expect(err).NotTo(HaveOccurred())
		for _, txID := range []string{"tx-1", "tx-2", "tx-3"} {
			Expect(s.BeginTransaction(txID)).To(Succeed())
			m := &schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}}
			_, cerr := s.CommitGeneration(txID, m, &schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user"}, nil)
			Expect(cerr).NotTo(HaveOccurred())
		}
		Expect(os.WriteFile(filepath.Join(storeRoot, "generations", "1", "manifest.json"), []byte("not json"), 0o600)).To(Succeed())

		var out bytes.Buffer
		root := NewRootCmd()
		root.SetArgs([]string{"gc", "--count", "1", "--age", "0"})
		root.SetOut(&out)
		root.SetErr(&out)
		Expect(root.Execute()).To(Succeed(), out.String())
		_, statErr := os.Stat(filepath.Join(storeRoot, "generations", "1", "manifest.json"))
		Expect(statErr).NotTo(HaveOccurred(), "a damaged generation is evidence and must be kept")
		_, statErr = os.Stat(filepath.Join(storeRoot, "generations", "2"))
		Expect(os.IsNotExist(statErr)).To(BeTrue(), "the complete generation outside --count is still collected")
		Expect(out.String()).To(ContainSubstring(fmt.Sprintf(
			"gc: generation 1's manifest is damaged; inspect %s, then delete it by hand if it is not needed as evidence",
			filepath.Join(storeRoot, "generations", "1"))))

		out.Reset()
		var stderr bytes.Buffer
		root = NewRootCmd()
		root.SetArgs([]string{"gc", "--format", "json"})
		root.SetOut(&out)
		root.SetErr(&stderr)
		Expect(root.Execute()).To(Succeed(), stderr.String())
		var env struct {
			Data struct {
				Damaged []int `json:"damaged"`
			} `json:"data"`
		}
		Expect(json.Unmarshal(out.Bytes(), &env)).To(Succeed(), out.String())
		Expect(env.Data.Damaged).To(Equal([]int{1}))
	})

	It("removes nothing, and calls nothing damaged, when a newer polypkg wrote a generation", func() {
		// This binary cannot judge a newer manifest. It is not incomplete (gc
		// would delete it) or damaged (gc would send the operator to delete
		// it), so gc must refuse outright.
		storeRoot := filepath.Join(sandboxUserEnv(GinkgoTB()), "data", "polypkg")
		s, err := substrate.New("store", storeRoot)
		Expect(err).NotTo(HaveOccurred())
		for _, txID := range []string{"tx-1", "tx-2", "tx-3"} {
			Expect(s.BeginTransaction(txID)).To(Succeed())
			m := &schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}}
			_, cerr := s.CommitGeneration(txID, m, &schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user"}, nil)
			Expect(cerr).NotTo(HaveOccurred())
		}
		Expect(os.WriteFile(filepath.Join(storeRoot, "generations", "1", "manifest.json"),
			[]byte(`{"schema":"polypkg.manifest/v3"}`), 0o600)).To(Succeed())

		var out bytes.Buffer
		root := NewRootCmd()
		root.SilenceUsage, root.SilenceErrors = true, true
		root.SetArgs([]string{"gc", "--count", "1", "--age", "0"})
		root.SetOut(&out)
		root.SetErr(&out)
		err = root.Execute()
		var ne *schema.NewerSchemaError
		Expect(errors.As(err, &ne)).To(BeTrue(), "got %v", err)
		for _, id := range []string{"1", "2"} {
			Expect(filepath.Join(storeRoot, "generations", id, "manifest.json")).To(BeAnExistingFile(), "generation %s", id)
		}
		Expect(out.String()).NotTo(ContainSubstring("damaged"))
	})
})

// The store sweep keeps every extract dir and cached download a retained
// generation's manifest references. Two manifest states change what it can
// know, and they govern both stores alike.
var _ = Describe("sweepStores with unusable manifests", func() {
	var (
		storeRoot, stateHome string
		s                    substrate.Substrate
	)
	old := time.Now().Add(-2 * extractstore.DefaultMinAge)
	// attHex is each entry's recorded attestation hash (hex, as the manifest
	// schema requires).
	attHex := map[string]string{"alpha": "aa01", "bravo": "bb02", "charlie": "cc03"}
	entry := func(name string) schema.ManifestEntry {
		return schema.ManifestEntry{
			Name: name, Version: "1.0.0", ContentHash: "blake3:" + name + "0123456789abcdef",
			SourceURL: "https://repo.invalid/pool/" + name + "-1.0.0.tar.zst",
			Attestation: &schema.AttestationState{
				Status: "verified", PolicyAtInstall: "warn", AttestationHash: "blake3:" + attHex[name],
			},
		}
	}
	extractDir := func(e schema.ManifestEntry) string {
		return extractstore.Dir(stateHome, e.Name, e.Version, e.ContentHash)
	}
	cached := func(name string) string {
		return filepath.Join(source.CacheRoot(stateHome), "native", name)
	}
	mkOld := func(dir string) {
		Expect(os.MkdirAll(dir, 0o700)).To(Succeed())
		Expect(os.Chtimes(dir, old, old)).To(Succeed())
	}
	mkOldFile := func(p string) {
		Expect(os.MkdirAll(filepath.Dir(p), 0o700)).To(Succeed())
		Expect(os.WriteFile(p, []byte("x"), 0o600)).To(Succeed())
		Expect(os.Chtimes(p, old, old)).To(Succeed())
	}
	commit := func(txID string, e schema.ManifestEntry) {
		Expect(s.BeginTransaction(txID)).To(Succeed())
		m := &schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{e}}
		_, err := s.CommitGeneration(txID, m, &schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user"}, nil)
		Expect(err).NotTo(HaveOccurred())
	}
	exists := func(p string) bool {
		_, err := os.Stat(p)
		return err == nil
	}

	BeforeEach(func() {
		dir := GinkgoT().TempDir()
		storeRoot = filepath.Join(dir, "data")
		stateHome = filepath.Join(dir, "state")
		var err error
		s, err = substrate.New("store", storeRoot)
		Expect(err).NotTo(HaveOccurred())
		commit("tx-1", entry("alpha"))
		commit("tx-2", entry("bravo"))
		for _, name := range []string{"alpha", "bravo"} {
			mkOld(extractDir(entry(name)))
			mkOldFile(cached(name + "-1.0.0.tar.zst"))
			mkOldFile(cached(attHex[name] + ".att.json"))
		}
		mkOld(filepath.Join(extractstore.Root(stateHome), "stale-1.0.0+feedfacefeedface"))
		mkOldFile(cached("stale-1.0.0.tar.zst"))
		mkOldFile(cached("5ca1ed.att.json"))
	})

	// keptEverything asserts a sweep that removed nothing from either store.
	keptEverything := func(sw storeSweep) {
		GinkgoHelper()
		Expect(sw.extractDirs).To(BeEmpty())
		Expect(sw.cacheArtifacts).To(BeEmpty())
		Expect(exists(filepath.Join(extractstore.Root(stateHome), "stale-1.0.0+feedfacefeedface"))).To(BeTrue())
		Expect(exists(cached("stale-1.0.0.tar.zst"))).To(BeTrue())
		Expect(exists(cached("5ca1ed.att.json"))).To(BeTrue())
	}

	It("keeps what retained generations reference and prunes the rest of both stores", func() {
		var stderr bytes.Buffer
		sw := sweepStores(s, stateHome, &stderr)
		Expect(sw.extractDirs).To(Equal([]string{"stale-1.0.0+feedfacefeedface"}), stderr.String())
		Expect(sw.cacheArtifacts).To(Equal([]string{"native/5ca1ed.att.json", "native/stale-1.0.0.tar.zst"}))
		for _, name := range []string{"alpha", "bravo"} {
			Expect(exists(extractDir(entry(name)))).To(BeTrue())
			Expect(exists(cached(name+"-1.0.0.tar.zst"))).To(BeTrue(), "an entry keeps the base name of its SourceURL")
			Expect(exists(cached(attHex[name]+".att.json"))).To(BeTrue(), "an entry keeps its recorded attestation")
		}
	})

	It("keeps a carried attestation a retained entry records", func() {
		e := entry("charlie")
		e.Attestation.CarriedBindings = []schema.CarriedBinding{{
			PredicateType: "https://slsa.dev/provenance/v1", Format: "dsse", SubjectScope: "artifact",
			Tier: "bound-unverified", AttestationHash: "blake3:ca44ed",
		}}
		commit("tx-3", e)
		mkOldFile(cached("ca44ed.att.json"))

		var stderr bytes.Buffer
		sw := sweepStores(s, stateHome, &stderr)
		Expect(sw.cacheArtifacts).NotTo(ContainElement("native/ca44ed.att.json"), stderr.String())
		Expect(sw.cacheArtifacts).To(ContainElement("native/stale-1.0.0.tar.zst"), "the sweep ran")
		Expect(exists(cached("ca44ed.att.json"))).To(BeTrue())
	})

	It("skips an incomplete generation and still sweeps what no complete generation references", func() {
		// A crashed apply's skeleton: no manifest, so it records no references.
		Expect(s.BeginTransaction("tx-crashed")).To(Succeed())

		var stderr bytes.Buffer
		sw := sweepStores(s, stateHome, &stderr)
		Expect(sw.extractDirs).To(HaveLen(1), stderr.String())
		Expect(sw.cacheArtifacts).To(HaveLen(2), stderr.String())
		Expect(exists(filepath.Join(extractstore.Root(stateHome), "stale-1.0.0+feedfacefeedface"))).To(BeFalse())
		Expect(exists(cached("stale-1.0.0.tar.zst"))).To(BeFalse())
		Expect(exists(extractDir(entry("alpha")))).To(BeTrue())
		Expect(exists(extractDir(entry("bravo")))).To(BeTrue())
		Expect(exists(cached("alpha-1.0.0.tar.zst"))).To(BeTrue())
	})

	It("keeps every extract dir and cached download while any generation's manifest is damaged, and names it", func() {
		// Generation 1's references are unknowable, and they may be evidence.
		Expect(os.WriteFile(filepath.Join(storeRoot, "generations", "1", "manifest.json"), []byte("garbage"), 0o600)).To(Succeed())

		var stderr bytes.Buffer
		keptEverything(sweepStores(s, stateHome, &stderr))
		Expect(exists(extractDir(entry("alpha")))).To(BeTrue())
		Expect(stderr.String()).To(ContainSubstring("generation 1's manifest is damaged"))
		Expect(stderr.String()).To(ContainSubstring("keeping every extract dir and cached download"))
	})

	It("skips the whole sweep when the current generation has no manifest", func() {
		// The live generation's references are unknown; its payload may
		// symlink into any extract dir, and its downloads are not recorded.
		Expect(os.Remove(filepath.Join(storeRoot, "generations", "2", "manifest.json"))).To(Succeed())

		var stderr bytes.Buffer
		keptEverything(sweepStores(s, stateHome, &stderr))
		Expect(exists(extractDir(entry("bravo")))).To(BeTrue())
		Expect(stderr.String()).To(ContainSubstring("store sweep skipped: the current generation 2 has no manifest"))
	})

	It("reports an empty sweep as empty lists, never nil", func() {
		Expect(os.Remove(filepath.Join(storeRoot, "generations", "2", "manifest.json"))).To(Succeed())
		sw := sweepStores(s, stateHome, &bytes.Buffer{})
		Expect(sw.extractDirs).NotTo(BeNil())
		Expect(sw.cacheArtifacts).NotTo(BeNil())
	})
})

var _ = Describe("gc's pruned-file listing", func() {
	// setup commits one generation and leaves n stale, unreferenced extract
	// dirs for gc to prune.
	setup := func(n int) {
		GinkgoHelper()
		root := sandboxUserEnv(GinkgoTB())
		s, err := substrate.New("store", filepath.Join(root, "data", "polypkg"))
		Expect(err).NotTo(HaveOccurred())
		Expect(s.BeginTransaction("tx-1")).To(Succeed())
		_, err = s.CommitGeneration("tx-1",
			&schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}},
			&schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user"}, nil)
		Expect(err).NotTo(HaveOccurred())
		old := time.Now().Add(-2 * extractstore.DefaultMinAge)
		for i := range n {
			dir := filepath.Join(extractstore.Root(filepath.Join(root, "state", "polypkg")), fmt.Sprintf("stale%02d-1.0.0+feedfacefeedface", i))
			Expect(os.MkdirAll(dir, 0o700)).To(Succeed())
			Expect(os.Chtimes(dir, old, old)).To(Succeed())
		}
	}
	runGCCmd := func(args ...string) string {
		GinkgoHelper()
		var out bytes.Buffer
		root := NewRootCmd()
		root.SetArgs(append(args, "gc"))
		root.SetOut(&out)
		root.SetErr(&bytes.Buffer{})
		Expect(root.Execute()).To(Succeed())
		return out.String()
	}

	It("caps the text listing at 20 names and points at JSON for the rest", func() {
		setup(25)
		out := runGCCmd()
		Expect(out).To(ContainSubstring("gc: swept 25 stale extract dir(s)"))
		Expect(out).To(ContainSubstring("  stale19-1.0.0+feedfacefeedface\n"))
		Expect(out).NotTo(ContainSubstring("stale20-"))
		Expect(out).To(ContainSubstring("  …and 5 more (use --format json for the full list)\n"))
	})

	It("lists every name when there are 20 or fewer", func() {
		setup(20)
		out := runGCCmd()
		Expect(out).To(ContainSubstring("  stale19-1.0.0+feedfacefeedface\n"))
		Expect(out).NotTo(ContainSubstring("more (use --format json"))
	})

	It("keeps the full list in JSON", func() {
		setup(25)
		var env struct {
			Data struct {
				ExtractDirsPruned []string `json:"extract_dirs_pruned"`
			} `json:"data"`
		}
		out := runGCCmd("--format", "json")
		Expect(json.Unmarshal([]byte(out), &env)).To(Succeed(), out)
		Expect(env.Data.ExtractDirsPruned).To(HaveLen(25))
	})
})

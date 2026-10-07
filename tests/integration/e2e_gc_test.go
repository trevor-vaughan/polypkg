package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/trevor-vaughan/polypkg/internal/cli"
)

// backdateManifest rewrites a generation's manifest.json so its
// ProducedBy.Timestamp simulates a past commit time. Used to drive age-based
// retention tests deterministically.
func backdateManifest(t testing.TB, dataHome string, gen int, ts time.Time) {
	t.Helper()
	g := NewWithT(t)
	mPath := filepath.Join(dataHome, "polypkg", "generations", strconv.Itoa(gen), "manifest.json")
	data, err := os.ReadFile(mPath)
	g.Expect(err).NotTo(HaveOccurred())
	var raw map[string]any
	g.Expect(json.Unmarshal(data, &raw)).To(Succeed())
	pb := raw["produced_by"].(map[string]any)
	pb["timestamp"] = ts.UTC().Format(time.RFC3339Nano)
	out, err := json.MarshalIndent(raw, "", "  ")
	g.Expect(err).NotTo(HaveOccurred())
	tmp := mPath + ".tmp"
	g.Expect(os.WriteFile(tmp, out, 0o600)).To(Succeed())
	g.Expect(os.Rename(tmp, mPath)).To(Succeed())
}

// ageExtractDirs backdates every extract-store dir past the sweep grace
// window so a gc/apply sweep sees them as old enough to remove.
func ageExtractDirs(t testing.TB, extractRoot string) {
	t.Helper()
	g := NewWithT(t)
	old := time.Now().Add(-2 * time.Hour)
	entries, err := os.ReadDir(extractRoot)
	g.Expect(err).NotTo(HaveOccurred())
	for _, e := range entries {
		g.Expect(os.Chtimes(filepath.Join(extractRoot, e.Name()), old, old)).To(Succeed())
	}
}

// extractDirNames lists the basenames under the extract-store root.
func extractDirNames(t testing.TB, extractRoot string) []string {
	t.Helper()
	g := NewWithT(t)
	entries, err := os.ReadDir(extractRoot)
	g.Expect(err).NotTo(HaveOccurred())
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func listGenIDs(t testing.TB, dataHome string) []int {
	t.Helper()
	g := NewWithT(t)
	entries, err := os.ReadDir(filepath.Join(dataHome, "polypkg", "generations"))
	g.Expect(err).NotTo(HaveOccurred())
	var ids []int
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if n, err := strconv.Atoi(e.Name()); err == nil {
			ids = append(ids, n)
		}
	}
	sort.Ints(ids)
	return ids
}

var _ = Describe("gc", func() {
	It("explicit command removes the oldest generations", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := buildHelloPackage(t)
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		for i := 0; i < 5; i++ {
			_, err := applyHelloOnce(t, srv.URL, trustRoot, "--no-drift-check")
			Expect(err).NotTo(HaveOccurred())
		}
		dataHome := os.Getenv("XDG_DATA_HOME")
		Expect(listGenIDs(t, dataHome)).To(Equal([]int{1, 2, 3, 4, 5}))

		root := cli.NewRootCmd()
		root.SilenceUsage, root.SilenceErrors = true, true
		root.SetOut(&bytes.Buffer{})
		root.SetErr(&bytes.Buffer{})
		root.SetArgs([]string{"gc", "--count", "3", "--age", "0s"})
		Expect(root.Execute()).To(Succeed())

		Expect(listGenIDs(t, dataHome)).To(Equal([]int{3, 4, 5}))
	})

	It("opportunistic GC after apply uses profile retention", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := buildHelloPackage(t)
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		// Profile with retention.count = 2 -- opportunistic GC after each apply
		// should keep only the most-recent 2 generations.
		dataHome := os.Getenv("XDG_DATA_HOME")

		profilePath := filepath.Join(t.TempDir(), "profile.yaml")
		body := installHelloProfile(t, srv.URL, trustRoot)
		body += "retention:\n  count: 2\n  age: 0s\n"
		Expect(os.WriteFile(profilePath, []byte(body), 0o644)).To(Succeed())

		for i := 0; i < 4; i++ {
			cmd := cli.NewRootCmd()
			cmd.SilenceUsage, cmd.SilenceErrors = true, true
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetArgs([]string{"apply", profilePath, "--no-drift-check"})
			Expect(cmd.Execute()).To(Succeed())
		}
		Expect(listGenIDs(t, dataHome)).To(Equal([]int{3, 4}), "opportunistic GC should keep top-2")
	})

	It("retention by age evicts old generations outside the age window", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := buildHelloPackage(t)
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		for i := 0; i < 3; i++ {
			_, err := applyHelloOnce(t, srv.URL, trustRoot, "--no-drift-check")
			Expect(err).NotTo(HaveOccurred())
		}
		dataHome := os.Getenv("XDG_DATA_HOME")
		// Backdate gens 1 and 2 past the 1h window; gen 3 stays fresh.
		now := time.Now()
		backdateManifest(t, dataHome, 1, now.Add(-2*time.Hour))
		backdateManifest(t, dataHome, 2, now.Add(-2*time.Hour))

		cmd := cli.NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"gc", "--count", "1", "--age", "1h"})
		Expect(cmd.Execute()).To(Succeed())

		Expect(listGenIDs(t, dataHome)).To(Equal([]int{3}),
			"only gen 3 should survive: count=1 keeps top-1; age=1h evicts older gens")
	})

	It("pinned generations survive eviction", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := buildHelloPackage(t)
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		_, err := applyHelloOnce(t, srv.URL, trustRoot, "--no-drift-check") // gen 1
		Expect(err).NotTo(HaveOccurred())

		// Pin gen 1.
		cmd := cli.NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"generation", "pin", "1", "--reason", "baseline"})
		Expect(cmd.Execute()).To(Succeed())

		for i := 0; i < 4; i++ {
			_, err := applyHelloOnce(t, srv.URL, trustRoot, "--no-drift-check")
			Expect(err).NotTo(HaveOccurred())
		}
		cmd = cli.NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"gc", "--count", "2", "--age", "0s"})
		Expect(cmd.Execute()).To(Succeed())

		dataHome := os.Getenv("XDG_DATA_HOME")
		ids := listGenIDs(t, dataHome)
		Expect(ids).To(ContainElement(1), "pinned gen 1 should survive top-2 eviction")
		Expect(ids).To(ContainElement(5), "current gen 5 should always survive")
		Expect(ids).To(ContainElement(4), "top-2 includes gen 4")
	})

	It("rollback restores a pinned generation", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := buildHelloPackage(t)
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		_, err := applyHelloOnce(t, srv.URL, trustRoot, "--no-drift-check") // gen 1
		Expect(err).NotTo(HaveOccurred())
		cmd := cli.NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"generation", "pin", "1", "--reason", "baseline"})
		Expect(cmd.Execute()).To(Succeed())

		for i := 0; i < 4; i++ {
			_, err := applyHelloOnce(t, srv.URL, trustRoot, "--no-drift-check")
			Expect(err).NotTo(HaveOccurred())
		}
		cmd = cli.NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"gc", "--count", "2", "--age", "0s"})
		Expect(cmd.Execute()).To(Succeed())

		cmd = cli.NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"rollback", "--to", "1"})
		Expect(cmd.Execute()).To(Succeed())

		dataHome := os.Getenv("XDG_DATA_HOME")
		target, err := os.Readlink(filepath.Join(dataHome, "polypkg", "active"))
		Expect(err).NotTo(HaveOccurred())
		Expect(target).To(ContainSubstring("generations/1/active"))
	})

	It("--force-pin makes a pinned generation evictable", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := buildHelloPackage(t)
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		_, err := applyHelloOnce(t, srv.URL, trustRoot, "--no-drift-check") // gen 1
		Expect(err).NotTo(HaveOccurred())
		cmd := cli.NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"generation", "pin", "1", "--reason", "x"})
		Expect(cmd.Execute()).To(Succeed())

		for i := 0; i < 2; i++ {
			_, err := applyHelloOnce(t, srv.URL, trustRoot, "--no-drift-check")
			Expect(err).NotTo(HaveOccurred())
		}

		cmd = cli.NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"gc", "--count", "1", "--age", "0s", "--force-pin", "1"})
		Expect(cmd.Execute()).To(Succeed())

		dataHome := os.Getenv("XDG_DATA_HOME")
		ids := listGenIDs(t, dataHome)
		Expect(ids).NotTo(ContainElement(1), "--force-pin should have made gen 1 evictable")
		Expect(ids).To(ContainElement(3), "current gen 3 always retained")
	})

	It("sweeps old extract dirs no retained generation references", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: buildHelloPackage(t)},
			indexPkg{name: "bye", version: "1.0.0", artifact: buildPkg(t, "bye", "1.0.0", "#!/bin/sh\necho bye\n")})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		// gen 1 references hello+bye; gen 2 references hello only.
		bothProfile := filepath.Join(t.TempDir(), "both.yaml")
		body := installHelloProfile(t, srv.URL, trustRoot) + "    bye:\n      version: \"=1.0.0\"\n"
		Expect(os.WriteFile(bothProfile, []byte(body), 0o644)).To(Succeed())
		out, err := runCmd("apply", bothProfile, "--no-drift-check")
		Expect(err).NotTo(HaveOccurred(), out)
		_, err = applyHelloOnce(t, srv.URL, trustRoot, "--no-drift-check")
		Expect(err).NotTo(HaveOccurred())

		// A legacy-layout dir for a still-referenced entry must survive too.
		extractRoot := filepath.Join(os.Getenv("XDG_STATE_HOME"), "polypkg", "pkg-extract")
		Expect(os.MkdirAll(filepath.Join(extractRoot, "hello-1.0.0"), 0o700)).To(Succeed())
		ageExtractDirs(t, extractRoot)

		// count=1 evicts gen 1; bye is now referenced by no retained manifest.
		out, err = runCmd("gc", "--count", "1", "--age", "0s")
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(out).To(ContainSubstring("swept 1 stale extract dir(s)"))

		names := extractDirNames(t, extractRoot)
		Expect(names).NotTo(ContainElement(HavePrefix("bye-1.0.0")), "unreferenced bye dir must be swept")
		Expect(names).To(ContainElement(HavePrefix("hello-1.0.0+")), "referenced hello dir must survive")
		Expect(names).To(ContainElement("hello-1.0.0"), "referenced legacy-layout dir must survive")
	})

	It("keeps young unreferenced extract dirs (in-flight apply grace window)", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: buildHelloPackage(t)},
			indexPkg{name: "bye", version: "1.0.0", artifact: buildPkg(t, "bye", "1.0.0", "#!/bin/sh\necho bye\n")})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		bothProfile := filepath.Join(t.TempDir(), "both.yaml")
		body := installHelloProfile(t, srv.URL, trustRoot) + "    bye:\n      version: \"=1.0.0\"\n"
		Expect(os.WriteFile(bothProfile, []byte(body), 0o644)).To(Succeed())
		out, err := runCmd("apply", bothProfile, "--no-drift-check")
		Expect(err).NotTo(HaveOccurred(), out)
		_, err = applyHelloOnce(t, srv.URL, trustRoot, "--no-drift-check")
		Expect(err).NotTo(HaveOccurred())

		// No aging: bye's extract dir is fresher than the grace window.
		out, err = runCmd("gc", "--count", "1", "--age", "0s")
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(out).NotTo(ContainSubstring("swept"))

		extractRoot := filepath.Join(os.Getenv("XDG_STATE_HOME"), "polypkg", "pkg-extract")
		Expect(extractDirNames(t, extractRoot)).To(ContainElement(HavePrefix("bye-1.0.0")),
			"young dirs stay even when unreferenced")
	})

	It("successful apply sweeps extract dirs orphaned by opportunistic GC", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: buildHelloPackage(t)},
			indexPkg{name: "bye", version: "1.0.0", artifact: buildPkg(t, "bye", "1.0.0", "#!/bin/sh\necho bye\n")})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		bothProfile := filepath.Join(t.TempDir(), "both.yaml")
		body := installHelloProfile(t, srv.URL, trustRoot) + "    bye:\n      version: \"=1.0.0\"\n"
		Expect(os.WriteFile(bothProfile, []byte(body), 0o644)).To(Succeed())
		out, err := runCmd("apply", bothProfile, "--no-drift-check")
		Expect(err).NotTo(HaveOccurred(), out)

		extractRoot := filepath.Join(os.Getenv("XDG_STATE_HOME"), "polypkg", "pkg-extract")
		ageExtractDirs(t, extractRoot)

		// hello-only profile with retention.count=1: the runner's opportunistic
		// GC prunes gen 1, and the post-apply sweep drops bye's aged dir.
		helloProfile := filepath.Join(t.TempDir(), "hello.yaml")
		body = installHelloProfile(t, srv.URL, trustRoot) + "retention:\n  count: 1\n  age: 0s\n"
		Expect(os.WriteFile(helloProfile, []byte(body), 0o644)).To(Succeed())
		out, err = runCmd("apply", helloProfile, "--no-drift-check")
		Expect(err).NotTo(HaveOccurred(), out)

		names := extractDirNames(t, extractRoot)
		Expect(names).NotTo(ContainElement(HavePrefix("bye-1.0.0")), "apply must sweep dirs of pruned generations")
		Expect(names).To(ContainElement(HavePrefix("hello-1.0.0+")), "referenced hello dir must survive")
	})

	It("emits audit events for pin, unpin, and gc", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		pkg := buildHelloPackage(t)
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1, indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		_, err := applyHelloOnce(t, srv.URL, trustRoot, "--no-drift-check")
		Expect(err).NotTo(HaveOccurred())
		cmd := cli.NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"generation", "pin", "1", "--reason", "x"})
		Expect(cmd.Execute()).To(Succeed())
		cmd = cli.NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"generation", "unpin", "1"})
		Expect(cmd.Execute()).To(Succeed())
		cmd = cli.NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"gc", "--count", "1", "--age", "0s"})
		Expect(cmd.Execute()).To(Succeed())

		stateHome := os.Getenv("XDG_STATE_HOME")
		logBytes, err := os.ReadFile(filepath.Join(stateHome, "polypkg", "audit.log"))
		Expect(err).NotTo(HaveOccurred())
		log := string(logBytes)
		Expect(log).To(ContainSubstring(`"event":"pin.add"`))
		Expect(log).To(ContainSubstring(`"event":"pin.remove"`))
		Expect(log).To(ContainSubstring(`"event":"gc.run"`))
		Expect(log).To(ContainSubstring(`"trigger":"explicit"`))
		Expect(log).To(ContainSubstring(`"trigger":"opportunistic"`))
	})
})

var _ = Describe("gc artifact cache pruning", func() {
	type gcEnvelope struct {
		Data struct {
			ExtractDirsPruned     []string `json:"extract_dirs_pruned"`
			CacheArtifactsPruned  []string `json:"cache_artifacts_pruned"`
			CacheArtifactsRemoved int      `json:"cache_artifacts_removed"`
		} `json:"data"`
	}

	// setup publishes hello and bye over HTTP (so the artifact cache is used),
	// applies a profile with both (gen 1, pinned when pinFirst) and then hello
	// alone (gen 2). When age is set it backdates the cache and extract store
	// past the sweep grace window. It returns the native source's cache dir.
	setup := func(t testing.TB, pinFirst, age bool) string {
		root := IsolatedEnv(t)
		t.Setenv("HOME", filepath.Join(root, "home"))
		t.Setenv("XDG_CACHE_HOME", filepath.Join(root, "cache"))
		t.Setenv("XDG_RUNTIME_DIR", filepath.Join(root, "runtime"))
		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: buildHelloPackage(t)},
			indexPkg{name: "bye", version: "1.0.0", artifact: buildPkg(t, "bye", "1.0.0", "#!/bin/sh\necho bye\n")})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		DeferCleanup(srv.Close)

		bothProfile := filepath.Join(t.TempDir(), "both.yaml")
		body := installHelloProfile(t, srv.URL, trustRoot) + "    bye:\n      version: \"=1.0.0\"\n"
		Expect(os.WriteFile(bothProfile, []byte(body), 0o644)).To(Succeed())
		out, err := runCmd("apply", bothProfile, "--no-drift-check")
		Expect(err).NotTo(HaveOccurred(), out)
		if pinFirst {
			out, err = runCmd("generation", "pin", "1", "--reason", "keep bye")
			Expect(err).NotTo(HaveOccurred(), out)
		}
		_, err = applyHelloOnce(t, srv.URL, trustRoot, "--no-drift-check")
		Expect(err).NotTo(HaveOccurred())

		stateRoot := filepath.Join(os.Getenv("XDG_STATE_HOME"), "polypkg")
		cacheDir := filepath.Join(stateRoot, "cache", "native")
		Expect(filepath.Join(cacheDir, "bye-1.0.0.tar.zst")).To(BeAnExistingFile(), "apply must have cached bye's artifact")
		if age {
			// ageExtractDirs backdates every entry of any directory.
			ageExtractDirs(t, cacheDir)
			ageExtractDirs(t, filepath.Join(stateRoot, "pkg-extract"))
		}
		return cacheDir
	}

	runGCJSON := func(args ...string) (string, gcEnvelope) {
		GinkgoHelper()
		cmd := cli.NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		var out, errBuf bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errBuf)
		cmd.SetArgs(append([]string{"--format", "json", "gc"}, args...))
		Expect(cmd.Execute()).To(Succeed(), errBuf.String())
		var env gcEnvelope
		Expect(json.Unmarshal(out.Bytes(), &env)).To(Succeed(), out.String())
		return out.String(), env
	}

	It("prunes cache and extract entries only a collected generation referenced, and lists them in JSON", func() {
		cacheDir := setup(GinkgoTB(), false, true)

		_, env := runGCJSON("--count", "1", "--age", "0s")

		Expect(env.Data.CacheArtifactsPruned).To(Equal([]string{"native/bye-1.0.0.tar.zst"}))
		Expect(env.Data.CacheArtifactsRemoved).To(Equal(1))
		Expect(env.Data.ExtractDirsPruned).To(ConsistOf(HavePrefix("bye-1.0.0+")))
		Expect(filepath.Join(cacheDir, "bye-1.0.0.tar.zst")).NotTo(BeAnExistingFile())
		Expect(filepath.Join(cacheDir, "hello-1.0.0.tar.zst")).To(BeAnExistingFile(), "the retained generation's artifact stays")
		Expect(filepath.Join(cacheDir, "index.json")).To(BeAnExistingFile(), "signed metadata is never pruned")
		Expect(filepath.Join(cacheDir, "trust.json")).To(BeAnExistingFile(), "signed metadata is never pruned")
	})

	It("names what it pruned in text output", func() {
		setup(GinkgoTB(), false, true)
		out, err := runCmd("gc", "--count", "1", "--age", "0s")
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(out).To(ContainSubstring("gc: pruned 1 cached artifact(s)"))
		Expect(out).To(ContainSubstring("  native/bye-1.0.0.tar.zst"))
		Expect(out).To(ContainSubstring("swept 1 stale extract dir(s)"))
	})

	It("keeps the cached artifact of a pinned generation", func() {
		cacheDir := setup(GinkgoTB(), true, true)

		raw, env := runGCJSON("--count", "1", "--age", "0s")

		Expect(env.Data.CacheArtifactsPruned).To(BeEmpty())
		Expect(raw).To(ContainSubstring(`"cache_artifacts_pruned":[]`), "an empty list renders as [], not null")
		Expect(filepath.Join(cacheDir, "bye-1.0.0.tar.zst")).To(BeAnExistingFile())
	})

	It("keeps young unreferenced cache entries (in-flight apply grace window)", func() {
		cacheDir := setup(GinkgoTB(), false, false)

		_, env := runGCJSON("--count", "1", "--age", "0s")

		Expect(env.Data.CacheArtifactsPruned).To(BeEmpty())
		Expect(filepath.Join(cacheDir, "bye-1.0.0.tar.zst")).To(BeAnExistingFile())
	})
})

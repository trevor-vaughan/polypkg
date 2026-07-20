package integration

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/cli"
)

// runCmd executes a polypkg command in-process and returns stdout+stderr and the error.
func runCmd(args ...string) (string, error) {
	cmd := cli.NewRootCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

// buildHelloPackageV110 creates a hello-1.1.0.tar.zst with the same actions as
// buildHelloPackage but at version 1.1.0.
func buildHelloPackageV110() []byte {
	manifest := `schema: polypkg.package/v1
name: hello
version: 1.1.0
actions:
  - phase: post-place
    action: dir
    params:
      path: $ACTIVE/hello/bin
      mode: "0o755"
  - phase: post-place
    action: install
    params:
      src: $PKG/content/bin/hi
      dest: $ACTIVE/hello/bin/hi
      policy: symlink
`
	hi := "#!/bin/sh\necho hello 1.1.0 from polypkg\n"
	return buildTarZst(GinkgoTB(), map[string]string{
		"polypkg.yaml":   manifest,
		"content/bin/hi": hi,
	})
}

// profileWithTwoVersions returns profile YAML that pins hello to =1.0.0 but
// the repo exposes both 1.0.0 and 1.1.0, so info can report available versions.
func profileWithTwoVersions(repoURL, trustRoot string) string {
	return fmt.Sprintf(`schema: polypkg.spec/v1
name: list-info-test
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: polypkg-native
    url: %s
    trust_root: %s
packages:
  user:
    hello:
      version: "=1.0.0"
`, repoURL, trustRoot)
}

var _ = Describe("search verb — empty-packages profile", func() {
	// Bug regression: search short-circuited to "no matches" when the profile
	// had no packages in scope (FetchCatalog's len(reqs)==0 guard).  The fix
	// sets ForceCatalogFetch:true so the full catalog is always fetched.
	var (
		profilePath string
		srv         *httptest.Server
	)

	BeforeEach(func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		pkg100 := buildHelloPackage(t)
		pkg110 := buildHelloPackageV110()

		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: pkg100},
			indexPkg{name: "hello", version: "1.1.0", artifact: pkg110},
		)

		srv = httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		DeferCleanup(srv.Close)

		// Profile has a native source but NO packages section.
		profilePath = filepath.Join(t.TempDir(), "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(profileNoPackages(srv.URL, trustRoot)), 0o644)).To(Succeed())
		GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)
	})

	It("search hello finds the package even though nothing is installed", func() {
		out, err := runCmd("search", "hello")
		Expect(err).NotTo(HaveOccurred(), "search failed: %s", out)
		Expect(out).To(ContainSubstring("hello"),
			"search must find hello from catalog even with empty profile; output:\n%s", out)
	})

	It("search hello shows available versions", func() {
		out, err := runCmd("search", "hello")
		Expect(err).NotTo(HaveOccurred(), "search failed: %s", out)
		Expect(out).To(ContainSubstring("1.1.0"),
			"search must show newest version from catalog; output:\n%s", out)
	})
})

var _ = Describe("info verb — empty-packages profile", func() {
	// Bug regression: info also short-circuited to nil catalog when the profile
	// had no packages in scope, showing "installed: none" with no available list.
	var (
		profilePath string
		srv         *httptest.Server
	)

	BeforeEach(func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		pkg100 := buildHelloPackage(t)
		pkg110 := buildHelloPackageV110()

		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: pkg100},
			indexPkg{name: "hello", version: "1.1.0", artifact: pkg110},
		)

		srv = httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		DeferCleanup(srv.Close)

		// Profile has a native source but NO packages section.
		profilePath = filepath.Join(t.TempDir(), "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(profileNoPackages(srv.URL, trustRoot)), 0o644)).To(Succeed())
		GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)
	})

	It("info hello shows installed: none and available versions 1.0.0 and 1.1.0", func() {
		out, err := runCmd("info", "hello")
		Expect(err).NotTo(HaveOccurred(), "info failed: %s", out)
		Expect(out).To(ContainSubstring("installed: none"),
			"must report no installed version; output:\n%s", out)
		Expect(out).To(ContainSubstring("1.0.0"),
			"must list 1.0.0 as available; output:\n%s", out)
		Expect(out).To(ContainSubstring("1.1.0"),
			"must list 1.1.0 as available; output:\n%s", out)
	})
})

var _ = Describe("no-profile hint — package verbs vs positional verbs", func() {
	// Bug regression: install/remove/upgrade showed "pass a path: polypkg install
	// <profile-file>" which is wrong — they take package names, not a profile
	// positional.  The fix gives installProfilePath a hint with --profile <path>.
	BeforeEach(func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		// Clear env so no profile is discoverable.
		GinkgoT().Setenv("POLYPKG_PROFILE", "")
	})

	It("install with no profile hint mentions --profile, not <profile-file>", func() {
		// Use JSON format so the hint is surfaced in the output envelope.
		out, err := runCmd("install", "--format", "json", "hello")
		Expect(err).To(HaveOccurred(), "install without profile must fail; output: %s", out)
		result := parseLastCLIResult(out)
		Expect(result.Status).To(Equal("error"),
			"status must be error; result=%v", result)
		Expect(result.Hint).To(ContainSubstring("--profile"),
			"hint must mention --profile flag; hint=%q", result.Hint)
		Expect(result.Hint).NotTo(ContainSubstring("install <profile-file>"),
			"hint must not suggest install <profile-file> positional; hint=%q", result.Hint)
	})

	It("apply with no profile hint still mentions <profile-file>", func() {
		// Use JSON format so the hint is surfaced in the output envelope.
		out, err := runCmd("apply", "--format", "json")
		Expect(err).To(HaveOccurred(), "apply without profile must fail; output: %s", out)
		result := parseLastCLIResult(out)
		Expect(result.Status).To(Equal("error"),
			"status must be error; result=%v", result)
		Expect(result.Hint).To(ContainSubstring("<profile-file>"),
			"apply hint must still mention positional; hint=%q", result.Hint)
	})
})

var _ = Describe("search verb", func() {
	var (
		profilePath string
		srv         *httptest.Server
	)

	BeforeEach(func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		pkg100 := buildHelloPackage(t)
		pkg110 := buildHelloPackageV110()

		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: pkg100},
			indexPkg{name: "hello", version: "1.1.0", artifact: pkg110},
		)

		srv = httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		DeferCleanup(srv.Close)

		profilePath = filepath.Join(t.TempDir(), "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(profileWithTwoVersions(srv.URL, trustRoot)), 0o644)).To(Succeed())
	})

	Context("after applying hello 1.0.0", func() {
		BeforeEach(func() {
			GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)
			out, err := runCmd("apply", profilePath)
			Expect(err).NotTo(HaveOccurred(), "apply failed: %s", out)
		})

		It("search hell finds hello and shows 1.1.0", func() {
			GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)
			out, err := runCmd("search", "hell")
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(ContainSubstring("hello"))
			Expect(out).To(ContainSubstring("1.1.0"))
		})

		It("search marks hello as installed when it is applied", func() {
			GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)
			out, err := runCmd("search", "hell")
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(ContainSubstring("installed:"))
		})

		It("search zzz exits 0 with friendly no-match line", func() {
			GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)
			out, err := runCmd("search", "zzz")
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(ContainSubstring(`no packages matching "zzz"`))
		})

		It("search --format json contains matches with both versions for hello", func() {
			GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)
			out, err := runCmd("search", "--format", "json", "hello")
			Expect(err).NotTo(HaveOccurred())
			result := parseLastCLIResult(out)
			Expect(result.Command).To(Equal("search"))
			Expect(result.Status).To(Equal("ok"))
			matches, ok := result.Data["matches"].([]any)
			Expect(ok).To(BeTrue(), "data.matches must be a slice; data=%v", result.Data)
			Expect(matches).To(HaveLen(1))
			m := matches[0].(map[string]any)
			Expect(m["name"]).To(Equal("hello"))
			versions, ok := m["versions"].([]any)
			Expect(ok).To(BeTrue())
			vStrs := make([]string, len(versions))
			for i, v := range versions {
				vStrs[i] = fmt.Sprintf("%v", v)
			}
			Expect(vStrs).To(ConsistOf("1.0.0", "1.1.0"))
		})

		It("search --format json zzz returns ok with empty matches", func() {
			GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)
			out, err := runCmd("search", "--format", "json", "zzz")
			Expect(err).NotTo(HaveOccurred())
			result := parseLastCLIResult(out)
			Expect(result.Command).To(Equal("search"))
			Expect(result.Status).To(Equal("ok"))
			matches, ok := result.Data["matches"].([]any)
			Expect(ok).To(BeTrue())
			Expect(matches).To(BeEmpty())
		})
	})
})

var _ = Describe("list and info verbs", func() {
	var (
		profilePath string
		srv         *httptest.Server
	)

	BeforeEach(func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		pkg100 := buildHelloPackage(t)
		pkg110 := buildHelloPackageV110()

		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: pkg100},
			indexPkg{name: "hello", version: "1.1.0", artifact: pkg110},
		)

		srv = httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		DeferCleanup(srv.Close)

		profilePath = filepath.Join(t.TempDir(), "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(profileWithTwoVersions(srv.URL, trustRoot)), 0o644)).To(Succeed())
	})

	Context("list with no generation applied", func() {
		It("prints friendly message and exits 0", func() {
			out, err := runCmd("list")
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(ContainSubstring("no packages installed"))
			Expect(out).To(ContainSubstring("polypkg install <name>"))
		})
	})

	Context("after applying hello 1.0.0", func() {
		BeforeEach(func() {
			out, err := runCmd("apply", profilePath)
			Expect(err).NotTo(HaveOccurred(), "apply failed: %s", out)
		})

		It("list output contains hello and 1.0.0", func() {
			out, err := runCmd("list")
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(ContainSubstring("hello"))
			Expect(out).To(ContainSubstring("1.0.0"))
		})

		It("list marks hello as pinned when profile pins it", func() {
			GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)
			out, err := runCmd("list")
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(ContainSubstring("pinned: =1.0.0"))
		})

		It("info hello shows installed 1.0.0 and available includes 1.1.0", func() {
			GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)
			out, err := runCmd("info", "hello")
			Expect(err).NotTo(HaveOccurred())
			Expect(out).To(ContainSubstring("installed: 1.0.0"),
				"must report installed version; output was:\n%s", out)
			Expect(out).To(ContainSubstring("1.1.0"),
				"must list 1.1.0 as available; output was:\n%s", out)
		})

		It("info hello emits JSON with installed and available fields", func() {
			GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)
			out, err := runCmd("info", "--format", "json", "hello")
			Expect(err).NotTo(HaveOccurred())
			result := parseLastCLIResult(out)
			Expect(result.Status).To(Equal("ok"))
			Expect(result.Data).NotTo(BeNil())
			Expect(result.Data["installed"]).To(Equal("1.0.0"))
			avail, ok := result.Data["available"].([]any)
			Expect(ok).To(BeTrue())
			availStrs := make([]string, len(avail))
			for i, v := range avail {
				availStrs[i] = fmt.Sprintf("%v", v)
			}
			Expect(availStrs).To(ContainElements("1.0.0", "1.1.0"))
		})

		It("info unknown package errors with CLIError naming the unknown name", func() {
			GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)
			out, err := runCmd("info", "notexist")
			Expect(err).To(HaveOccurred(), "info on unknown package must fail; output: %s", out)
			Expect(strings.ToLower(out) + err.Error()).To(
				Or(
					ContainSubstring("notexist"),
					ContainSubstring("unknown"),
				),
			)
		})
	})
})

// profileNoPackages returns profile YAML with the native source configured but
// no packages section, so `install` adds the first entry.
func profileNoPackages(repoURL, trustRoot string) string {
	return fmt.Sprintf(`schema: polypkg.spec/v1
name: install-test
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: polypkg-native
    url: %s
    trust_root: %s
`, repoURL, trustRoot)
}

var _ = Describe("install verb end-to-end", func() {
	var (
		profilePath string
		srv         *httptest.Server
	)

	BeforeEach(func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		pkg100 := buildHelloPackage(t)
		pkg110 := buildHelloPackageV110()

		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: pkg100},
			indexPkg{name: "hello", version: "1.1.0", artifact: pkg110},
		)

		srv = httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		DeferCleanup(srv.Close)

		profilePath = filepath.Join(t.TempDir(), "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(profileNoPackages(srv.URL, trustRoot)), 0o644)).To(Succeed())
		GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)
	})

	It("install hello adds the newest as a >= floor, applies, and list shows it", func() {
		out, err := runCmd("install", "hello")
		Expect(err).NotTo(HaveOccurred(), "install failed: %s", out)
		Expect(out).To(ContainSubstring("applied generation"))

		raw, rerr := os.ReadFile(profilePath)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(string(raw)).To(ContainSubstring(`">=1.1.0"`),
			"profile must pin newest as a >= floor; profile was:\n%s", string(raw))

		listOut, listErr := runCmd("list")
		Expect(listErr).NotTo(HaveOccurred())
		Expect(listOut).To(ContainSubstring("hello"))
	})

	It("install hello a second time reports already-present and applies no new generation", func() {
		out1, err1 := runCmd("install", "hello")
		Expect(err1).NotTo(HaveOccurred(), "first install failed: %s", out1)

		out2, err2 := runCmd("install", "hello")
		Expect(err2).NotTo(HaveOccurred(), "second install failed: %s", out2)
		Expect(out2).To(ContainSubstring("already in the profile"))
		Expect(out2).NotTo(ContainSubstring("applied generation"),
			"second install must not apply a new generation; output:\n%s", out2)
	})

	It("install hello@=1.0.0 after a bare install reports an update and applies", func() {
		out1, err1 := runCmd("install", "hello")
		Expect(err1).NotTo(HaveOccurred(), "first install failed: %s", out1)

		out2, err2 := runCmd("install", "hello@=1.0.0")
		Expect(err2).NotTo(HaveOccurred(), "update install failed: %s", out2)
		Expect(out2).To(ContainSubstring("updating hello"))
		Expect(out2).To(ContainSubstring("applied generation"))

		raw, rerr := os.ReadFile(profilePath)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(string(raw)).To(ContainSubstring(`"=1.0.0"`))
	})

	It("install of an unknown package errors and leaves the profile byte-identical", func() {
		before, rerr := os.ReadFile(profilePath)
		Expect(rerr).NotTo(HaveOccurred())

		out, err := runCmd("install", "nosuchpkg")
		Expect(err).To(HaveOccurred(), "install of unknown package must fail; output: %s", out)

		after, aerr := os.ReadFile(profilePath)
		Expect(aerr).NotTo(HaveOccurred())
		Expect(after).To(Equal(before), "profile must be unchanged after a failed install")
	})

	It("emits a JSON envelope with edits and gen_id on success", func() {
		out, err := runCmd("install", "--format", "json", "hello")
		Expect(err).NotTo(HaveOccurred(), "install failed: %s", out)
		result := parseLastCLIResult(out)
		Expect(result.Command).To(Equal("install"))
		Expect(result.Status).To(Equal("ok"))
		Expect(result.Data["gen_id"]).NotTo(BeNil())
		edits, ok := result.Data["edits"].([]any)
		Expect(ok).To(BeTrue(), "data.edits must be a slice; data=%v", result.Data)
		Expect(edits).To(HaveLen(1))
		e := edits[0].(map[string]any)
		Expect(e["name"]).To(Equal("hello"))
		Expect(e["constraint"]).To(Equal(">=1.1.0"))
		Expect(e["action"]).To(Equal("add"))
	})
})

var _ = Describe("init verb end-to-end", func() {
	var (
		srv       *httptest.Server
		trustRoot string
	)

	BeforeEach(func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		pkg := buildHelloPackage(t)
		repoDir := t.TempDir()
		trustRoot = signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: pkg},
		)

		srv = httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		DeferCleanup(srv.Close)
	})

	It("writes a valid profile to the user config dir and reports it", func() {
		out, err := runCmd("init", "--source-url", srv.URL, "--trust-root-file", trustRoot)
		Expect(err).NotTo(HaveOccurred(), "init failed: %s", out)
		Expect(out).To(ContainSubstring("wrote "))
		Expect(out).To(ContainSubstring("next steps:"))
		// The profile must be discoverable via the default path — plan must not
		// return a "no profile found" error.
		planOut, planErr := runCmd("plan")
		if planErr != nil {
			Expect(planErr.Error()).NotTo(ContainSubstring("no profile found"),
				"plan must not report no profile found; output: %s", planOut)
		}
	})

	It("errors with already-exists when run twice on the same scope", func() {
		out, err := runCmd("init", "--source-url", srv.URL, "--trust-root-file", trustRoot)
		Expect(err).NotTo(HaveOccurred(), "first init failed: %s", out)
		out2, err2 := runCmd("init", "--source-url", srv.URL, "--trust-root-file", trustRoot)
		Expect(err2).To(HaveOccurred(), "second init must fail; output: %s", out2)
		Expect(err2.Error()).To(ContainSubstring("profile already exists at"))
	})

	It("emits JSON output when --format json", func() {
		out, err := runCmd("init", "--format", "json", "--source-url", srv.URL, "--trust-root-file", trustRoot)
		Expect(err).NotTo(HaveOccurred(), "init failed: %s", out)
		result := parseLastCLIResult(out)
		Expect(result.Status).To(Equal("ok"))
		Expect(result.Command).To(Equal("init"))
		pathVal, ok := result.Data["path"].(string)
		Expect(ok).To(BeTrue(), "data.path must be a string; data: %v", result.Data)
		Expect(pathVal).To(ContainSubstring("profile.yaml"))
		_, statErr := os.Stat(pathVal)
		Expect(statErr).NotTo(HaveOccurred(), "profile.yaml must exist at reported path")
	})

	It("init profile is usable: plan detects hello as a pending change", func() {
		out, err := runCmd("init", "--source-url", srv.URL, "--trust-root-file", trustRoot)
		Expect(err).NotTo(HaveOccurred(), "init failed: %s", out)

		// Append hello package to the written profile.
		profilePath := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "polypkg", "profile.yaml")
		raw, rerr := os.ReadFile(profilePath)
		Expect(rerr).NotTo(HaveOccurred())
		appended := string(raw) + "packages:\n  user:\n    hello:\n      version: \">=1.0.0\"\n"
		Expect(os.WriteFile(profilePath, []byte(appended), 0o600)).To(Succeed())

		planOut, planErr := runCmd("plan")
		// plan exits 2 (StatusError) when changes are pending.
		Expect(planErr).To(HaveOccurred(), "plan must have pending changes; output: %s", planOut)
		Expect(planOut).To(ContainSubstring("hello"), "plan must list hello; output: %s", planOut)
	})
})

var _ = Describe("remove verb end-to-end", func() {
	var (
		profilePath string
		srv         *httptest.Server
	)

	BeforeEach(func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		pkg := buildHelloPackage(t)

		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: pkg},
		)

		srv = httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		DeferCleanup(srv.Close)

		profilePath = filepath.Join(t.TempDir(), "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(profileNoPackages(srv.URL, trustRoot)), 0o644)).To(Succeed())
		GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)
	})

	It("install then remove: profile no longer contains hello and list shows zero packages", func() {
		out, err := runCmd("install", "hello@1.0.0")
		Expect(err).NotTo(HaveOccurred(), "install failed: %s", out)

		profBefore, rerr := os.ReadFile(profilePath)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(string(profBefore)).To(ContainSubstring("hello"),
			"profile must contain hello after install")

		out, err = runCmd("remove", "hello")
		Expect(err).NotTo(HaveOccurred(), "remove failed: %s", out)
		Expect(out).To(ContainSubstring("removing hello"))
		Expect(out).To(ContainSubstring("applied generation"))

		profAfter, rerr2 := os.ReadFile(profilePath)
		Expect(rerr2).NotTo(HaveOccurred())
		Expect(string(profAfter)).NotTo(ContainSubstring("hello"),
			"profile must not contain hello after remove; profile:\n%s", string(profAfter))

		// After removing the last package, list shows zero packages (a generation
		// exists but the manifest is empty — not the same as no-generation state).
		listOut, listErr := runCmd("list", "--format", "json")
		Expect(listErr).NotTo(HaveOccurred(), "list after remove failed: %s", listOut)
		result := parseLastCLIResult(listOut)
		Expect(result.Status).To(Equal("ok"))
		pkgs, ok := result.Data["packages"].([]any)
		Expect(ok).To(BeTrue(), "data.packages must be a slice; data=%v", result.Data)
		Expect(pkgs).To(BeEmpty(), "list must show zero packages after remove")
	})

	It("remove of a package not in the profile errors and leaves the profile byte-identical", func() {
		// Install hello so the profile is non-empty; then try to remove a missing name.
		out, err := runCmd("install", "hello@1.0.0")
		Expect(err).NotTo(HaveOccurred(), "install failed: %s", out)

		profBefore, rerr := os.ReadFile(profilePath)
		Expect(rerr).NotTo(HaveOccurred())

		out, err = runCmd("remove", "nosuch")
		Expect(err).To(HaveOccurred(), "remove of missing package must fail; output: %s", out)
		Expect(err.Error()).To(ContainSubstring("not in the profile"),
			"error must say not in the profile; got: %s", err.Error())

		// Hint is surfaced in JSON mode; verify it lists hello.
		out2, err2 := runCmd("remove", "--format", "json", "nosuch")
		Expect(err2).To(HaveOccurred())
		result := parseLastCLIResult(out2)
		Expect(result.Status).To(Equal("error"))
		Expect(strings.ToLower(result.Hint)).To(ContainSubstring("hello"),
			"hint must list known packages; hint=%q", result.Hint)

		profAfter, rerr2 := os.ReadFile(profilePath)
		Expect(rerr2).NotTo(HaveOccurred())
		Expect(profAfter).To(Equal(profBefore), "profile must be unchanged after a failed remove")
	})

	It("remove with empty profile shows hint about empty scope via JSON", func() {
		// Profile has no packages yet.
		out, err := runCmd("remove", "--format", "json", "hello")
		Expect(err).To(HaveOccurred(), "remove on empty profile must fail; output: %s", out)
		result := parseLastCLIResult(out)
		Expect(result.Status).To(Equal("error"))
		Expect(strings.ToLower(result.Error)).To(ContainSubstring("not in the profile"))
		Expect(strings.ToLower(result.Hint)).To(ContainSubstring("no packages in scope"))
	})

	It("emits a JSON envelope with command remove, edits action=remove, and gen_id", func() {
		out, err := runCmd("install", "hello@1.0.0")
		Expect(err).NotTo(HaveOccurred(), "install failed: %s", out)

		out, err = runCmd("remove", "--format", "json", "hello")
		Expect(err).NotTo(HaveOccurred(), "remove failed: %s", out)

		result := parseLastCLIResult(out)
		Expect(result.Command).To(Equal("remove"))
		Expect(result.Status).To(Equal("ok"))
		Expect(result.Data["gen_id"]).NotTo(BeNil())
		edits, ok := result.Data["edits"].([]any)
		Expect(ok).To(BeTrue(), "data.edits must be a slice; data=%v", result.Data)
		Expect(edits).To(HaveLen(1))
		e := edits[0].(map[string]any)
		Expect(e["name"]).To(Equal("hello"))
		Expect(e["action"]).To(Equal("remove"))
	})
})

// profileRangeConstraint returns a profile that follows hello with a >= floor,
// so upgrade (no args) re-resolves it to the newest with no held-back report.
func profileRangeConstraint(repoURL, trustRoot string) string {
	return fmt.Sprintf(`schema: polypkg.spec/v1
name: upgrade-range-test
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: polypkg-native
    url: %s
    trust_root: %s
packages:
  user:
    hello:
      version: ">=1.0.0"
`, repoURL, trustRoot)
}

var _ = Describe("upgrade verb end-to-end", func() {
	var srv *httptest.Server
	var trustRoot string

	BeforeEach(func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		pkg100 := buildHelloPackage(t)
		pkg110 := buildHelloPackageV110()

		repoDir := t.TempDir()
		trustRoot = signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: pkg100},
			indexPkg{name: "hello", version: "1.1.0", artifact: pkg110},
		)

		srv = httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		DeferCleanup(srv.Close)
	})

	Context("with an exact pin held back behind a newer version", func() {
		var profilePath string

		BeforeEach(func() {
			profilePath = filepath.Join(GinkgoT().TempDir(), "profile.yaml")
			Expect(os.WriteFile(profilePath, []byte(profileWithTwoVersions(srv.URL, trustRoot)), 0o644)).To(Succeed())
			GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)

			out, err := runCmd("apply", profilePath)
			Expect(err).NotTo(HaveOccurred(), "initial apply failed: %s", out)
		})

		It("upgrade with no args reports held-back, leaves the pin unchanged, exits 0", func() {
			before, rerr := os.ReadFile(profilePath)
			Expect(rerr).NotTo(HaveOccurred())

			out, err := runCmd("upgrade")
			Expect(err).NotTo(HaveOccurred(), "upgrade failed: %s", out)
			Expect(out).To(ContainSubstring("held back: hello =1.0.0 (1.1.0 available)"))
			Expect(out).To(ContainSubstring("run `polypkg upgrade hello` to bump the pin"))
			Expect(out).NotTo(ContainSubstring("—"), "house style forbids the em dash")

			after, aerr := os.ReadFile(profilePath)
			Expect(aerr).NotTo(HaveOccurred())
			Expect(after).To(Equal(before), "upgrade with no args must not edit the profile")
		})

		It("upgrade hello bumps the pin to =1.1.0, applies a new generation, list shows 1.1.0", func() {
			out, err := runCmd("upgrade", "hello")
			Expect(err).NotTo(HaveOccurred(), "upgrade hello failed: %s", out)
			Expect(out).To(ContainSubstring("bumping hello pin"))
			Expect(out).To(ContainSubstring("applied generation"))

			raw, rerr := os.ReadFile(profilePath)
			Expect(rerr).NotTo(HaveOccurred())
			Expect(string(raw)).To(ContainSubstring(`"=1.1.0"`),
				"pin must be bumped to =1.1.0; profile:\n%s", string(raw))
			Expect(string(raw)).NotTo(ContainSubstring(`"=1.0.0"`))

			listOut, listErr := runCmd("list")
			Expect(listErr).NotTo(HaveOccurred())
			Expect(listOut).To(ContainSubstring("hello"))
			Expect(listOut).To(ContainSubstring("1.1.0"))
		})

		It("upgrade hello a second time reports already-newest and applies no new generation", func() {
			out1, err1 := runCmd("upgrade", "hello")
			Expect(err1).NotTo(HaveOccurred(), "first upgrade failed: %s", out1)

			out2, err2 := runCmd("upgrade", "hello")
			Expect(err2).NotTo(HaveOccurred(), "second upgrade failed: %s", out2)
			Expect(out2).To(ContainSubstring("already at the newest version (1.1.0)"))
			Expect(out2).NotTo(ContainSubstring("applied generation"),
				"second upgrade must not apply a new generation; output:\n%s", out2)
		})

		It("upgrade hello --format json at-newest: status ok, edits present, gen_id absent (no apply ran)", func() {
			// First bump to the newest so the next upgrade hits the at-newest path.
			out1, err1 := runCmd("upgrade", "hello")
			Expect(err1).NotTo(HaveOccurred(), "first upgrade failed: %s", out1)

			out2, err2 := runCmd("upgrade", "--format", "json", "hello")
			Expect(err2).NotTo(HaveOccurred(), "second upgrade failed: %s", out2)

			result := parseLastCLIResult(out2)
			Expect(result.Command).To(Equal("upgrade"))
			Expect(result.Status).To(Equal("ok"))
			// gen_id is intentionally absent when no apply runs: the no-apply path
			// emits only edits. Consumers must treat gen_id as optional.
			Expect(result.Data).NotTo(HaveKey("gen_id"),
				"gen_id must be absent when no apply ran; data=%v", result.Data)
			edits, ok := result.Data["edits"].([]any)
			Expect(ok).To(BeTrue(), "data.edits must be a slice; data=%v", result.Data)
			Expect(edits).To(HaveLen(1))
			e := edits[0].(map[string]any)
			Expect(e["name"]).To(Equal("hello"))
			Expect(e["action"]).To(Equal("at-newest"))
		})

		It("emits a JSON envelope with held_back and gen_id on the no-args form", func() {
			out, err := runCmd("upgrade", "--format", "json")
			Expect(err).NotTo(HaveOccurred(), "upgrade failed: %s", out)
			result := parseLastCLIResult(out)
			Expect(result.Command).To(Equal("upgrade"))
			Expect(result.Status).To(Equal("ok"))
			Expect(result.Data["gen_id"]).NotTo(BeNil())
			held, ok := result.Data["held_back"].([]any)
			Expect(ok).To(BeTrue(), "data.held_back must be a slice; data=%v", result.Data)
			Expect(held).To(HaveLen(1))
			e := held[0].(map[string]any)
			Expect(e["name"]).To(Equal("hello"))
			Expect(e["pinned"]).To(Equal("=1.0.0"))
			Expect(e["available"]).To(Equal("1.1.0"))
		})
	})

	Context("with a range constraint", func() {
		var profilePath string

		BeforeEach(func() {
			profilePath = filepath.Join(GinkgoT().TempDir(), "profile.yaml")
			Expect(os.WriteFile(profilePath, []byte(profileRangeConstraint(srv.URL, trustRoot)), 0o644)).To(Succeed())
			GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)

			out, err := runCmd("apply", profilePath)
			Expect(err).NotTo(HaveOccurred(), "initial apply failed: %s", out)
		})

		It("upgrade with no args applies cleanly and reports no held-back line", func() {
			out, err := runCmd("upgrade")
			Expect(err).NotTo(HaveOccurred(), "upgrade failed: %s", out)
			Expect(out).To(ContainSubstring("applied generation"))
			Expect(out).NotTo(ContainSubstring("held back:"),
				"a range constraint is not held back; output:\n%s", out)
		})
	})

	Context("with no packages in the profile", func() {
		It("upgrade with no args errors and names install", func() {
			profilePath := filepath.Join(GinkgoT().TempDir(), "profile.yaml")
			Expect(os.WriteFile(profilePath, []byte(profileNoPackages(srv.URL, trustRoot)), 0o644)).To(Succeed())
			GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)

			out, err := runCmd("upgrade")
			Expect(err).To(HaveOccurred(), "upgrade on empty profile must fail; output: %s", out)
			Expect(err.Error()).To(ContainSubstring("no packages to upgrade"))
		})

		It("upgrade of a package not in the profile errors", func() {
			profilePath := filepath.Join(GinkgoT().TempDir(), "profile.yaml")
			Expect(os.WriteFile(profilePath, []byte(profileWithTwoVersions(srv.URL, trustRoot)), 0o644)).To(Succeed())
			GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)

			out, err := runCmd("upgrade", "nosuch")
			Expect(err).To(HaveOccurred(), "upgrade of missing package must fail; output: %s", out)
			Expect(err.Error()).To(ContainSubstring("not in the profile"))
		})
	})
})

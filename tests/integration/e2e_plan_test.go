package integration

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/cli"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func runPlanCmd(args ...string) (string, error) {
	cmd := cli.NewRootCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(append([]string{"plan"}, args...))
	err := cmd.Execute()
	return buf.String(), err
}

// buildSharedAreaActionPackage builds hello-1.0.0 exercising every target-carrying
// action whose runner places a symlink into a shared per-generation area and stores
// a $ACTIVE-expanded link target: path (bin/<name>), completion
// (completions/<shell>/<hostfile>), desktop (applications/<base>), and mime
// (mime/<base>) — plus dir + install and a $ACTIVE-targeted symlink. Each shared
// action installs its source into the package namespace first, then declares the
// shared-area action against that $ACTIVE source. It exercises the plan-after-apply
// convergence path for all four shared-area actions, which the dir+install fixture
// never reached and which produced the hard "relativize \"\"" error before the
// projection learned their stored shapes.
func buildSharedAreaActionPackage(t testing.TB) []byte {
	t.Helper()
	manifest := `schema: polypkg.package/v1
name: hello
version: 1.0.0
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
  - phase: post-place
    action: symlink
    params:
      src: $ACTIVE/hello/bin/hi
      dest: $ACTIVE/hello/bin/hi-active
  - phase: post-place
    action: path
    params:
      name: hi
      source: $ACTIVE/hello/bin/hi
  - phase: pre-place
    action: install
    params:
      src: $PKG/content/comp/hi.bash
      dest: $ACTIVE/hello/comp/hi.bash
      policy: symlink
  - phase: post-place
    action: completion
    params:
      shell: bash
      name: hi
      source: $ACTIVE/hello/comp/hi.bash
  - phase: pre-place
    action: install
    params:
      src: $PKG/content/share/org.hello.App.desktop
      dest: $ACTIVE/hello/share/org.hello.App.desktop
      policy: symlink
  - phase: post-place
    action: desktop
    params:
      source: $ACTIVE/hello/share/org.hello.App.desktop
  - phase: pre-place
    action: install
    params:
      src: $PKG/content/share/org.hello.App.xml
      dest: $ACTIVE/hello/share/org.hello.App.xml
      policy: symlink
  - phase: post-place
    action: mime
    params:
      source: $ACTIVE/hello/share/org.hello.App.xml
`
	return buildTarZst(t, map[string]string{
		"polypkg.yaml":                        manifest,
		"content/bin/hi":                      "#!/bin/sh\necho hello from polypkg\n",
		"content/comp/hi.bash":                "# bash completion for hi\n",
		"content/share/org.hello.App.desktop": "[Desktop Entry]\nType=Application\nName=Hello\nExec=hi\n",
		"content/share/org.hello.App.xml": "<?xml version=\"1.0\"?>\n" +
			"<mime-info xmlns=\"http://www.freedesktop.org/standards/shared-mime-info\"></mime-info>\n",
	})
}

var _ = Describe("plan", func() {
	var (
		repoDir   string
		srv       *httptest.Server
		trustRoot string
		profile   string
	)

	BeforeEach(func() {
		IsolatedEnv(GinkgoTB())
		pkg := buildHelloPackage(GinkgoTB())
		repoDir = GinkgoT().TempDir()
		trustRoot = signRepo(GinkgoTB(), repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		srv = httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		DeferCleanup(srv.Close)
		profile = filepath.Join(GinkgoT().TempDir(), "profile.yaml")
		Expect(os.WriteFile(profile, []byte(installHelloProfile(GinkgoTB(), srv.URL, trustRoot)), 0o644)).To(Succeed())
	})

	It("treats first apply as every-package-added (exits non-zero)", func() {
		out, err := runPlanCmd(profile)
		Expect(err).To(HaveOccurred(), "plan should exit non-zero when changes pending")
		Expect(out).To(ContainSubstring("no current generation"))
		Expect(out).To(ContainSubstring("added packages"))
		Expect(out).To(ContainSubstring("hello"))
	})

	It("shows empty diff after applying an empty profile (exits 0)", func() {
		// The empty-profile path: an empty prior compared against an empty
		// projected next yields no diff. (The converging hello-profile case —
		// where the planner precomputes install content_hashes and normalizes
		// the dir-mode string format to match the runner's stored form — is
		// covered by the "converges" spec above.)
		emptyProfile := filepath.Join("..", "fixtures", "profiles", "empty.yaml")
		apply := cli.NewRootCmd()
		apply.SilenceUsage, apply.SilenceErrors = true, true
		var ab bytes.Buffer
		apply.SetOut(&ab)
		apply.SetErr(&ab)
		apply.SetArgs([]string{"apply", emptyProfile})
		Expect(apply.Execute()).To(Succeed(), "apply output: %s", ab.String())

		out, err := runPlanCmd(emptyProfile)
		Expect(err).NotTo(HaveOccurred(), "plan output: %s", out)
		Expect(out).To(ContainSubstring("no changes pending"))
	})

	It("converges: plan after applying the same profile reports no changes (exits 0)", func() {
		// Regression for the plan-after-apply convergence bug: the hello
		// fixture places BOTH a dir action (mode "0o755") and an install-symlink
		// action, so the two stored-vs-projected asymmetries are exercised — the
		// dir mode string format and the symlink install content_hash. A
		// converged system must report converged.
		apply := cli.NewRootCmd()
		apply.SilenceUsage, apply.SilenceErrors = true, true
		var ab bytes.Buffer
		apply.SetOut(&ab)
		apply.SetErr(&ab)
		apply.SetArgs([]string{"apply", profile})
		Expect(apply.Execute()).To(Succeed(), "apply output: %s", ab.String())

		out, err := runPlanCmd("--format", "json", profile)
		Expect(err).NotTo(HaveOccurred(), "plan should exit 0 after a converged apply; output: %s", out)
		lines := strings.Split(strings.TrimSpace(out), "\n")
		last := lines[len(lines)-1]
		pr, perr := schema.ParsePlanResult(strings.NewReader(last))
		Expect(perr).NotTo(HaveOccurred())
		Expect(pr.Exit).To(Equal(0), "plan result body: %s", last)
		Expect(pr.Ownership.Changed).To(BeEmpty(), "no ownership should be reported as changed: %s", last)
		Expect(pr.Ownership.Added).To(BeEmpty())
		Expect(pr.Ownership.Removed).To(BeEmpty())
		Expect(pr.Packages.Added).To(BeEmpty())

		text, terr := runPlanCmd(profile)
		Expect(terr).NotTo(HaveOccurred())
		Expect(text).To(ContainSubstring("no changes pending"))
	})

	It("converges: plan after applying a profile with path, completion, desktop, mime, and $ACTIVE-targeted symlink actions (exits 0)", func() {
		// Regression for the shared-area-action convergence bug. Two distinct
		// failures are covered:
		//   1. path/symlink (and any action whose source is a $ACTIVE/... path)
		//      store a fully $ACTIVE-expanded absolute link target at apply time,
		//      but the planner projected the unexpanded "$ACTIVE/..." literal — a
		//      converged system reported them changed forever.
		//   2. completion/desktop/mime have no dest/path param, so the planner
		//      derived an empty ownership path and filepath.Rel(active, "")
		//      hard-errored ("relativize \"\"") the instant a plan ran after an
		//      apply that placed any of them. The fixture exercises all four
		//      shared-area actions (bin/<name>, completions/<shell>/<hostfile>,
		//      applications/<base>, mime/<base>) plus a $ACTIVE-targeted symlink.
		pkg := buildSharedAreaActionPackage(GinkgoTB())
		pathRepoDir := GinkgoT().TempDir()
		pathTrustRoot := signRepo(GinkgoTB(), pathRepoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: pkg})
		pathSrv := httptest.NewServer(http.FileServer(http.Dir(pathRepoDir)))
		DeferCleanup(pathSrv.Close)
		pathProfile := filepath.Join(GinkgoT().TempDir(), "profile.yaml")
		Expect(os.WriteFile(pathProfile,
			[]byte(installHelloProfile(GinkgoTB(), pathSrv.URL, pathTrustRoot)), 0o644)).To(Succeed())

		apply := cli.NewRootCmd()
		apply.SilenceUsage, apply.SilenceErrors = true, true
		var ab bytes.Buffer
		apply.SetOut(&ab)
		apply.SetErr(&ab)
		apply.SetArgs([]string{"apply", pathProfile})
		Expect(apply.Execute()).To(Succeed(), "apply output: %s", ab.String())

		out, err := runPlanCmd("--format", "json", pathProfile)
		Expect(err).NotTo(HaveOccurred(), "plan should exit 0 after a converged apply; output: %s", out)
		lines := strings.Split(strings.TrimSpace(out), "\n")
		last := lines[len(lines)-1]
		pr, perr := schema.ParsePlanResult(strings.NewReader(last))
		Expect(perr).NotTo(HaveOccurred())
		Expect(pr.Exit).To(Equal(0), "plan result body: %s", last)
		Expect(pr.Ownership.Changed).To(BeEmpty(), "no ownership should be reported as changed: %s", last)
		Expect(pr.Ownership.Added).To(BeEmpty())
		Expect(pr.Ownership.Removed).To(BeEmpty())
		Expect(pr.Packages.Added).To(BeEmpty())
	})

	It("emits a polypkg.plan/v1 envelope under --format json", func() {
		out, _ := runPlanCmd("--format", "json", profile)
		// Take the last non-empty line in case warnings precede the JSON.
		lines := strings.Split(strings.TrimSpace(out), "\n")
		last := lines[len(lines)-1]
		pr, err := schema.ParsePlanResult(strings.NewReader(last))
		Expect(err).NotTo(HaveOccurred())
		Expect(pr.Schema).To(Equal("polypkg.plan/v1"))
		Expect(pr.Profile).To(Equal(profile))
		Expect(pr.Exit).To(Equal(2))
		Expect(pr.Packages.Added).To(HaveLen(1))
	})

	It("returns an error envelope under --format json on profile parse failure", func() {
		badProfile := filepath.Join(GinkgoT().TempDir(), "bad.yaml")
		Expect(os.WriteFile(badProfile, []byte("invalid: yaml: : :"), 0o644)).To(Succeed())
		cmd := cli.NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		cmd.SetArgs([]string{"--format", "json", "plan", badProfile})
		err := cmd.Execute()
		Expect(err).To(HaveOccurred())
		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		last := lines[len(lines)-1]
		r, perr := schema.ParseCLIResult(strings.NewReader(last))
		Expect(perr).NotTo(HaveOccurred())
		Expect(r.Status).To(Equal("error"))
	})
})

package integration

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/trevor-vaughan/polypkg/internal/cli"
)

// starlarkTimeoutLimit is a deliberately generous wall-clock cap for the
// !starlark evaluations these e2e tests trigger. The evaluator isolates each
// snippet in a re-exec'd subprocess; under `go test -race ./...` that child is
// the race-instrumented test binary, and dozens spawn concurrently across
// packages, so the production 2s default (schema.DefaultStarlarkLimits) can be
// exceeded by process startup alone. These tests assert functional behavior and
// step-limit enforcement, not wall-clock enforcement, so the cap is set high
// enough never to be the flaky variable.
const starlarkTimeoutLimit = "  timeout: 120s\n"

func starlarkProfile(url, trustRoot, starlarkBlock string) string {
	return "schema: polypkg.spec/v1\nname: sl\n" +
		"scopes:\n  user:\n    substrate: store\n    prefix: $XDG_DATA_HOME/polypkg\n" +
		"sources:\n  order: [native]\n  native:\n    type: polypkg-native\n" +
		"    url: " + url + "\n    trust_root: " + trustRoot + "\n" +
		starlarkBlock +
		"packages:\n  user:\n    hello:\n      version: \"=1.0.0\"\n"
}

// runStarlarkApply builds a one-package repo from the given artifact files,
// serves it, renders the profile (with optional starlark limits block), runs
// apply in-process, and returns combined stdout and the error.
func runStarlarkApply(t testing.TB, files map[string]string, starlarkBlock string) (string, error) {
	t.Helper()
	g := NewWithT(t)
	IsolatedEnv(t)
	artifact := buildTarZst(t, files)
	repoDir := t.TempDir()
	trustRoot := signRepo(t, repoDir, "native", 1,
		indexPkg{name: "hello", version: "1.0.0", artifact: artifact})
	srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
	defer srv.Close()

	profilePath := filepath.Join(t.TempDir(), "profile.yaml")
	g.Expect(os.WriteFile(profilePath, []byte(starlarkProfile(srv.URL, trustRoot, starlarkBlock)), 0o644)).To(Succeed())

	cmd := cli.NewRootCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"apply", profilePath})
	err := cmd.Execute()
	return out.String(), err
}

var _ = Describe("starlark", func() {
	It("installs a package whose dest is computed at evaluation time", func() {
		t := GinkgoTB()
		pkgYAML := "schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\n" +
			"actions:\n" +
			"  - phase: post-place\n    action: dir\n    params:\n      path: !starlark |\n        return \"$ACTIVE/hello/\" + host.arch\n" +
			"  - phase: post-place\n    action: install\n    params:\n      src: $PKG/bin/hi\n" +
			"      dest: !starlark |\n        return \"$ACTIVE/hello/\" + host.arch + \"/hi\"\n      policy: symlink\n"
		files := map[string]string{
			"polypkg.yaml": pkgYAML,
			"bin/hi":       "#!/bin/sh\necho hi\n",
		}
		out, err := runStarlarkApply(t, files, "starlark:\n"+starlarkTimeoutLimit)
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(ContainSubstring("applied generation"))

		dataHome := os.Getenv("XDG_DATA_HOME")
		hi := filepath.Join(dataHome, "polypkg", "active", "hello", runtime.GOARCH, "hi")
		_, statErr := os.Lstat(hi)
		Expect(statErr).NotTo(HaveOccurred(), "expected computed dest %s to exist", hi)
	})

	It("aborts when a starlark snippet returns a non-string result", func() {
		t := GinkgoTB()
		pkgYAML := "schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\n" +
			"actions:\n  - phase: post-place\n    action: dir\n    params:\n      path: !starlark |\n        return 123\n"
		_, err := runStarlarkApply(t, map[string]string{"polypkg.yaml": pkgYAML}, "starlark:\n"+starlarkTimeoutLimit)
		Expect(err).To(HaveOccurred())
		dataHome := os.Getenv("XDG_DATA_HOME")
		_, statErr := os.Lstat(filepath.Join(dataHome, "polypkg", "active"))
		Expect(statErr).To(HaveOccurred(), "no generation may activate when a snippet fails")
	})

	It("aborts when a snippet exceeds the configured step limit", func() {
		t := GinkgoTB()
		pkgYAML := "schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\n" +
			"actions:\n  - phase: post-place\n    action: dir\n    params:\n      path: !starlark |\n" +
			"        n = 0\n        for i in range(1000000):\n            n += i\n        return \"$ACTIVE/\" + str(n)\n"
		_, err := runStarlarkApply(t, map[string]string{"polypkg.yaml": pkgYAML}, "starlark:\n  max_steps: 200\n"+starlarkTimeoutLimit)
		Expect(err).To(HaveOccurred())
		dataHome := os.Getenv("XDG_DATA_HOME")
		_, statErr := os.Lstat(filepath.Join(dataHome, "polypkg", "active"))
		Expect(statErr).To(HaveOccurred())
	})
})

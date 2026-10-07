package integration

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/action"
	"github.com/trevor-vaughan/polypkg/internal/cli"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

const (
	extractedScript = "#!/bin/sh\necho hello from an extracted archive\n"
	extractedReadme = "hello, documented\n"
)

// buildHelloReleaseTarGz returns a .tar.gz shaped like an upstream release:
// everything under one hello-1.0.0/ directory, an executable, a relative
// in-archive symlink, and a nested documentation file.
func buildHelloReleaseTarGz(t testing.TB) []byte {
	t.Helper()
	g := NewWithT(t)
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, m := range []struct {
		name, body, link string
		typeflag         byte
		mode             int64
	}{
		{name: "hello-1.0.0/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "hello-1.0.0/bin/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "hello-1.0.0/bin/hello", typeflag: tar.TypeReg, mode: 0o755, body: extractedScript},
		{name: "hello-1.0.0/bin/hi", typeflag: tar.TypeSymlink, mode: 0o777, link: "hello"},
		{name: "hello-1.0.0/share/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "hello-1.0.0/share/doc/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "hello-1.0.0/share/doc/README", typeflag: tar.TypeReg, mode: 0o644, body: extractedReadme},
	} {
		g.Expect(tw.WriteHeader(&tar.Header{
			Name: m.name, Typeflag: m.typeflag, Mode: m.mode, Linkname: m.link, Size: int64(len(m.body)),
		})).To(Succeed())
		_, err := io.WriteString(tw, m.body)
		g.Expect(err).NotTo(HaveOccurred())
	}
	g.Expect(tw.Close()).To(Succeed())
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, err := zw.Write(raw.Bytes())
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(zw.Close()).To(Succeed())
	return gz.Bytes()
}

// extractPackage builds package `name` that ships the release archive under
// content/ and unpacks it into dest with strip_components: 1. A non-empty
// drift sets the action's drift policy.
func extractPackage(t testing.TB, name, dest, drift string) []byte {
	t.Helper()
	driftLine := ""
	if drift != "" {
		driftLine = "    drift: " + drift + "\n"
	}
	manifest := fmt.Sprintf(`schema: polypkg.package/v1
name: %s
version: 1.0.0
actions:
  - phase: post-place
    action: extract
%s    params:
      src: $PKG/content/hello-1.0.0.tar.gz
      dest: %s
      strip_components: 1
`, name, driftLine, dest)
	return buildTarZst(t, map[string]string{
		"polypkg.yaml":               manifest,
		"content/hello-1.0.0.tar.gz": string(buildHelloReleaseTarGz(t)),
	})
}

// extractEnv sandboxes HOME and every XDG directory variable.
func extractEnv(t testing.TB) {
	t.Helper()
	root := IsolatedEnv(t)
	t.Setenv("HOME", root)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(root, "cache"))
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(root, "runtime"))
	t.Setenv("XDG_CONFIG_DIRS", filepath.Join(root, "config-dirs"))
	t.Setenv("XDG_DATA_DIRS", filepath.Join(root, "data-dirs"))
}

// serveExtractRepo signs pkgs into a fresh repository and serves it for the
// rest of the spec, returning the URL and trust-root path.
func serveExtractRepo(t testing.TB, pkgs ...indexPkg) (url, trustRoot string) {
	t.Helper()
	repoDir := t.TempDir()
	trustRoot = signRepo(t, repoDir, "native", 1, pkgs...)
	srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
	DeferCleanup(srv.Close)
	return srv.URL, trustRoot
}

// readExtractEntries returns generation gen's extract ownership entries keyed
// by path, failing if any path is recorded twice.
func readExtractEntries(t testing.TB, gen int) map[string]schema.OwnershipEntry {
	t.Helper()
	g := NewWithT(t)
	f, err := os.Open(filepath.Join(os.Getenv("XDG_DATA_HOME"), "polypkg", "generations", strconv.Itoa(gen), "ownership.json"))
	g.Expect(err).NotTo(HaveOccurred())
	defer f.Close()
	own, err := schema.ParseOwnership(f)
	g.Expect(err).NotTo(HaveOccurred())
	out := map[string]schema.OwnershipEntry{}
	for _, e := range own.Entries {
		if e.Action != "extract" {
			continue
		}
		g.Expect(out).NotTo(HaveKey(e.Path), "each placed path is recorded once")
		out[e.Path] = e
	}
	return out
}

// activePath is rel inside the active generation.
func activePath(rel string) string {
	return filepath.Join(os.Getenv("XDG_DATA_HOME"), "polypkg", "active", filepath.FromSlash(rel))
}

var _ = Describe("extract action e2e", func() {
	It("records one ownership entry per placed path", func() {
		t := GinkgoTB()
		extractEnv(t)
		url, trust := serveExtractRepo(t, indexPkg{name: "hello", version: "1.0.0",
			artifact: extractPackage(t, "hello", "$ACTIVE/hello/dist", "")})

		out, err := applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred(), out)

		got := map[string]schema.Expected{}
		for p, e := range readExtractEntries(t, 1) {
			Expect(e.Package).To(Equal("hello"))
			Expect(e.DriftPolicy).To(Equal("notify_heal"))
			Expect(e.Stat.Inode).NotTo(BeZero(), "stat captured for %s", p)
			got[p] = e.Expected
		}
		Expect(got).To(Equal(map[string]schema.Expected{
			"hello/dist":                  {FileType: "dir", Mode: "0700"},
			"hello/dist/bin":              {FileType: "dir", Mode: "0700"},
			"hello/dist/bin/hello":        {FileType: "regular", ContentHash: blakeHash([]byte(extractedScript)), Mode: "0755"},
			"hello/dist/bin/hi":           {FileType: "symlink", Target: "hello"},
			"hello/dist/share":            {FileType: "dir", Mode: "0700"},
			"hello/dist/share/doc":        {FileType: "dir", Mode: "0700"},
			"hello/dist/share/doc/README": {FileType: "regular", ContentHash: blakeHash([]byte(extractedReadme)), Mode: "0644"},
		}))

		info, err := os.Lstat(activePath("hello/dist/bin/hello"))
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().IsRegular()).To(BeTrue(), "an extracted file is a real file, not a link into the extract cache")
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o755)))
		body, err := os.ReadFile(activePath("hello/dist/bin/hello"))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(body)).To(Equal(extractedScript))
	})

	It("keeps two packages that extract identical layouts in their own namespaces", func() {
		t := GinkgoTB()
		extractEnv(t)
		url, trust := serveExtractRepo(t,
			indexPkg{name: "alpha", version: "1.0.0", artifact: extractPackage(t, "alpha", "$ACTIVE/alpha/dist", "")},
			indexPkg{name: "bravo", version: "1.0.0", artifact: extractPackage(t, "bravo", "$ACTIVE/bravo/dist", "")})

		out, err := applyProfileWith(t, url, trust, "alpha", "bravo")
		Expect(err).NotTo(HaveOccurred(), out)

		entries := readExtractEntries(t, 1)
		Expect(entries).To(HaveKey("alpha/dist/bin/hello"))
		Expect(entries).To(HaveKey("bravo/dist/bin/hello"))
		Expect(entries["alpha/dist/bin/hello"].Package).To(Equal("alpha"))
		Expect(entries["bravo/dist/bin/hello"].Package).To(Equal("bravo"))
		Expect(entries).To(HaveLen(14), "seven paths per package, none shared")
	})

	It("refuses an extract into another package's namespace and commits no generation", func() {
		t := GinkgoTB()
		extractEnv(t)
		url, trust := serveExtractRepo(t,
			indexPkg{name: "alpha", version: "1.0.0", artifact: extractPackage(t, "alpha", "$ACTIVE/bravo/dist", "")},
			indexPkg{name: "bravo", version: "1.0.0", artifact: extractPackage(t, "bravo", "$ACTIVE/bravo/other", "")})

		out, err := applyProfileWith(t, url, trust, "alpha", "bravo")
		Expect(err).To(HaveOccurred())
		Expect(err.Error() + out).To(ContainSubstring("outside the package scope"))
		_, statErr := os.Lstat(filepath.Join(os.Getenv("XDG_DATA_HOME"), "polypkg", "active"))
		Expect(os.IsNotExist(statErr)).To(BeTrue(), "no generation may be activated")
		_, statErr = os.Stat(filepath.Join(os.Getenv("XDG_DATA_HOME"), "polypkg", "generations", "1"))
		Expect(os.IsNotExist(statErr)).To(BeTrue(), "the staged generation must be removed on abort")
	})

	It("reports an edited extracted file under its own path in status -vv, and apply heals it", func() {
		t := GinkgoTB()
		extractEnv(t)
		url, trust := serveExtractRepo(t, indexPkg{name: "hello", version: "1.0.0",
			artifact: extractPackage(t, "hello", "$ACTIVE/hello/dist", "")})
		out, err := applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred(), out)

		Expect(os.WriteFile(activePath("hello/dist/bin/hello"), []byte("#!/bin/sh\necho tampered\n"), 0o755)).To(Succeed())

		out, err = runStatusCmd("-vv")
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(ContainSubstring("hello/dist/bin/hello (extract): content [policy: notify_heal]"))

		out, err = applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(out).To(ContainSubstring("applied generation"))
		body, err := os.ReadFile(activePath("hello/dist/bin/hello"))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(body)).To(Equal(extractedScript))
		out, err = runStatusCmd("-vv")
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(ContainSubstring("drift: 0 entries"))
	})

	It("reports a mode change on an extracted file in status -vv, and apply heals it", func() {
		t := GinkgoTB()
		extractEnv(t)
		url, trust := serveExtractRepo(t, indexPkg{name: "hello", version: "1.0.0",
			artifact: extractPackage(t, "hello", "$ACTIVE/hello/dist", "")})
		out, err := applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred(), out)

		Expect(os.Chmod(activePath("hello/dist/share/doc/README"), 0o600)).To(Succeed())

		out, err = runStatusCmd("-vv")
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(ContainSubstring("hello/dist/share/doc/README (extract): mode [policy: notify_heal]"))

		out, err = applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred(), out)
		info, err := os.Lstat(activePath("hello/dist/share/doc/README"))
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o644)))
		out, err = runStatusCmd("-vv")
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(ContainSubstring("drift: 0 entries"))
	})

	It("lets accept-drift unblock a refused content edit to an extracted file", func() {
		t := GinkgoTB()
		extractEnv(t)
		url, trust := serveExtractRepo(t, indexPkg{name: "hello", version: "1.0.0",
			artifact: extractPackage(t, "hello", "$ACTIVE/hello/dist", "refuse")})
		out, err := applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred(), out)

		Expect(os.WriteFile(activePath("hello/dist/bin/hello"), []byte("#!/bin/sh\necho local\n"), 0o755)).To(Succeed())

		_, err = applyHelloOnce(t, url, trust)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("apply refused"))

		root := cli.NewRootCmd()
		root.SilenceUsage, root.SilenceErrors = true, true
		root.SetOut(&bytes.Buffer{})
		root.SetErr(&bytes.Buffer{})
		root.SetArgs([]string{"accept-drift", "hello/dist/bin/hello"})
		Expect(root.Execute()).To(Succeed())

		out, err = applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(out).To(ContainSubstring("applied generation"))
	})

	It("plans no changes after applying an extract package", func() {
		t := GinkgoTB()
		extractEnv(t)
		url, trust := serveExtractRepo(t, indexPkg{name: "hello", version: "1.0.0",
			artifact: extractPackage(t, "hello", "$ACTIVE/hello/dist", "")})
		out, err := applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred(), out)

		out, err = planProfileWith(t, url, trust, "hello")
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(out).To(ContainSubstring("no changes pending"))
	})

	It("enforces a later perms mode on an extracted file without perpetual drift", func() {
		t := GinkgoTB()
		extractEnv(t)
		manifest := `schema: polypkg.package/v1
name: hello
version: 1.0.0
actions:
  - phase: post-place
    action: extract
    drift: refuse
    params:
      src: $PKG/content/hello-1.0.0.tar.gz
      dest: $ACTIVE/hello/dist
      strip_components: 1
  - phase: post-place
    action: perms
    drift: refuse
    params:
      path: $ACTIVE/hello/dist/share/doc/README
      mode: "0600"
`
		url, trust := serveExtractRepo(t, indexPkg{name: "hello", version: "1.0.0",
			artifact: buildTarZst(t, map[string]string{
				"polypkg.yaml":               manifest,
				"content/hello-1.0.0.tar.gz": string(buildHelloReleaseTarGz(t)),
			})})
		out, err := applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred(), out)
		info, err := os.Lstat(activePath("hello/dist/share/doc/README"))
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o600)))

		out, err = runStatusCmd("-vv")
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(ContainSubstring("drift: 0 entries"))

		out, err = applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred(), "a refuse policy must not refuse a converged path: %s", out)
		Expect(out).NotTo(ContainSubstring("drift"))

		out, err = planProfileWith(t, url, trust, "hello")
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(out).To(ContainSubstring("no changes pending"))
	})

	It("plans no changes after apply when a perms is declared before the earlier-phase dir it re-modes", func() {
		t := GinkgoTB()
		extractEnv(t)
		manifest := `schema: polypkg.package/v1
name: hello
version: 1.0.0
actions:
  - phase: post-place
    action: perms
    params:
      path: $ACTIVE/hello/var
      mode: "0700"
  - phase: pre-place
    action: dir
    params:
      path: $ACTIVE/hello/var
      mode: "0755"
`
		url, trust := serveExtractRepo(t, indexPkg{name: "hello", version: "1.0.0",
			artifact: buildTarZst(t, map[string]string{"polypkg.yaml": manifest})})
		out, err := applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred(), out)

		out, err = planProfileWith(t, url, trust, "hello")
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(out).To(ContainSubstring("no changes pending"))
	})

	It("plans no changes after applying an extract package in system scope", func() {
		t := GinkgoTB()
		extractEnv(t)
		url, trust := serveExtractRepo(t, indexPkg{name: "hello", version: "1.0.0",
			artifact: extractPackage(t, "hello", "$ACTIVE/hello/dist", "")})
		profilePath := filepath.Join(t.TempDir(), "system.yaml")
		Expect(os.WriteFile(profilePath, []byte(installHelloSystemProfile(t, url, trust)), 0o644)).To(Succeed())
		prefix := t.TempDir()
		run := func(verb string) (string, error) {
			root := cli.NewRootCmd()
			root.SilenceUsage, root.SilenceErrors = true, true
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&out)
			root.SetArgs([]string{verb, "--scope", "system", "--prefix", prefix, profilePath})
			err := root.Execute()
			return out.String(), err
		}

		out, err := run("apply")
		Expect(err).NotTo(HaveOccurred(), out)
		// System-scope directories are 0755, not the user scope's 0700; the
		// projection must use the same mode or every dir reports a change.
		out, err = run("plan")
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(out).To(ContainSubstring("no changes pending"))
	})

	It("extracts each archive exactly once per apply", func() {
		t := GinkgoTB()
		extractEnv(t)
		url, trust := serveExtractRepo(t, indexPkg{name: "hello", version: "1.0.0",
			artifact: extractPackage(t, "hello", "$ACTIVE/hello/dist", "")})
		spec := action.Registry["extract"]
		calls := 0
		counted := spec
		counted.MultiHandler = func(inv action.Invocation, scope action.Scope) ([]action.Result, error) {
			calls++
			return spec.MultiHandler(inv, scope)
		}
		action.Registry["extract"] = counted
		DeferCleanup(func() { action.Registry["extract"] = spec })

		out, err := applyHelloOnce(t, url, trust)
		Expect(err).NotTo(HaveOccurred(), out)
		Expect(calls).To(Equal(1), "apply never reads the projected ownership, so it must not extract to project it")
	})
})

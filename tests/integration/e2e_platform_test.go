package integration

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/cli"
	"github.com/trevor-vaughan/polypkg/internal/platform"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// countingServer file-serves a directory over HTTP and counts requests per URL
// path, so a spec can prove that a published file was never fetched.
type countingServer struct {
	*httptest.Server
	mu   sync.Mutex
	hits map[string]int
}

// newCountingServer starts a countingServer over dir and closes it when the
// enclosing Ginkgo node's cleanup runs.
func newCountingServer(dir string) *countingServer {
	cs := &countingServer{hits: map[string]int{}}
	files := http.FileServer(http.Dir(dir))
	cs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.mu.Lock()
		cs.hits[r.URL.Path]++
		cs.mu.Unlock()
		files.ServeHTTP(w, r)
	}))
	DeferCleanup(cs.Close)
	return cs
}

// fetches counts the requests for the repository-relative path rel and for its
// detached signature rel+".minisig".
func (cs *countingServer) fetches(rel string) int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.hits["/"+rel] + cs.hits["/"+rel+".minisig"]
}

// platformPkgSource scaffolds a package source for <name> 1.0.0 under
// workDir/pkgs and returns its path. A non-empty plat is written as the
// recipe's platform: key; "" omits the key, making the package
// platform-agnostic. The installed command prints "<name> <plat>" ("any" when
// plat is empty), so a spec can tell which artifact was installed.
func platformPkgSource(workDir, name, plat string) string {
	label := plat
	platformKey := ""
	if plat == "" {
		label = platform.Any
	} else {
		platformKey = "platform: " + plat + "\n"
	}
	srcDir := filepath.Join(workDir, "pkgs", name+"-"+strings.ReplaceAll(label, "/", "-"))
	Expect(os.MkdirAll(filepath.Join(srcDir, "content", "bin"), 0o755)).To(Succeed())

	manifest := fmt.Sprintf(`schema: polypkg.package/v1
name: %[1]s
version: 1.0.0
%[2]sactions:
  - phase: post-place
    action: dir
    params:
      path: $ACTIVE/%[1]s/bin
      mode: "0o755"
  - phase: post-place
    action: install
    params:
      src: $PKG/content/bin/%[1]s
      dest: $ACTIVE/%[1]s/bin/%[1]s
`, name, platformKey)
	Expect(os.WriteFile(filepath.Join(srcDir, "polypkg.yaml"), []byte(manifest), 0o644)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(srcDir, "content", "bin", name),
		[]byte("#!/bin/sh\necho "+name+" "+label+"\n"), 0o755)).To(Succeed())
	return srcDir
}

// publishedPaths maps each of name's index entries, keyed by platform ("" for a
// platform-agnostic entry), to every pool path it references: the artifact
// first, then each attestation blob.
func publishedPaths(idx *schema.Index, name string) map[string][]string {
	out := make(map[string][]string, len(idx.Packages[name]))
	for _, e := range idx.Packages[name] {
		paths := make([]string, 0, 1+len(e.Attestations))
		paths = append(paths, e.Artifact)
		for _, a := range e.Attestations {
			paths = append(paths, a.Artifact)
		}
		out[e.Platform] = paths
	}
	return out
}

var _ = Describe("platform-aware index", Ordered, func() {
	var (
		host, other string
		publicDir   string
		profilePath string
		srv         *countingServer
		hello       map[string][]string
		greet       map[string][]string
		onlyOther   map[string][]string
		foreign     []string
	)

	// expectNeverFetched fails if any pool file published only for the other
	// platform has been requested so far in this ordered run.
	expectNeverFetched := func() {
		GinkgoHelper()
		for _, rel := range foreign {
			Expect(srv.fetches(rel)).To(BeZero(),
				"%s is published only for %s and must never be fetched on %s", rel, other, host)
		}
	}

	BeforeAll(func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		t.Setenv("POLYPKG_REPO_KEY_PASSWORD", "pw")

		// Publish for this host plus one real platform that is not this host, so
		// the spec holds wherever it runs. On a linux/amd64 runner the pair is
		// linux/amd64 + darwin/arm64.
		host = platform.Host()
		other = "darwin/arm64"
		if host == other {
			other = "linux/amd64"
		}

		workDir := t.TempDir()
		repoDir := filepath.Join(workDir, "repo")
		keyDir := filepath.Join(workDir, "keys")
		manifest := filepath.Join(repoDir, "polypkg-repo.yaml")

		out, err := runCmd("repo", "init", repoDir, "--source", "native", "--key-dir", keyDir)
		Expect(err).NotTo(HaveOccurred(), "repo init: %s", out)
		for _, src := range []string{
			platformPkgSource(workDir, "hello", host),
			platformPkgSource(workDir, "hello", other),
			platformPkgSource(workDir, "greet", ""),
			platformPkgSource(workDir, "onlyother", other),
		} {
			out, err = runCmd("repo", "add", src, "--manifest", manifest, "--key-dir", keyDir)
			Expect(err).NotTo(HaveOccurred(), "repo add %s: %s", src, out)
		}

		publicDir = filepath.Join(repoDir, "public")
		f, err := os.Open(filepath.Join(publicDir, "index.json"))
		Expect(err).NotTo(HaveOccurred())
		idx, perr := schema.ParseIndex(f)
		Expect(f.Close()).To(Succeed())
		Expect(perr).NotTo(HaveOccurred())
		hello = publishedPaths(idx, "hello")
		greet = publishedPaths(idx, "greet")
		onlyOther = publishedPaths(idx, "onlyother")

		// foreign is every pool file published only for the other platform. A
		// blob shared with an installable entry is excluded, so the
		// never-fetched assertion cannot fire on a legitimate download.
		installable := map[string]bool{}
		for _, p := range append(append([]string{}, hello[host]...), greet[""]...) {
			installable[p] = true
		}
		for _, p := range append(append([]string{}, hello[other]...), onlyOther[other]...) {
			if !installable[p] {
				foreign = append(foreign, p)
			}
		}
		sort.Strings(foreign)

		srv = newCountingServer(publicDir)
		profilePath = filepath.Join(workDir, "profile.yaml")
		profile := fmt.Sprintf(`schema: polypkg.spec/v1
name: platform-test
scopes:
  user:
    substrate: store
    prefix: $XDG_DATA_HOME/polypkg
sources:
  order: [native]
  native:
    type: polypkg-native
    url: %s
    trust_root: %s
`, srv.URL, filepath.Join(publicDir, "trust_root.pub"))
		Expect(os.WriteFile(profilePath, []byte(profile), 0o644)).To(Succeed())
		t.Setenv("POLYPKG_PROFILE", profilePath)
	})

	It("publishes hello once per platform and greet without a platform", func() {
		Expect(hello).To(HaveLen(2))
		Expect(hello).To(HaveKey(host))
		Expect(hello).To(HaveKey(other))
		Expect(hello[host][0]).NotTo(Equal(hello[other][0]),
			"each platform must publish its own artifact")
		Expect(greet).To(HaveLen(1))
		Expect(greet).To(HaveKey(""),
			"a recipe without platform: must publish a platform-agnostic entry")
		Expect(onlyOther).To(HaveLen(1))
		Expect(onlyOther).To(HaveKey(other))
		Expect(foreign).NotTo(BeEmpty())
	})

	It("signs each artifact's platform into its trusted comment", func() {
		for _, c := range []struct{ name, artifact, claim string }{
			{"hello", hello[host][0], "platform=" + host},
			{"hello", hello[other][0], "platform=" + other},
			{"greet", greet[""][0], "platform=" + platform.Any},
		} {
			sig, err := os.ReadFile(filepath.Join(publicDir, c.artifact+".minisig"))
			Expect(err).NotTo(HaveOccurred())
			Expect(string(sig)).To(ContainSubstring(
				"trusted comment: name=" + c.name + " version=1.0.0 " + c.claim + " hash=blake3:"))
		}
	})

	It("install hello installs the host's artifact and never fetches the other platform's", func() {
		out, err := runCmd("install", "hello")
		Expect(err).NotTo(HaveOccurred(), "install hello: %s", out)
		Expect(out).To(ContainSubstring("applied generation"))

		installed, rerr := os.ReadFile(filepath.Join(
			os.Getenv("XDG_DATA_HOME"), "polypkg", "active", "hello", "bin", "hello"))
		Expect(rerr).NotTo(HaveOccurred())
		Expect(string(installed)).To(Equal("#!/bin/sh\necho hello " + host + "\n"))

		Expect(srv.fetches(hello[host][0])).To(BeNumerically(">=", 2),
			"the host artifact and its signature must both be fetched")
		expectNeverFetched()
	})

	It("install greet installs the platform-agnostic package", func() {
		out, err := runCmd("install", "greet")
		Expect(err).NotTo(HaveOccurred(), "install greet: %s", out)

		installed, rerr := os.ReadFile(filepath.Join(
			os.Getenv("XDG_DATA_HOME"), "polypkg", "active", "greet", "bin", "greet"))
		Expect(rerr).NotTo(HaveOccurred())
		Expect(string(installed)).To(Equal("#!/bin/sh\necho greet " + platform.Any + "\n"))

		Expect(srv.fetches(greet[""][0])).To(BeNumerically(">=", 2))
		expectNeverFetched()
	})

	It("info hello names both platforms published for 1.0.0", func() {
		out, err := runCmd("info", "hello")
		Expect(err).NotTo(HaveOccurred(), "info hello: %s", out)
		Expect(out).To(ContainSubstring(host),
			"info must show the platform it installs; output:\n%s", out)
		Expect(out).To(ContainSubstring(other),
			"info must list the other published platform; output:\n%s", out)
		expectNeverFetched()
	})

	It("refuses a package published only for another platform and leaves the profile unchanged", func() {
		before, err := os.ReadFile(profilePath)
		Expect(err).NotTo(HaveOccurred())

		out, err := runCmd("install", "onlyother")
		Expect(err).To(HaveOccurred(), "install onlyother must fail on %s; output: %s", host, out)
		var ce *cli.CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected *cli.CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring(
			fmt.Sprintf("onlyother 1.0.0 is published for %s; this host is %s", other, host)))

		after, err := os.ReadFile(profilePath)
		Expect(err).NotTo(HaveOccurred())
		Expect(after).To(Equal(before), "a refused install must not edit the profile")
		expectNeverFetched()
	})
})

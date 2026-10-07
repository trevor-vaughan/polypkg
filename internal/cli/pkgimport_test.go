package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/cobra"

	"github.com/trevor-vaughan/polypkg/internal/ghrelease"
	"github.com/trevor-vaughan/polypkg/internal/ghrelease/ghreleasetest"
	"github.com/trevor-vaughan/polypkg/internal/importer"
	"github.com/trevor-vaughan/polypkg/internal/pkglint"
)

// helloArchive is a release archive holding <top>/hello, executable.
func helloArchive(top string) []byte {
	GinkgoHelper()
	b, err := ghreleasetest.TarGz(ghreleasetest.TarEntry{
		Name: top + "/hello", Mode: 0o755, Body: []byte("#!/bin/sh\necho hello\n"),
	})
	Expect(err).NotTo(HaveOccurred())
	return b
}

// importRelease is the upstream most specs import: acme/hello v1.2.0 with
// attested linux/amd64 and linux/arm64 archives and a Windows zip the
// importer skips.
func importRelease() ghreleasetest.Release {
	GinkgoHelper()
	return ghreleasetest.Release{
		Owner: "acme", Repo: "hello", Tag: "v1.2.0", Description: "Says hello.",
		Assets: []ghreleasetest.Asset{
			{Name: "hello_1.2.0_linux_amd64.tar.gz", Data: helloArchive("hello_1.2.0_linux_amd64"), Attest: true},
			{Name: "hello_1.2.0_linux_arm64.tar.gz", Data: helloArchive("hello_1.2.0_linux_arm64"), Attest: true},
			{Name: "hello_1.2.0_windows_amd64.zip", Data: []byte("not a zip; skipped by name")},
		},
	}
}

// singleAsset is a one-platform release of acme/hello v1.2.0 holding a.
func singleAsset(a ghreleasetest.Asset) ghreleasetest.Release {
	return ghreleasetest.Release{Owner: "acme", Repo: "hello", Tag: "v1.2.0", Assets: []ghreleasetest.Asset{a}}
}

// startFake serves rel for the spec's lifetime and writes the fake's trusted
// root to a file. It returns the API URL, the fake (for its request log),
// and the root file's path.
func startFake(rel ghreleasetest.Release) (string, *ghreleasetest.Fake, string) {
	GinkgoHelper()
	fake, err := ghreleasetest.New(rel)
	Expect(err).NotTo(HaveOccurred())
	srv := httptest.NewServer(fake)
	DeferCleanup(srv.Close)
	rootPath := filepath.Join(GinkgoT().TempDir(), "trusted_root.json")
	Expect(os.WriteFile(rootPath, fake.TrustedRoot(), 0o600)).To(Succeed())
	return srv.URL, fake, rootPath
}

// importOut is a fresh, not-yet-existing output directory.
func importOut() string {
	return filepath.Join(GinkgoT().TempDir(), "imports")
}

// lineWith returns the first line of s containing sub, or "".
func lineWith(s, sub string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, sub) {
			return l
		}
	}
	return ""
}

type importEnvelope struct {
	Schema  string `json:"schema"`
	Command string `json:"command"`
	Status  string `json:"status"`
	Error   string `json:"error"`
	Hint    string `json:"hint"`
	Data    struct {
		Release     string `json:"release"`
		Name        string `json:"name"`
		Version     string `json:"version"`
		TrustedRoot string `json:"trusted_root"`
		Platforms   []struct {
			Platform     string   `json:"platform"`
			Asset        string   `json:"asset"`
			Integrity    string   `json:"integrity"`
			Attestations int      `json:"attestations"`
			Dir          string   `json:"dir"`
			Warnings     []string `json:"warnings"`
		} `json:"platforms"`
		Skipped []struct {
			Name   string `json:"name"`
			Reason string `json:"reason"`
		} `json:"skipped"`
		Next []string `json:"next"`
	} `json:"data"`
}

var _ = Describe("pkg import", func() {
	BeforeEach(func() {
		sandboxUserEnv(GinkgoTB())
		GinkgoT().Setenv("GITHUB_TOKEN", "")
		GinkgoT().Setenv("GH_TOKEN", "")
	})

	It("imports every platform, prints the summary and the next commands", func() {
		api, _, rootPath := startFake(importRelease())
		out := importOut()

		stdout, stderr, code := runRoot("pkg", "import", "github:acme/hello@v1.2.0", out,
			"--api-url", api, "--trusted-root", rootPath)

		Expect(code).To(BeZero(), stderr)
		Expect(stdout).To(ContainSubstring("Imported hello 1.2.0 from github:acme/hello@v1.2.0"))
		Expect(stdout).To(MatchRegexp(`linux/amd64\s+hello_1\.2\.0_linux_amd64\.tar\.gz\s+github-digest\s+1\s`))
		Expect(stdout).To(MatchRegexp(`linux/arm64\s+hello_1\.2\.0_linux_arm64\.tar\.gz\s+github-digest\s+1\s`))
		Expect(stdout).To(ContainSubstring("hello_1.2.0_windows_amd64.zip"))
		Expect(stdout).To(ContainSubstring(`note: linux/amd64: skipped an attestation with predicate type "https://in-toto.io/attestation/release/v0.2"`),
			"GitHub's release attestation is noted and skipped, not carried")

		amd := filepath.Join(out, "hello", "1.2.0", "linux-amd64")
		arm := filepath.Join(out, "hello", "1.2.0", "linux-arm64")
		add := lineWith(stdout, "polypkg repo add ")
		Expect(add).To(ContainSubstring(amd))
		Expect(add).To(ContainSubstring(arm))
		// The next commands use ./polypkg-repo.yaml, and a manifest's
		// sigstore_roots resolve against its own directory.
		cwd, err := os.Getwd()
		Expect(err).NotTo(HaveOccurred())
		rel, err := filepath.Rel(cwd, filepath.Join(out, "sigstore-trusted-root.json"))
		Expect(err).NotTo(HaveOccurred())
		Expect(lineWith(stdout, "sigstore_roots:")).To(HaveSuffix(`(relative to that file):  sigstore_roots: ["` + rel + `"]`))
		Expect(stdout).To(ContainSubstring("polypkg repo build"))

		for dir, asset := range map[string]string{amd: "hello_1.2.0_linux_amd64", arm: "hello_1.2.0_linux_arm64"} {
			res, err := pkglint.Lint(dir)
			Expect(err).NotTo(HaveOccurred())
			Expect(res.Findings).To(BeEmpty(), dir)
			Expect(os.ReadFile(filepath.Join(dir, "content", asset+".tar.gz"))).To(Equal(helloArchive(asset)),
				"the content file must be the upstream asset byte for byte")
			atts, err := filepath.Glob(filepath.Join(dir, "attestations", "*.json"))
			Expect(err).NotTo(HaveOccurred())
			Expect(atts).To(HaveLen(1), dir)
		}
		Expect(filepath.Join(out, "sigstore-trusted-root.json")).To(BeAnExistingFile())
	})

	It("emits the result as a cli-result envelope under --format json", func() {
		api, _, rootPath := startFake(importRelease())
		out := importOut()

		stdout, stderr, code := runRoot("--format", "json", "pkg", "import", "github:acme/hello@v1.2.0", out,
			"--api-url", api, "--trusted-root", rootPath)

		Expect(code).To(BeZero(), stderr)
		Expect(strings.Count(strings.TrimSpace(stdout), "\n")).To(BeZero(), "stdout must be one JSON document")
		var env importEnvelope
		Expect(json.Unmarshal([]byte(stdout), &env)).To(Succeed())
		Expect(env.Schema).To(Equal("polypkg.cli-result/v2"))
		Expect(env.Command).To(Equal("pkg import"))
		Expect(env.Status).To(Equal("ok"))
		Expect(env.Data.Release).To(Equal("github:acme/hello@v1.2.0"))
		Expect(env.Data.Name).To(Equal("hello"))
		Expect(env.Data.Version).To(Equal("1.2.0"))
		Expect(env.Data.TrustedRoot).To(Equal(filepath.Join(out, "sigstore-trusted-root.json")))
		Expect(env.Data.Platforms).To(HaveLen(2))
		for _, p := range env.Data.Platforms {
			Expect(p.Integrity).To(Equal("github-digest"))
			Expect(p.Attestations).To(Equal(1))
			Expect(p.Warnings).NotTo(BeNil())
			Expect(p.Dir).To(Equal(filepath.Join(out, "hello", "1.2.0", strings.ReplaceAll(p.Platform, "/", "-"))))
		}
		Expect(env.Data.Skipped).To(ContainElement(HaveField("Name", "hello_1.2.0_windows_amd64.zip")))
		Expect(env.Data.Next).To(HaveLen(2))
		Expect(env.Data.Next[0]).To(HavePrefix("polypkg repo add "))
		Expect(env.Data.Next[1]).To(Equal("polypkg repo build"))
	})

	It("passes --name, --version and --bin through to the generated source", func() {
		archive, err := ghreleasetest.TarGz(ghreleasetest.TarEntry{
			Name: "greeter-9/bin/greet", Mode: 0o755, Body: []byte("#!/bin/sh\necho hi\n"),
		})
		Expect(err).NotTo(HaveOccurred())
		api, _, rootPath := startFake(singleAsset(ghreleasetest.Asset{
			Name: "greeter_linux_amd64.tar.gz", Data: archive, Attest: true,
		}))
		out := importOut()

		_, stderr, code := runRoot("pkg", "import", "github:acme/hello@v1.2.0", out,
			"--api-url", api, "--trusted-root", rootPath,
			"--name", "greeter", "--version", "9.9.9", "--bin", "greet")

		Expect(code).To(BeZero(), stderr)
		dir := filepath.Join(out, "greeter", "9.9.9", "linux-amd64")
		recipe, err := os.ReadFile(filepath.Join(dir, "polypkg.yaml"))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(recipe)).To(ContainSubstring("name: greeter"))
		Expect(string(recipe)).To(ContainSubstring("version: 9.9.9"))
		Expect(string(recipe)).To(ContainSubstring("bin/greet"))
		res, err := pkglint.Lint(dir)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Findings).To(BeEmpty())
	})

	It("imports an unattested platform unless --require-attestation is set", func() {
		api, _, rootPath := startFake(singleAsset(ghreleasetest.Asset{
			Name: "hello_1.2.0_linux_amd64.tar.gz", Data: helloArchive("hello_1.2.0_linux_amd64"),
		}))

		stdout, stderr, code := runRoot("pkg", "import", "github:acme/hello@v1.2.0", importOut(),
			"--api-url", api, "--trusted-root", rootPath)
		Expect(code).To(BeZero(), stderr)
		Expect(stdout).To(MatchRegexp(`linux/amd64\s+\S+\s+github-digest\s+0\s`))

		refused := importOut()
		_, _, code = runRoot("pkg", "import", "github:acme/hello@v1.2.0", refused,
			"--api-url", api, "--trusted-root", rootPath, "--require-attestation")
		Expect(code).NotTo(BeZero())
		Expect(filepath.Join(refused, "hello")).NotTo(BeAnExistingFile())
	})

	It("imports an asset with no published digest only under --insecure-skip-digest", func() {
		api, _, rootPath := startFake(singleAsset(ghreleasetest.Asset{
			Name: "hello_1.2.0_linux_amd64.tar.gz", Data: helloArchive("hello_1.2.0_linux_amd64"), OmitDigest: true,
		}))

		refused := importOut()
		_, _, code := runRoot("pkg", "import", "github:acme/hello@v1.2.0", refused,
			"--api-url", api, "--trusted-root", rootPath)
		Expect(code).NotTo(BeZero())
		Expect(filepath.Join(refused, "hello")).NotTo(BeAnExistingFile())

		stdout, stderr, code := runRoot("pkg", "import", "github:acme/hello@v1.2.0", importOut(),
			"--api-url", api, "--trusted-root", rootPath, "--insecure-skip-digest")
		Expect(code).To(BeZero(), stderr)
		Expect(stdout).To(MatchRegexp(`linux/amd64\s+\S+\s+UNVERIFIED\s`))
		Expect(stdout).To(ContainSubstring("warning: linux/amd64: hello_1.2.0_linux_amd64.tar.gz has no published digest"))
	})

	It("forces a platform's asset with --platform OS/ARCH=GLOB", func() {
		rel := ghreleasetest.Release{Owner: "acme", Repo: "hello", Tag: "v1.2.0", Assets: []ghreleasetest.Asset{
			{Name: "hello_1.2.0_linux_amd64.tar.gz", Data: helloArchive("a"), Attest: true},
			{Name: "hello_1.2.0_linux_x86_64.tar.gz", Data: helloArchive("b"), Attest: true},
		}}
		api, _, rootPath := startFake(rel)

		stdout, stderr, code := runRoot("pkg", "import", "github:acme/hello@v1.2.0", importOut(),
			"--api-url", api, "--trusted-root", rootPath, "--platform", "linux/amd64=*_x86_64.tar.gz")

		Expect(code).To(BeZero(), stderr)
		Expect(stdout).To(MatchRegexp(`linux/amd64\s+hello_1\.2\.0_linux_x86_64\.tar\.gz\s`))
	})

	DescribeTable("sends GITHUB_TOKEN, else GH_TOKEN, to the API host only",
		func(githubToken, ghToken, want string) {
			GinkgoT().Setenv("GITHUB_TOKEN", githubToken)
			GinkgoT().Setenv("GH_TOKEN", ghToken)
			api, fake, rootPath := startFake(importRelease())

			_, stderr, code := runRoot("pkg", "import", "github:acme/hello@v1.2.0", importOut(),
				"--api-url", api, "--trusted-root", rootPath)

			Expect(code).To(BeZero(), stderr)
			reqs := fake.Requests()
			Expect(reqs).NotTo(BeEmpty())
			for _, r := range reqs {
				if !strings.HasPrefix(r.Path, "/repos/") {
					Expect(r.Authorization).To(BeEmpty(), "asset and bundle downloads are unauthenticated: %s", r.Path)
					continue
				}
				if want == "" {
					Expect(r.Authorization).To(BeEmpty(), r.Path)
					continue
				}
				Expect(r.Authorization).To(ContainSubstring(want), r.Path)
				if ghToken != "" && ghToken != want {
					Expect(r.Authorization).NotTo(ContainSubstring(ghToken), r.Path)
				}
			}
		},
		// The two values share no substring, so "contains one" can never pass
		// because of the other.
		Entry("GITHUB_TOKEN wins over GH_TOKEN", "alpha-token", "bravo-token", "alpha-token"),
		Entry("GH_TOKEN when GITHUB_TOKEN is unset", "", "bravo-token", "bravo-token"),
		Entry("surrounding whitespace is trimmed", " alpha-token\n", "", "alpha-token"),
		Entry("no token, no Authorization header", "", "", ""),
	)

	It("sends a token over plain http to LOCALHOST, as the client allows", func() {
		GinkgoT().Setenv("GITHUB_TOKEN", "alpha-token")
		api, fake, rootPath := startFake(importRelease())
		u, err := url.Parse(api)
		Expect(err).NotTo(HaveOccurred())

		_, stderr, code := runRoot("pkg", "import", "github:acme/hello@v1.2.0", importOut(),
			"--api-url", "http://LOCALHOST:"+u.Port(), "--trusted-root", rootPath)

		Expect(code).To(BeZero(), stderr)
		Expect(fake.Requests()).To(ContainElement(HaveField("Authorization", "Bearer alpha-token")))
	})

	It("refuses to send a token over plain http to a non-loopback host", func() {
		GinkgoT().Setenv("GITHUB_TOKEN", "tok-secret")
		_, _, rootPath := startFake(importRelease())

		stdout, stderr, code := runRoot("pkg", "import", "github:acme/hello", importOut(),
			"--api-url", "http://github.example.invalid", "--trusted-root", rootPath)

		Expect(code).NotTo(BeZero())
		Expect(stderr).To(ContainSubstring("refusing to send GITHUB_TOKEN/GH_TOKEN over plain http"))
		Expect(stdout + stderr).NotTo(ContainSubstring("tok-secret"))
	})

	It("needs exactly a release and an output directory", func() {
		_, stderr, code := runRoot("pkg", "import", "github:acme/hello")
		Expect(code).NotTo(BeZero())
		Expect(stderr).To(ContainSubstring("(got 1 argument)"))
	})

	DescribeTable("refuses bad input before any request",
		func(args []string, want string) {
			_, fake, rootPath := startFake(importRelease())
			full := append([]string{"pkg", "import"}, args...)
			if !strings.Contains(strings.Join(args, " "), "--trusted-root") {
				full = append(full, "--trusted-root", rootPath)
			}

			stdout, stderr, code := runRoot(full...)

			Expect(code).NotTo(BeZero())
			Expect(stderr).To(ContainSubstring(want))
			Expect(stdout+stderr).NotTo(ContainSubstring("hunter2"), "a URL password must never be echoed")
			Expect(fake.Requests()).To(BeEmpty())
		},
		Entry("no github: prefix", []string{"acme/hello", "out"}, "must start with github:"),
		Entry("another forge", []string{"gitlab:acme/hello", "out"}, "must start with github:"),
		Entry("no repository", []string{"github:acme", "out"}, "OWNER/REPO"),
		Entry("empty owner", []string{"github:/hello", "out"}, "OWNER/REPO"),
		Entry("empty repository", []string{"github:acme/", "out"}, "OWNER/REPO"),
		Entry("extra path segment", []string{"github:acme/hello/x", "out"}, "OWNER/REPO"),
		Entry("owner starting with a hyphen", []string{"github:-acme/hello", "out"}, "OWNER/REPO"),
		Entry("dot-dot repository", []string{"github:acme/..", "out"}, "OWNER/REPO"),
		Entry("empty tag", []string{"github:acme/hello@", "out"}, "invalid release tag"),
		Entry("tag with a space", []string{"github:acme/hello@v1 2", "out"}, "invalid release tag"),
		Entry("tag with ..", []string{"github:acme/hello@v1..2", "out"}, "invalid release tag"),
		Entry("tag with a colon", []string{"github:acme/hello@v1:2", "out"}, "invalid release tag"),
		Entry("tag with a control character", []string{"github:acme/hello@v1\x07", "out"}, "invalid release tag"),
		Entry("invalid --name", []string{"github:acme/hello", "out", "--name", "Hello World"}, "--name"),
		Entry("--bin with a slash", []string{"github:acme/hello", "out", "--bin", "../x"}, "--bin"),
		Entry("empty --bin", []string{"github:acme/hello", "out", "--bin", ""}, "--bin"),
		Entry("--bin with a dot", []string{"github:acme/hello", "out", "--bin", "rg.exe"}, `--bin "rg.exe" is not a command name`),
		Entry("--bin twice", []string{"github:acme/hello", "out", "--bin", "rg", "--bin", "rg"}, `--bin "rg" is given twice`),
		Entry("--platform without =", []string{"github:acme/hello", "out", "--platform", "linux/amd64"}, "OS/ARCH=GLOB"),
		Entry("--platform with an empty glob", []string{"github:acme/hello", "out", "--platform", "linux/amd64="}, "OS/ARCH=GLOB"),
		Entry("--platform with a dash", []string{"github:acme/hello", "out", "--platform", "linux-amd64=x"}, "--platform"),
		Entry("--platform not a Go port", []string{"github:acme/hello", "out", "--platform", "plan9/zzz=x"}, "--platform"),
		Entry("--platform with a variant", []string{"github:acme/hello", "out", "--platform", "linux/arm/v7=x"}, "--platform"),
		Entry("--platform with a bad glob", []string{"github:acme/hello", "out", "--platform", "linux/amd64=["}, "not a valid glob"),
		Entry("--platform twice", []string{"github:acme/hello", "out", "--platform", "linux/amd64=a", "--platform", "linux/amd64=b"}, "more than once"),
		Entry("--api-url not http(s)", []string{"github:acme/hello", "out", "--api-url", "ftp://api.example"}, "--api-url"),
		Entry("--api-url without a scheme", []string{"github:acme/hello", "out", "--api-url", "api.github.com"}, "--api-url"),
		Entry("--api-url with a query", []string{"github:acme/hello", "out", "--api-url", "https://api.example?x=1"}, "--api-url"),
		Entry("--api-url with credentials", []string{"github:acme/hello", "out", "--api-url", "https://me:hunter2@api.example"}, "--api-url"),
		Entry("--trusted-root missing", []string{"github:acme/hello", "out", "--trusted-root", "/nonexistent/root.json"}, "cannot read --trusted-root"),
	)

	It("explains a --bin the path action cannot expose", func() {
		_, stderr, code := runRoot("pkg", "import", "github:acme/hello", importOut(), "--bin", "bin/rg")

		Expect(code).NotTo(BeZero())
		Expect(lineWith(stderr, "hint:")).To(ContainSubstring("letters, digits"))
	})

	It("refuses a --trusted-root that is not a sigstore trusted root, before any request", func() {
		_, fake, _ := startFake(importRelease())
		bad := filepath.Join(GinkgoT().TempDir(), "root.json")
		Expect(os.WriteFile(bad, []byte(`{"mediaType":"nope"}`), 0o600)).To(Succeed())

		_, stderr, code := runRoot("pkg", "import", "github:acme/hello", importOut(), "--trusted-root", bad)

		Expect(code).NotTo(BeZero())
		Expect(stderr).To(ContainSubstring("is not a sigstore trusted_root.json"))
		Expect(fake.Requests()).To(BeEmpty())
	})

	It("refuses an oversized --trusted-root without parsing it", func() {
		big := filepath.Join(GinkgoT().TempDir(), "root.json")
		Expect(os.WriteFile(big, make([]byte, maxTrustedRootBytes+1), 0o600)).To(Succeed())

		_, stderr, code := runRoot("pkg", "import", "github:acme/hello", importOut(), "--trusted-root", big)

		Expect(code).NotTo(BeZero())
		Expect(stderr).To(ContainSubstring("is larger than"))
	})
})

var _ = Describe("pkg import result rendering", func() {
	// noted is an import whose platform skipped a non-provenance attestation
	// and whose release held an asset with a hostile name.
	noted := func() *importer.Result {
		return &importer.Result{
			Name: "hello", Version: "1.2.0", TrustedRootPath: "/out/sigstore-trusted-root.json",
			Platforms: []importer.PlatformResult{{
				Platform: "linux/amd64", Asset: "hello_linux_amd64.tar.gz", Integrity: "github-digest",
				Dir: "/out/hello/1.2.0/linux-amd64", Attestations: 1,
				Notes: []string{`skipped an attestation with predicate type "https://example.test/release/v0.2"; only SLSA provenance is carried`},
			}},
			Skipped: []ghrelease.Skip{{Name: "evil\x1b[2J.zip", Reason: "no platform\nin name"}},
		}
	}
	render := func(format Format) string {
		cmd := &cobra.Command{}
		var out bytes.Buffer
		cmd.SetOut(&out)
		emitImportResult(cmd, format, "github:acme/hello@v1.2.0", noted())
		return out.String()
	}

	It("prints a platform's notes as note: lines, apart from warnings", func() {
		out := render(FormatText)
		Expect(out).To(ContainSubstring(`note: linux/amd64: skipped an attestation with predicate type "https://example.test/release/v0.2"`))
		Expect(out).NotTo(ContainSubstring("warning:"))
	})

	It("carries the notes as an additive notes array in JSON", func() {
		var env struct {
			Data struct {
				Platforms []struct {
					Warnings []string `json:"warnings"`
					Notes    []string `json:"notes"`
				} `json:"platforms"`
			} `json:"data"`
		}
		Expect(json.Unmarshal([]byte(render(FormatJSON)), &env)).To(Succeed())
		Expect(env.Data.Platforms).To(HaveLen(1))
		Expect(env.Data.Platforms[0].Notes).To(ConsistOf(ContainSubstring("only SLSA provenance is carried")))
		Expect(env.Data.Platforms[0].Warnings).To(BeEmpty())
	})

	It("never emits null notes or warnings", func() {
		res := noted()
		res.Platforms[0].Notes = nil
		cmd := &cobra.Command{}
		var out bytes.Buffer
		cmd.SetOut(&out)
		emitImportResult(cmd, FormatJSON, "github:acme/hello", res)
		Expect(out.String()).To(ContainSubstring(`"notes":[]`))
		Expect(out.String()).To(ContainSubstring(`"warnings":[]`))
	})

	It("quotes skipped asset names and reasons, which the release author controls", func() {
		out := render(FormatText)
		Expect(out).NotTo(ContainSubstring("\x1b"))
		Expect(out).To(ContainSubstring(`"evil\x1b[2J.zip": "no platform\nin name"`))
	})
})

var _ = Describe("pkg import errors", func() {
	BeforeEach(func() {
		sandboxUserEnv(GinkgoTB())
		GinkgoT().Setenv("GITHUB_TOKEN", "")
		GinkgoT().Setenv("GH_TOKEN", "")
	})

	It("tells an anonymous caller to set GITHUB_TOKEN when rate-limited", func() {
		rel := importRelease()
		rel.RateLimited = true
		api, _, rootPath := startFake(rel)

		_, stderr, code := runRoot("pkg", "import", "github:acme/hello", importOut(),
			"--api-url", api, "--trusted-root", rootPath)

		Expect(code).NotTo(BeZero())
		Expect(stderr).To(ContainSubstring("API rate limit exceeded"))
		Expect(lineWith(stderr, "hint:")).To(ContainSubstring("set GITHUB_TOKEN"))
	})

	It("carries the rate-limit hint in the JSON error envelope", func() {
		rel := importRelease()
		rel.RateLimited = true
		api, _, rootPath := startFake(rel)

		stdout, _, code := runRoot("--format", "json", "pkg", "import", "github:acme/hello", importOut(),
			"--api-url", api, "--trusted-root", rootPath)

		Expect(code).NotTo(BeZero())
		var env importEnvelope
		Expect(json.Unmarshal([]byte(stdout), &env)).To(Succeed())
		Expect(env.Command).To(Equal("pkg import"))
		Expect(env.Status).To(Equal("error"))
		Expect(env.Error).To(ContainSubstring("API rate limit exceeded"))
		Expect(env.Hint).To(ContainSubstring("GITHUB_TOKEN"))
	})

	It("tells a token holder to wait, and never prints the token", func() {
		GinkgoT().Setenv("GITHUB_TOKEN", "tok-s3cr3t")
		rel := importRelease()
		rel.RateLimited = true
		api, _, rootPath := startFake(rel)

		stdout, stderr, code := runRoot("pkg", "import", "github:acme/hello", importOut(),
			"--api-url", api, "--trusted-root", rootPath)

		Expect(code).NotTo(BeZero())
		Expect(lineWith(stderr, "hint:")).To(ContainSubstring("wait for it to reset"))
		Expect(stdout + stderr).NotTo(ContainSubstring("tok-s3cr3t"))
	})

	It("names the missing release", func() {
		api, _, rootPath := startFake(importRelease())

		_, stderr, code := runRoot("pkg", "import", "github:acme/hello@v9.9.9", importOut(),
			"--api-url", api, "--trusted-root", rootPath)

		Expect(code).NotTo(BeZero())
		Expect(stderr).To(ContainSubstring("GitHub has no release for github:acme/hello@v9.9.9"))
		Expect(lineWith(stderr, "hint:")).To(ContainSubstring("@TAG"))
	})

	It("does not report a 404 on an asset download as a missing release", func() {
		dl := fmt.Errorf("download hello.tar.gz (listed as 3 bytes): %w",
			&ghrelease.NotFoundError{URL: "https://github.com/acme/hello/releases/download/v1.2.0/hello.tar.gz"})
		Expect(importError(dl, "github:acme/hello@v1.2.0", false, defaultGitHubAPIURL)).To(BeIdenticalTo(dl))
	})

	It("does not report a 404 on a later attestations page as a missing release", func() {
		page2 := fmt.Errorf("fetch attestations for asset hello.tar.gz: %w", &ghrelease.NotFoundError{
			URL: "https://api.github.com/repos/acme/hello/attestations/sha256:" + strings.Repeat("a", 64) + "?page=2"})
		Expect(importError(page2, "github:acme/hello@v1.2.0", false, defaultGitHubAPIURL)).To(BeIdenticalTo(page2))
	})

	It("does not report a release lookup's 404 from another origin as a missing release", func() {
		moved := &importer.LookupError{Lookup: "release", Err: &ghrelease.NotFoundError{
			URL: "https://elsewhere.example/repos/acme/hello/releases/latest"}}
		Expect(importError(moved, "github:acme/hello", false, defaultGitHubAPIURL)).To(BeIdenticalTo(moved))
	})

	It("names a missing repository from the repository lookup", func() {
		gone := &importer.LookupError{Lookup: "repository", Err: &ghrelease.NotFoundError{
			URL: "https://api.github.com/repos/acme/hello"}}
		var ce *CLIError
		Expect(errors.As(importError(gone, "github:acme/hello", false, defaultGitHubAPIURL), &ce)).To(BeTrue())
		Expect(ce.Msg).To(Equal("GitHub has no repository for github:acme/hello"))
	})

	It("suggests --insecure-skip-digest when no platform has an integrity source", func() {
		api, _, rootPath := startFake(singleAsset(ghreleasetest.Asset{
			Name: "hello_1.2.0_linux_amd64.tar.gz", Data: helloArchive("hello_1.2.0_linux_amd64"), OmitDigest: true,
		}))

		_, stderr, code := runRoot("pkg", "import", "github:acme/hello@v1.2.0", importOut(),
			"--api-url", api, "--trusted-root", rootPath)

		Expect(code).NotTo(BeZero())
		Expect(stderr).To(ContainSubstring("neither a GitHub digest nor a checksums file"))
		Expect(lineWith(stderr, "hint:")).To(ContainSubstring("--insecure-skip-digest"))
		Expect(lineWith(stderr, "hint:")).To(ContainSubstring("UNVERIFIED"))
	})

	It("explains a provenance attestation that does not verify", func() {
		api, _, _ := startFake(importRelease())
		_, _, otherRoot := startFake(importRelease())

		_, stderr, code := runRoot("pkg", "import", "github:acme/hello@v1.2.0", importOut(),
			"--api-url", api, "--trusted-root", otherRoot)

		Expect(code).NotTo(BeZero())
		Expect(lineWith(stderr, "error:")).To(MatchRegexp(`import refused: provenance attestation [12] of 2 for hello_1\.2\.0_linux_\w+\.tar\.gz does not verify against the Sigstore trusted root$`))
		hint := lineWith(stderr, "hint:")
		Expect(hint).To(ContainSubstring("re-run"))
		Expect(hint).To(ContainSubstring("report"))
		Expect(hint).To(ContainSubstring("GitHub Enterprise Server"))
	})

	It("tells how to get past an existing target directory", func() {
		api, _, rootPath := startFake(importRelease())
		out := importOut()
		_, stderr, code := runRoot("pkg", "import", "github:acme/hello@v1.2.0", out, "--api-url", api, "--trusted-root", rootPath)
		Expect(code).To(BeZero(), stderr)

		_, stderr, code = runRoot("pkg", "import", "github:acme/hello@v1.2.0", out, "--api-url", api, "--trusted-root", rootPath)

		Expect(code).NotTo(BeZero())
		Expect(lineWith(stderr, "error:")).To(ContainSubstring(filepath.Join(out, "hello", "1.2.0", "linux-amd64") + " already exists"))
		hint := lineWith(stderr, "hint:")
		Expect(hint).To(ContainSubstring("another"))
		Expect(hint).To(ContainSubstring("remove or rename"))
	})

	It("suggests --name when the repository name is not a package name, before any request", func() {
		_, fake, rootPath := startFake(importRelease())

		_, stderr, code := runRoot("pkg", "import", "github:acme/tool.js", importOut(), "--trusted-root", rootPath)

		Expect(code).NotTo(BeZero())
		Expect(lineWith(stderr, "error:")).To(ContainSubstring(`lower-cased as "tool.js", is not a valid package name`))
		Expect(lineWith(stderr, "hint:")).To(ContainSubstring("--name"))
		Expect(fake.Requests()).To(BeEmpty())
	})

	It("refuses a --version that is not a semantic version, before any request", func() {
		_, fake, rootPath := startFake(importRelease())

		_, stderr, code := runRoot("pkg", "import", "github:acme/hello", importOut(), "--trusted-root", rootPath, "--version", "latest")

		Expect(code).NotTo(BeZero())
		Expect(lineWith(stderr, "error:")).To(ContainSubstring(`version "latest" is not a semantic version`))
		Expect(lineWith(stderr, "hint:")).To(ContainSubstring("1.2.0"))
		Expect(fake.Requests()).To(BeEmpty())
	})

	It("suggests --version when the release tag is not a semantic version", func() {
		api, _, rootPath := startFake(ghreleasetest.Release{Owner: "acme", Repo: "hello", Tag: "nightly", Assets: []ghreleasetest.Asset{
			{Name: "hello_linux_amd64.tar.gz", Data: helloArchive("hello")},
		}})

		_, stderr, code := runRoot("pkg", "import", "github:acme/hello@nightly", importOut(), "--api-url", api, "--trusted-root", rootPath)

		Expect(code).NotTo(BeZero())
		Expect(lineWith(stderr, "error:")).To(ContainSubstring(`release tag "nightly" is not a semantic version`))
		Expect(lineWith(stderr, "hint:")).To(ContainSubstring("--version"))
	})

	It("lists every dropped platform and how to choose another asset when none remains", func() {
		api, _, rootPath := startFake(singleAsset(ghreleasetest.Asset{Name: "hello_1.2.0_linux_amd64.tar.gz", Data: []byte("not an archive")}))

		_, stderr, code := runRoot("pkg", "import", "github:acme/hello@v1.2.0", importOut(), "--api-url", api, "--trusted-root", rootPath)

		Expect(code).NotTo(BeZero())
		Expect(lineWith(stderr, "error:")).To(ContainSubstring("no platform of acme/hello 1.2.0 could be imported: linux/amd64:"))
		Expect(lineWith(stderr, "hint:")).To(ContainSubstring("--platform OS/ARCH=GLOB"))
	})

	It("maps an invalid owner or repository name to a message and hint", func() {
		bad := fmt.Errorf("wrapped: %w", &ghrelease.RepositoryNameError{Owner: "-acme", Repo: "hello"})
		var ce *CLIError
		Expect(errors.As(importError(bad, "github:-acme/hello", false, defaultGitHubAPIURL), &ce)).To(BeTrue())
		Expect(ce.Msg).To(ContainSubstring(`GitHub owner "-acme" is not a valid account name`))
		Expect(ce.Hint).To(ContainSubstring("not starting with '-'"))
		Expect(ce.Err).To(BeIdenticalTo(bad))
	})

	It("explains an invalid owner name from the release reference, before any request", func() {
		_, fake, rootPath := startFake(importRelease())

		_, stderr, code := runRoot("pkg", "import", "github:acme.corp/hello", importOut(), "--trusted-root", rootPath)

		Expect(code).NotTo(BeZero())
		Expect(lineWith(stderr, "error:")).To(ContainSubstring(`GitHub owner "acme.corp" is not a valid account name`))
		Expect(lineWith(stderr, "hint:")).To(ContainSubstring("letters, digits, '-' and '_'"))
		Expect(fake.Requests()).To(BeEmpty())
	})

	It("points at --trusted-root when the Sigstore root cannot be fetched", func() {
		fetch := fmt.Errorf("%w: %w", importer.ErrFetchTrustedRoot, errors.New("sigstore TUF: x509: certificate signed by unknown authority"))
		var ce *CLIError
		Expect(errors.As(importError(fetch, "github:acme/hello", false, defaultGitHubAPIURL), &ce)).To(BeTrue())
		Expect(ce.Msg).NotTo(ContainSubstring("x509"))
		Expect(ce.Hint).To(ContainSubstring("--trusted-root FILE"))
		Expect(ce.Err).To(MatchError(ContainSubstring("x509")))
	})

	It("explains that latest skips prereleases", func() {
		rel := importRelease()
		rel.Prerelease = true
		api, _, rootPath := startFake(rel)

		_, stderr, code := runRoot("pkg", "import", "github:acme/hello", importOut(),
			"--api-url", api, "--trusted-root", rootPath)

		Expect(code).NotTo(BeZero())
		Expect(stderr).To(ContainSubstring("GitHub has no release for github:acme/hello"))
		Expect(lineWith(stderr, "hint:")).To(ContainSubstring("prerelease"))
	})

	It("lists ambiguous candidates and the --platform syntax", func() {
		api, _, rootPath := startFake(ghreleasetest.Release{Owner: "acme", Repo: "hello", Tag: "v1.2.0", Assets: []ghreleasetest.Asset{
			{Name: "hello_1.2.0_linux_amd64.tar.gz", Data: helloArchive("a")},
			{Name: "hello_1.2.0_linux_x86_64.tar.gz", Data: helloArchive("b")},
		}})
		out := importOut()

		_, stderr, code := runRoot("pkg", "import", "github:acme/hello@v1.2.0", out,
			"--api-url", api, "--trusted-root", rootPath)

		Expect(code).NotTo(BeZero())
		Expect(stderr).To(ContainSubstring("more than one release asset matches linux/amd64"))
		Expect(stderr).To(ContainSubstring("hello_1.2.0_linux_amd64.tar.gz"))
		Expect(stderr).To(ContainSubstring("hello_1.2.0_linux_x86_64.tar.gz"))
		Expect(lineWith(stderr, "hint:")).To(ContainSubstring("--platform linux/amd64=GLOB"))
		Expect(filepath.Join(out, "hello")).NotTo(BeAnExistingFile())
	})

	It("refuses an asset whose bytes do not match GitHub's digest, writing nothing", func() {
		api, _, rootPath := startFake(singleAsset(ghreleasetest.Asset{
			Name: "hello_1.2.0_linux_amd64.tar.gz", Data: helloArchive("hello_1.2.0_linux_amd64"),
			Digest: "sha256:" + strings.Repeat("0", 64),
		}))
		out := importOut()

		_, stderr, code := runRoot("pkg", "import", "github:acme/hello@v1.2.0", out,
			"--api-url", api, "--trusted-root", rootPath, "--insecure-skip-digest")

		Expect(code).NotTo(BeZero(), "--insecure-skip-digest must never waive a digest that is present and wrong")
		Expect(stderr).To(ContainSubstring("import refused"))
		Expect(stderr).To(ContainSubstring("nothing was written"))
		Expect(lineWith(stderr, "hint:")).To(ContainSubstring("tampering"))
		Expect(filepath.Join(out, "hello")).NotTo(BeAnExistingFile())
	})
})

package cli

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/platform"
	"github.com/trevor-vaughan/polypkg/internal/repo"
	"github.com/trevor-vaughan/polypkg/internal/resolver"
)

// platformPkg is one artifact published into a platform-repo fixture. Several
// may share a name and version with different platforms; Platform "" publishes
// a platform-agnostic artifact.
type platformPkg struct {
	Name, Version, Platform string
}

// otherPlatform returns a producer-valid platform that is not this host's, so
// a fixture can publish an artifact this host must never select.
func otherPlatform() string {
	if platform.Host() == "linux/amd64" {
		return "darwin/arm64"
	}
	return "linux/amd64"
}

// sandboxPlatformEnv points HOME and every XDG directory at a fresh temp dir
// and returns it.
func sandboxPlatformEnv() string {
	env := GinkgoT().TempDir()
	GinkgoT().Setenv("HOME", env)
	for _, v := range []string{"XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_BIN_HOME", "XDG_DATA_DIRS"} {
		GinkgoT().Setenv(v, filepath.Join(env, strings.ToLower(v)))
	}
	return env
}

// publishPlatformRepo builds a signed repo publishing pkgs, sandboxes the
// environment, and points POLYPKG_PROFILE at a profile that requests
// profilePkg from it (FetchCatalog builds no catalog for an empty profile).
func publishPlatformRepo(profilePkg string, pkgs []platformPkg) {
	root := GinkgoT().TempDir()
	keyDir := GinkgoT().TempDir() // outside the output dir

	sources := map[string][]string{}
	for _, p := range pkgs {
		dirName := p.Name + "-" + p.Version + "-" + strings.ReplaceAll(cmp.Or(p.Platform, platform.Any), "/", "-")
		dir := filepath.Join(root, "pkgs", dirName)
		Expect(os.MkdirAll(filepath.Join(dir, "content", "bin"), 0o755)).To(Succeed())
		recipe := "schema: polypkg.package/v1\nname: " + p.Name + "\nversion: " + p.Version + "\n"
		if p.Platform != "" {
			recipe += "platform: " + p.Platform + "\n"
		}
		recipe += "actions: []\n"
		Expect(os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte(recipe), 0o644)).To(Succeed())
		// Distinct bytes per artifact so no two entries share a content hash.
		Expect(os.WriteFile(filepath.Join(dir, "content", "bin", p.Name),
			[]byte("#!/bin/sh\necho "+dirName+"\n"), 0o755)).To(Succeed())
		sources[p.Name] = append(sources[p.Name], "./pkgs/"+dirName)
	}
	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)

	kp, err := repo.GenerateKeypair()
	Expect(err).NotTo(HaveOccurred())
	keyPath := filepath.Join(keyDir, "repo.key")
	Expect(repo.SaveKey(keyPath, kp, "pw", repo.KDFScrypt)).To(Succeed())

	manifest := "schema: polypkg.repo/v1\nsource: repo\noutput: ./public\n" +
		"key:\n  path: " + keyPath + "\n  kdf: scrypt\npackages:\n"
	for _, name := range names {
		manifest += "  " + name + ":\n"
		for _, src := range sources[name] {
			manifest += "    - source: " + src + "\n"
		}
	}
	mPath := filepath.Join(root, "polypkg-repo.yaml")
	Expect(os.WriteFile(mPath, []byte(manifest), 0o644)).To(Succeed())
	b, err := repo.NewBuilder(mPath, keyDir, "pw")
	Expect(err).NotTo(HaveOccurred())
	_, err = b.Build(repo.BuildOptions{SkipAttestations: true})
	Expect(err).NotTo(HaveOccurred())
	publicDir := filepath.Join(root, "public")

	env := sandboxPlatformEnv()
	profilePath := filepath.Join(env, "profile.yaml")
	Expect(os.WriteFile(profilePath, []byte(
		"schema: polypkg.spec/v1\nname: platform-fixture\n"+
			"scopes:\n  user:\n    substrate: store\n"+
			"sources:\n  order: [repo]\n  repo:\n    type: polypkg-native\n"+
			"    url: file://"+publicDir+"\n"+
			"    trust_root: "+filepath.Join(publicDir, "trust_root.pub")+"\n"+
			"packages:\n  user:\n    "+profilePkg+":\n      version: \">=1.0.0\"\n"), 0o644)).To(Succeed())
	GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)
}

// publishStandardPlatformRepo publishes hello 1.0.0 for this host and another
// platform, hello 2.0.0 for the other platform only, an agnostic greet, and an
// rg with no artifact for this host.
func publishStandardPlatformRepo() {
	publishPlatformRepo("greet", []platformPkg{
		{Name: "hello", Version: "1.0.0", Platform: platform.Host()},
		{Name: "hello", Version: "1.0.0", Platform: otherPlatform()},
		{Name: "hello", Version: "2.0.0", Platform: otherPlatform()},
		{Name: "greet", Version: "1.0.0"},
		{Name: "rg", Version: "14.1.1", Platform: otherPlatform()},
	})
}

var _ = Describe("search on a multi-platform repository", func() {
	It("lists each version once and separates versions published only for other platforms", func() {
		publishStandardPlatformRepo()
		cmd := newSearchCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		scope, _, stateHome, err := resolveListScope(cmd, bestEffortProfile(cmd))
		Expect(err).NotTo(HaveOccurred())

		rows, err := searchRows(cmd, "", scope, stateHome, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(rows).To(Equal([]searchMatch{
			{Name: "greet", Versions: []string{"1.0.0"}, Unavailable: []string{}},
			{Name: "hello", Versions: []string{"1.0.0"}, Unavailable: []string{"2.0.0"}},
			{Name: "rg", Versions: []string{}, Unavailable: []string{"14.1.1"}},
		}))
	})

	It("reports unavailable_versions additively under --format json", func() {
		publishStandardPlatformRepo()
		root := NewRootCmd()
		var out, errOut bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&errOut)
		root.SetArgs([]string{"search", "--format", "json", "hello"})
		Expect(root.Execute()).To(Succeed(), errOut.String())

		var result struct {
			Data struct {
				Matches []struct {
					Name                string   `json:"name"`
					Versions            []string `json:"versions"`
					UnavailableVersions []string `json:"unavailable_versions"`
				} `json:"matches"`
			} `json:"data"`
		}
		Expect(json.Unmarshal([]byte(strings.TrimSpace(out.String())), &result)).To(Succeed())
		Expect(result.Data.Matches).To(HaveLen(1))
		Expect(result.Data.Matches[0].Name).To(Equal("hello"))
		Expect(result.Data.Matches[0].Versions).To(Equal([]string{"1.0.0"}))
		Expect(result.Data.Matches[0].UnavailableVersions).To(Equal([]string{"2.0.0"}))
	})
})

var _ = Describe("info on a multi-platform repository", func() {
	type infoData struct {
		Available         []string `json:"available"`
		Platform          string   `json:"platform"`
		OtherPlatforms    []string `json:"other_platforms"`
		InstalledPlatform string   `json:"installed_platform"`
		Note              string   `json:"note"`
	}
	runInfoCmd := func(args ...string) (string, error) {
		root := NewRootCmd()
		var out, errOut bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&errOut)
		root.SetArgs(append([]string{"info"}, args...))
		err := root.Execute()
		return out.String(), err
	}
	infoJSON := func(name string) infoData {
		out, err := runInfoCmd("--format", "json", name)
		Expect(err).NotTo(HaveOccurred(), out)
		var result struct {
			Data infoData `json:"data"`
		}
		Expect(json.Unmarshal([]byte(strings.TrimSpace(out)), &result)).To(Succeed())
		return result.Data
	}

	It("shows the candidate's host platform and the other platforms published for that version", func() {
		publishStandardPlatformRepo()
		d := infoJSON("hello")
		Expect(d.Available).To(Equal([]string{"1.0.0"}))
		Expect(d.Platform).To(Equal(platform.Host()))
		Expect(d.OtherPlatforms).To(Equal([]string{otherPlatform()}))

		text, err := runInfoCmd("hello")
		Expect(err).NotTo(HaveOccurred())
		Expect(text).To(ContainSubstring("  platform:  " + platform.Host() + " (newest)\n"))
		Expect(text).To(ContainSubstring("  other platforms: " + otherPlatform() + "\n"))
	})

	It("reports any, and no other platforms, for a platform-agnostic package", func() {
		publishStandardPlatformRepo()
		d := infoJSON("greet")
		Expect(d.Platform).To(Equal(platform.Any))
		Expect(d.OtherPlatforms).To(BeNil())

		text, err := runInfoCmd("greet")
		Expect(err).NotTo(HaveOccurred())
		Expect(text).To(ContainSubstring("  platform:  any (newest)\n"))
		Expect(text).NotTo(ContainSubstring("other platforms:"))
	})

	It("says where a package is published when this host has no artifact for it", func() {
		publishStandardPlatformRepo()
		want := "rg 14.1.1 is published for " + otherPlatform() + "; this host is " + platform.Host()
		d := infoJSON("rg")
		Expect(d.Available).To(BeEmpty())
		Expect(d.Platform).To(BeEmpty())
		Expect(d.OtherPlatforms).To(Equal([]string{otherPlatform()}))
		Expect(d.Note).To(Equal(want))

		text, err := runInfoCmd("rg")
		Expect(err).NotTo(HaveOccurred())
		Expect(text).To(ContainSubstring("  note: " + want + "\n"))
		Expect(text).NotTo(ContainSubstring("  platform:  "))
	})

	It("gives the wrong-platform reason, not an unreachable source, for an installed package", func() {
		publishStandardPlatformRepo()
		storeRoot := filepath.Join(os.Getenv("XDG_DATA_HOME"), "polypkg")
		Expect(os.MkdirAll(filepath.Join(storeRoot, "generations", "1", "active"), 0o700)).To(Succeed())
		Expect(os.Symlink(filepath.Join("generations", "1", "active"), filepath.Join(storeRoot, "active"))).To(Succeed())
		Expect(os.WriteFile(filepath.Join(storeRoot, "generations", "1", "ownership.json"),
			[]byte(`{"schema":"polypkg.ownership/v1","scope":"user","entries":[]}`), 0o600)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(storeRoot, "generations", "1", "manifest.json"), []byte(`{
  "schema":"polypkg.manifest/v2","generation":1,"scope":"user",
  "produced_by":{"tool":"polypkg","version":"0.1.0","timestamp":"2026-01-01T00:00:00Z","host":"test"},
  "entries":[{"name":"rg","version":"14.0.0","content_hash":"blake3:aabbcc"}]}`), 0o600)).To(Succeed())

		d := infoJSON("rg")
		Expect(d.Note).To(Equal("rg 14.1.1 is published for " + otherPlatform() + "; this host is " + platform.Host()))
		Expect(d.InstalledPlatform).To(Equal(platform.Any))
	})

	It("still fails for a name published for no platform", func() {
		publishStandardPlatformRepo()
		_, err := runInfoCmd("nope")
		var re *resolver.ResolveError
		Expect(errors.As(err, &re)).To(BeTrue(), "want a resolver error, got %v", err)
		Expect(re.Kind).To(Equal(resolver.KindUnknownName))
	})

	It("reads the installed artifact's platform from the generation manifest", func() {
		env := sandboxPlatformEnv()
		storeRoot := filepath.Join(env, "xdg_data_home", "polypkg")
		Expect(os.MkdirAll(filepath.Join(storeRoot, "generations", "1", "active"), 0o700)).To(Succeed())
		Expect(os.Symlink(filepath.Join("generations", "1", "active"), filepath.Join(storeRoot, "active"))).To(Succeed())
		Expect(os.WriteFile(filepath.Join(storeRoot, "generations", "1", "ownership.json"),
			[]byte(`{"schema":"polypkg.ownership/v1","scope":"user","entries":[]}`), 0o600)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(storeRoot, "generations", "1", "manifest.json"), []byte(`{
  "schema":"polypkg.manifest/v2","generation":1,"scope":"user",
  "produced_by":{"tool":"polypkg","version":"0.1.0","timestamp":"2026-01-01T00:00:00Z","host":"test"},
  "entries":[
    {"name":"hello","version":"1.0.0","content_hash":"blake3:aabbcc","platform":"linux/amd64"},
    {"name":"greet","version":"2.0.0","content_hash":"blake3:ddeeff"}
  ]}`), 0o600)).To(Succeed())
		// An unreachable source sends info down its offline path: installed
		// information only, read from the manifest.
		profilePath := filepath.Join(env, "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte("schema: polypkg.spec/v1\nname: installed-platform\n"+
			"scopes:\n  user:\n    substrate: store\n"+
			"sources:\n  order: [native]\n  native:\n    type: polypkg-native\n"+
			"    url: http://127.0.0.1:1\n    trust_root: /dev/null\n"+
			"packages:\n  user:\n    hello: {version: \"\"}\n"), 0o644)).To(Succeed())
		GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)

		Expect(infoJSON("hello").InstalledPlatform).To(Equal("linux/amd64"))
		Expect(infoJSON("greet").InstalledPlatform).To(Equal(platform.Any))

		text, err := runInfoCmd("hello")
		Expect(err).NotTo(HaveOccurred())
		Expect(text).To(ContainSubstring("  installed: 1.0.0 (generation 1, linux/amd64)\n"))
		text, err = runInfoCmd("greet")
		Expect(err).NotTo(HaveOccurred())
		Expect(text).To(ContainSubstring("  installed: 2.0.0 (generation 1)\n"),
			"an agnostic install keeps the existing installed line")
	})
})

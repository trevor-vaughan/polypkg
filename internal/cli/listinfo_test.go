package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/cobra"

	"github.com/trevor-vaughan/polypkg/internal/paths"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// makeListGen1State creates generation-1 substrate state with a manifest
// containing two packages: hello 1.0.0 and world 2.0.0.
func makeListGen1State(storeRoot string) {
	gen1Dir := filepath.Join(storeRoot, "generations", "1", "active")
	Expect(os.MkdirAll(gen1Dir, 0o700)).To(Succeed())
	activeLink := filepath.Join(storeRoot, "active")
	Expect(os.Symlink(filepath.Join("generations", "1", "active"), activeLink)).To(Succeed())
	own := filepath.Join(storeRoot, "generations", "1", "ownership.json")
	Expect(os.WriteFile(own,
		[]byte(`{"schema":"polypkg.ownership/v1","scope":"user","entries":[]}`),
		0o600)).To(Succeed())
	manifest := filepath.Join(storeRoot, "generations", "1", "manifest.json")
	Expect(os.WriteFile(manifest, []byte(`{
  "schema": "polypkg.manifest/v2",
  "generation": 1,
  "scope": "user",
  "produced_by": {"tool":"polypkg","version":"0.1.0","timestamp":"2026-01-01T00:00:00Z","host":"test"},
  "entries": [
    {"name":"hello","version":"1.0.0","content_hash":"blake3:aabbcc","platform":"linux/amd64"},
    {"name":"world","version":"2.0.0","content_hash":"blake3:ddeeff"}
  ]
}`), 0o600)).To(Succeed())
}

var _ = Describe("list command", func() {
	setup := func() (dir, storeRoot string) {
		dir = GinkgoT().TempDir()
		GinkgoT().Setenv("HOME", dir)
		GinkgoT().Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
		GinkgoT().Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
		GinkgoT().Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
		GinkgoT().Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
		GinkgoT().Setenv("XDG_BIN_HOME", filepath.Join(dir, "bin"))
		GinkgoT().Setenv("POLYPKG_PROFILE", "")
		storeRoot = filepath.Join(dir, "data", "polypkg")
		return dir, storeRoot
	}

	It("prints a friendly message and exits 0 when no generation exists", func() {
		setup()
		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"list"})
		err := root.Execute()
		Expect(err).NotTo(HaveOccurred())
		Expect(out.String()).To(ContainSubstring("no packages installed"))
		Expect(out.String()).To(ContainSubstring("polypkg install <name>"))
	})

	It("lists packages sorted by name with NAME  VERSION columns", func() {
		_, storeRoot := setup()
		makeListGen1State(storeRoot)
		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"list"})
		err := root.Execute()
		Expect(err).NotTo(HaveOccurred())
		output := out.String()
		// hello must appear before world (sorted)
		helloIdx := strings.Index(output, "hello")
		worldIdx := strings.Index(output, "world")
		Expect(helloIdx).To(BeNumerically("<", worldIdx), "hello must sort before world")
		Expect(output).To(ContainSubstring("hello"))
		Expect(output).To(ContainSubstring("1.0.0"))
		Expect(output).To(ContainSubstring("world"))
		Expect(output).To(ContainSubstring("2.0.0"))
	})

	It("annotates pinned packages with the pin suffix", func() {
		_, storeRoot := setup()
		makeListGen1State(storeRoot)

		// Write a profile that pins hello exactly.
		profileDir := filepath.Join(GinkgoT().TempDir())
		profilePath := filepath.Join(profileDir, "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(`schema: polypkg.spec/v1
name: pin-test
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: polypkg-native
    url: http://unreachable.invalid
    trust_root: /dev/null
packages:
  user:
    hello: {version: "=1.0.0"}
    world: {version: ""}
`), 0o644)).To(Succeed())
		GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)

		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"list"})
		err := root.Execute()
		Expect(err).NotTo(HaveOccurred())
		output := out.String()
		Expect(output).To(ContainSubstring("pinned: =1.0.0"),
			"hello must carry the pinned annotation")
		// world has no pin constraint so it must not carry the annotation
		Expect(output).NotTo(MatchRegexp(`world\s+\S+.*pinned`))
	})

	It("emits JSON result with packages array when --format json", func() {
		_, storeRoot := setup()
		makeListGen1State(storeRoot)
		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"list", "--format", "json"})
		err := root.Execute()
		Expect(err).NotTo(HaveOccurred())
		var result struct {
			Status string `json:"status"`
			Data   struct {
				Packages []struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Scope   string `json:"scope"`
					Pinned  string `json:"pinned"`
				} `json:"packages"`
			} `json:"data"`
		}
		Expect(json.Unmarshal([]byte(strings.TrimSpace(out.String())), &result)).To(Succeed())
		Expect(result.Status).To(Equal("ok"))
		names := make([]string, 0, len(result.Data.Packages))
		for _, p := range result.Data.Packages {
			names = append(names, p.Name)
		}
		Expect(names).To(ContainElements("hello", "world"))
	})

	It("emits JSON empty-state result when --format json and no generation", func() {
		setup()
		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"list", "--format", "json"})
		err := root.Execute()
		Expect(err).NotTo(HaveOccurred())
		var result struct {
			Status string `json:"status"`
			Data   struct {
				Packages []any `json:"packages"`
			} `json:"data"`
		}
		Expect(json.Unmarshal([]byte(strings.TrimSpace(out.String())), &result)).To(Succeed())
		Expect(result.Status).To(Equal("ok"))
		Expect(result.Data.Packages).To(BeEmpty())
	})

	It("keeps the default text output byte-identical: no platform column", func() {
		_, storeRoot := setup()
		makeListGen1State(storeRoot)
		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"list"})
		Expect(root.Execute()).To(Succeed())
		Expect(out.String()).To(Equal("hello  1.0.0\nworld  2.0.0\n"))
	})

	It("adds a platform column under -v, showing any for an agnostic artifact", func() {
		_, storeRoot := setup()
		makeListGen1State(storeRoot)
		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"list", "-v"})
		Expect(root.Execute()).To(Succeed())
		Expect(out.String()).To(Equal("hello  1.0.0  linux/amd64\nworld  2.0.0  any\n"))
	})

	It("includes platform on every JSON package object", func() {
		_, storeRoot := setup()
		makeListGen1State(storeRoot)
		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"list", "--format", "json"})
		Expect(root.Execute()).To(Succeed())
		var result struct {
			Data struct {
				Packages []struct {
					Name     string `json:"name"`
					Platform string `json:"platform"`
				} `json:"packages"`
			} `json:"data"`
		}
		Expect(json.Unmarshal([]byte(strings.TrimSpace(out.String())), &result)).To(Succeed())
		got := map[string]string{}
		for _, p := range result.Data.Packages {
			got[p.Name] = p.Platform
		}
		Expect(got).To(Equal(map[string]string{"hello": "linux/amd64", "world": "any"}))
	})
})

var _ = Describe("info command argument validation", func() {
	setup := func() {
		dir := GinkgoT().TempDir()
		GinkgoT().Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
		GinkgoT().Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	}

	It("returns CLIError when no package name is supplied", func() {
		setup()
		root := NewRootCmd()
		root.SetArgs([]string{"info"})
		err := root.Execute()
		Expect(err).To(HaveOccurred())
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(cliErr.Msg).To(ContainSubstring("info"))
		Expect(cliErr.Msg).To(ContainSubstring("<package>"))
	})

	It("returns CLIError when more than one package name is supplied", func() {
		setup()
		root := NewRootCmd()
		root.SetArgs([]string{"info", "hello", "world"})
		err := root.Execute()
		Expect(err).To(HaveOccurred())
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
	})
})

var _ = Describe("info command fetch-error path", func() {
	setup := func() (dir, storeRoot string) {
		dir = GinkgoT().TempDir()
		GinkgoT().Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
		GinkgoT().Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
		storeRoot = filepath.Join(dir, "data", "polypkg")
		return dir, storeRoot
	}

	It("returns CLIError when package not installed and source unreachable", func() {
		setup()
		// Write a profile pointing at a localhost port we know is not listening.
		profileDir := GinkgoT().TempDir()
		profilePath := filepath.Join(profileDir, "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(`schema: polypkg.spec/v1
name: info-error-test
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: polypkg-native
    url: http://127.0.0.1:1
    trust_root: /dev/null
packages:
  user:
    hello: {version: ""}
`), 0o644)).To(Succeed())
		GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)

		root := NewRootCmd()
		var out, errOut bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&errOut)
		root.SetArgs([]string{"info", "hello"})
		err := root.Execute()
		Expect(err).To(HaveOccurred(),
			"info must fail when source is unreachable and package not installed")
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(),
			"expected *CLIError from fetch failure, got %T: %v", err, err)
	})

	It("shows installed info and offline note when installed but source unreachable", func() {
		_, storeRoot := setup()
		makeListGen1State(storeRoot)

		profileDir := GinkgoT().TempDir()
		profilePath := filepath.Join(profileDir, "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(`schema: polypkg.spec/v1
name: info-offline-test
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: polypkg-native
    url: http://127.0.0.1:1
    trust_root: /dev/null
packages:
  user:
    hello: {version: ""}
`), 0o644)).To(Succeed())
		GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)

		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"info", "hello"})
		err := root.Execute()
		Expect(err).NotTo(HaveOccurred(),
			"info must succeed when package is installed even if source unreachable")
		output := out.String()
		Expect(output).To(ContainSubstring("installed: 1.0.0"),
			"must show installed version")
		Expect(output).To(ContainSubstring("unreachable"),
			"must note that available versions are unknown due to offline source")
	})

	It("emits JSON result with note field when source unreachable and package installed", func() {
		_, storeRoot := setup()
		makeListGen1State(storeRoot)

		profileDir := GinkgoT().TempDir()
		profilePath := filepath.Join(profileDir, "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(`schema: polypkg.spec/v1
name: info-offline-json-test
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: polypkg-native
    url: http://127.0.0.1:1
    trust_root: /dev/null
packages:
  user:
    hello: {version: ""}
`), 0o644)).To(Succeed())
		GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)

		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"info", "--format", "json", "hello"})
		err := root.Execute()
		Expect(err).NotTo(HaveOccurred(),
			"info must succeed when package is installed even if source unreachable")
		var result struct {
			Status string `json:"status"`
			Data   struct {
				Installed string `json:"installed"`
				Note      string `json:"note"`
				Artifact  string `json:"artifact"`
			} `json:"data"`
		}
		Expect(json.Unmarshal([]byte(strings.TrimSpace(out.String())), &result)).To(Succeed())
		Expect(result.Status).To(Equal("ok"))
		Expect(result.Data.Installed).To(Equal("1.0.0"))
		Expect(result.Data.Note).NotTo(BeEmpty(), "must have non-empty note field")
	})
})

var _ = Describe("info command attestation rendering", func() {
	// makeInfoAttestState writes generation-1 substrate state whose manifest
	// spans every attestation-record case: hello verified, unatt unattested,
	// and legacy with no record (pre-v2 generation).
	makeInfoAttestState := func(storeRoot string) {
		gen1Dir := filepath.Join(storeRoot, "generations", "1", "active")
		Expect(os.MkdirAll(gen1Dir, 0o700)).To(Succeed())
		activeLink := filepath.Join(storeRoot, "active")
		Expect(os.Symlink(filepath.Join("generations", "1", "active"), activeLink)).To(Succeed())
		own := filepath.Join(storeRoot, "generations", "1", "ownership.json")
		Expect(os.WriteFile(own,
			[]byte(`{"schema":"polypkg.ownership/v1","scope":"user","entries":[]}`),
			0o600)).To(Succeed())
		manifest := filepath.Join(storeRoot, "generations", "1", "manifest.json")
		Expect(os.WriteFile(manifest, []byte(`{
  "schema": "polypkg.manifest/v2",
  "generation": 1,
  "scope": "user",
  "produced_by": {"tool":"polypkg","version":"0.1.0","timestamp":"2026-01-01T00:00:00Z","host":"test"},
  "entries": [
    {"name":"hello","version":"1.0.0","content_hash":"blake3:aabbcc",
     "attestation":{"status":"verified","predicate_types":["https://polypkg.dev/attestation/sarif/v1"],"attestation_hash":"blake3:445566","policy_at_install":"warn"}},
    {"name":"unatt","version":"2.0.0","content_hash":"blake3:ddeeff",
     "attestation":{"status":"unattested","policy_at_install":"warn"}},
    {"name":"legacy","version":"3.0.0","content_hash":"blake3:778899"}
  ]
}`), 0o600)).To(Succeed())
	}

	// setup isolates XDG state and points the profile at an unreachable source
	// so info takes the offline-tolerance path (installed info only) — the
	// attestation record comes from the installed manifest, not the catalog.
	setup := func() {
		dir := GinkgoT().TempDir()
		GinkgoT().Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
		GinkgoT().Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
		makeInfoAttestState(filepath.Join(dir, "data", "polypkg"))
		profilePath := filepath.Join(GinkgoT().TempDir(), "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(`schema: polypkg.spec/v1
name: info-attest-test
scopes:
  user:
    substrate: store
sources:
  order: [native]
  native:
    type: polypkg-native
    url: http://127.0.0.1:1
    trust_root: /dev/null
packages:
  user:
    hello: {version: ""}
`), 0o644)).To(Succeed())
		GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)
	}

	runInfoText := func(pkg string) string {
		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"info", pkg})
		Expect(root.Execute()).To(Succeed())
		return out.String()
	}

	It("renders the verified attestation line with predicate and policy", func() {
		setup()
		output := runInfoText("hello")
		Expect(output).To(ContainSubstring(
			"attestation: verified (https://polypkg.dev/attestation/sarif/v1) under policy warn"),
			"verified record must render predicate URIs and install-time policy")
	})

	It("renders the unattested attestation line with the install-time policy", func() {
		setup()
		output := runInfoText("unatt")
		Expect(output).To(ContainSubstring("attestation: unattested (policy warn at install)"),
			"unattested record must render its variant")
	})

	It("renders no attestation line when the record is absent", func() {
		setup()
		output := runInfoText("legacy")
		Expect(output).NotTo(ContainSubstring("attestation:"),
			"pre-v2 generations have no record and must render nothing")
	})

	It("includes the attestation object in JSON output", func() {
		setup()
		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"info", "--format", "json", "hello"})
		Expect(root.Execute()).To(Succeed())
		var result struct {
			Data struct {
				Attestation *schema.AttestationState `json:"attestation"`
			} `json:"data"`
		}
		Expect(json.Unmarshal([]byte(strings.TrimSpace(out.String())), &result)).To(Succeed())
		Expect(result.Data.Attestation).NotTo(BeNil())
		Expect(result.Data.Attestation.Status).To(Equal("verified"))
		Expect(result.Data.Attestation.PolicyAtInstall).To(Equal("warn"))
	})

	It("emits attestation as an explicit JSON null when the record is absent", func() {
		setup()
		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs([]string{"info", "--format", "json", "legacy"})
		Expect(root.Execute()).To(Succeed())
		var result struct {
			Data map[string]json.RawMessage `json:"data"`
		}
		Expect(json.Unmarshal([]byte(strings.TrimSpace(out.String())), &result)).To(Succeed())
		raw, ok := result.Data["attestation"]
		Expect(ok).To(BeTrue(), "the attestation key must be present even without a record")
		Expect(string(raw)).To(Equal("null"),
			"a pre-v2 entry with no record must yield the documented explicit null")
	})
})

var _ = Describe("resolveListScope system-prefix tiers", func() {
	// newListCmd builds a cobra command with scope flags attached, mirroring the
	// production setup so we can call resolveListScope directly.
	newCmd := func(flagArgs ...string) *cobra.Command {
		c := &cobra.Command{Use: "list", RunE: func(*cobra.Command, []string) error { return nil }}
		addScopeFlags(c)
		Expect(c.ParseFlags(append([]string{"--scope", "system"}, flagArgs...))).To(Succeed())
		return c
	}
	profile := func(systemPrefix string) *schema.Profile {
		return &schema.Profile{Scopes: map[string]schema.ScopeSpec{
			"system": {Substrate: "store", Prefix: systemPrefix},
		}}
	}

	It("honors POLYPKG_SYSTEM_PREFIX env for system scope (previously ignored)", func() {
		prefix := GinkgoT().TempDir()
		GinkgoT().Setenv("POLYPKG_SYSTEM_PREFIX", prefix)
		c := newCmd()
		scope, _, stateHome, err := resolveListScope(c, &schema.Profile{})
		Expect(err).NotTo(HaveOccurred())
		Expect(scope).To(Equal("system"))
		Expect(stateHome).To(Equal(filepath.Join(prefix, paths.SystemStateDir())))
	})

	It("honors profile.scopes.system.prefix when no flag or env is set", func() {
		prefix := GinkgoT().TempDir()
		GinkgoT().Setenv("POLYPKG_SYSTEM_PREFIX", "")
		c := newCmd()
		scope, _, stateHome, err := resolveListScope(c, profile(prefix))
		Expect(err).NotTo(HaveOccurred())
		Expect(scope).To(Equal("system"))
		Expect(stateHome).To(Equal(filepath.Join(prefix, paths.SystemStateDir())))
	})

	It("prefers env prefix over profile prefix", func() {
		envPrefix := GinkgoT().TempDir()
		profilePrefix := GinkgoT().TempDir()
		GinkgoT().Setenv("POLYPKG_SYSTEM_PREFIX", envPrefix)
		c := newCmd()
		_, _, stateHome, err := resolveListScope(c, profile(profilePrefix))
		Expect(err).NotTo(HaveOccurred())
		Expect(stateHome).To(Equal(filepath.Join(envPrefix, paths.SystemStateDir())))
	})

	It("prefers --prefix flag over env and profile prefix", func() {
		flagPrefix := GinkgoT().TempDir()
		GinkgoT().Setenv("POLYPKG_SYSTEM_PREFIX", GinkgoT().TempDir())
		c := newCmd("--prefix", flagPrefix)
		_, _, stateHome, err := resolveListScope(c, profile(GinkgoT().TempDir()))
		Expect(err).NotTo(HaveOccurred())
		Expect(stateHome).To(Equal(filepath.Join(flagPrefix, paths.SystemStateDir())))
	})

	It("user-scope behavior is unchanged: returns XDG state home", func() {
		dir := GinkgoT().TempDir()
		GinkgoT().Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
		GinkgoT().Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
		c := &cobra.Command{Use: "list", RunE: func(*cobra.Command, []string) error { return nil }}
		addScopeFlags(c)
		Expect(c.ParseFlags(nil)).To(Succeed())
		_, _, stateHome, err := resolveListScope(c, &schema.Profile{})
		Expect(err).NotTo(HaveOccurred())
		Expect(stateHome).To(Equal(filepath.Join(dir, "state", "polypkg")))
	})
})

var _ = Describe("info command recommends/suggests rendering", func() {
	setup := func() {
		dir := GinkgoT().TempDir()
		GinkgoT().Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
		GinkgoT().Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	}

	It("renders Recommends and Suggests in text output", func() {
		setup()
		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)

		recommends := []string{"extras"}
		suggests := []string{"docs"}
		err := emitInfoResult(root, FormatText, infoView{
			name: "hello", scope: "user",
			installed:  infoInstalled{version: "1.0.0", gen: 1},
			recommends: recommends, suggests: suggests,
		})
		Expect(err).NotTo(HaveOccurred())
		output := out.String()
		Expect(output).To(ContainSubstring("recommends:"),
			"must show recommends section")
		Expect(output).To(ContainSubstring("extras"),
			"must list the recommended package")
		Expect(output).To(ContainSubstring("suggests:"),
			"must show suggests section")
		Expect(output).To(ContainSubstring("docs"),
			"must list the suggested package")
	})

	It("omits Recommends and Suggests sections when both are empty", func() {
		setup()
		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)

		err := emitInfoResult(root, FormatText, infoView{
			name: "hello", scope: "user",
			installed: infoInstalled{version: "1.0.0", gen: 1},
		})
		Expect(err).NotTo(HaveOccurred())
		output := out.String()
		Expect(output).NotTo(ContainSubstring("recommends:"))
		Expect(output).NotTo(ContainSubstring("suggests:"))
	})

	It("includes recommends and suggests in JSON output", func() {
		setup()
		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)

		recommends := []string{"extras"}
		suggests := []string{"docs"}
		err := emitInfoResult(root, FormatJSON, infoView{
			name: "hello", scope: "user",
			installed:  infoInstalled{version: "1.0.0", gen: 1},
			recommends: recommends, suggests: suggests,
		})
		Expect(err).NotTo(HaveOccurred())
		var result struct {
			Status string `json:"status"`
			Data   struct {
				Recommends []string `json:"recommends"`
				Suggests   []string `json:"suggests"`
			} `json:"data"`
		}
		Expect(json.Unmarshal([]byte(strings.TrimSpace(out.String())), &result)).To(Succeed())
		Expect(result.Data.Recommends).To(ContainElement("extras"))
		Expect(result.Data.Suggests).To(ContainElement("docs"))
	})
})

var _ = Describe("profilePins", func() {
	It("returns exact-pin constraints for the given scope", func() {
		p := &schema.Profile{
			Packages: map[string]map[string]schema.PackageRef{
				"user": {
					"hello": {Version: "=1.0.0"},
					"world": {Version: ">=2.0.0"},
					"foo":   {Version: ""},
				},
			},
		}
		pins := profilePins(p, "user")
		Expect(pins).To(HaveKeyWithValue("hello", "=1.0.0"))
		Expect(pins).NotTo(HaveKey("world"))
		Expect(pins).NotTo(HaveKey("foo"))
	})

	It("returns an empty map when the scope has no packages", func() {
		pins := profilePins(&schema.Profile{}, "user")
		Expect(pins).To(BeEmpty())
	})
})

func TestAttestationLineGateOffAndBindings(t *testing.T) {
	off := &schema.AttestationState{Status: "unattested", PolicyAtInstall: "off", GateDisabled: true}
	if got := attestationLine(off); !strings.Contains(got, "gate disabled") {
		t.Errorf("gate-off info line must note the disabled gate, got %q", got)
	}
	verified := &schema.AttestationState{
		Status:          "verified",
		PolicyAtInstall: "warn",
		PredicateTypes:  []string{"native-sarif"},
		CarriedBindings: []schema.CarriedBinding{
			{PredicateType: "slsa", Tier: schema.CarriedTierVerifiedTransportOnly},
			{
				PredicateType:   "https://slsa.dev/provenance/v1",
				Tier:            schema.CarriedTierBuilderVerified,
				BuilderIdentity: "https://github.com/acme/builder",
			},
		},
	}
	got := attestationLine(verified)
	// Each carried binding renders as "predicate — tier" (not "predicate@tier"),
	// so a transport-only ref reads distinctly from an anchored one.
	if !strings.Contains(got, "slsa — "+schema.CarriedTierVerifiedTransportOnly) {
		t.Errorf("info line must render carried bindings as 'predicate — tier', got %q", got)
	}
	// An anchored binding surfaces its verifying identity in brackets.
	if !strings.Contains(got, "[https://github.com/acme/builder]") {
		t.Errorf("info line must surface the builder identity of an anchored binding, got %q", got)
	}
}

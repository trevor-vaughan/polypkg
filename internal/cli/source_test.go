package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

// runSource runs the root command in-process with the given args, setting
// POLYPKG_PROFILE to profilePath, and returns combined output.
func runSource(profilePath string, args ...string) (string, error) {
	root := NewRootCmd()
	root.SilenceUsage = true
	root.SilenceErrors = true
	var buf strings.Builder
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetIn(strings.NewReader(""))
	root.SetArgs(args)
	GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)
	err := root.Execute()
	return buf.String(), err
}

// initMinimalProfile writes a minimal valid profile.yaml to dir and returns
// the file path. It creates a single source named "initial" so there is always
// at least one source (required by the profile schema).
func initMinimalProfile(dir string) string {
	keyContent := minisignPubFile()
	keyPath := filepath.Join(dir, "initial.pub")
	Expect(os.WriteFile(keyPath, []byte(keyContent), 0o600)).To(Succeed())

	// Use the CLI init command to produce a properly schema-valid profile.
	profilePath := filepath.Join(dir, "profile.yaml")
	root := NewRootCmd()
	root.SilenceUsage = true
	root.SilenceErrors = true
	var buf strings.Builder
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetIn(strings.NewReader(""))
	root.SetArgs([]string{
		"init",
		"--source-url", "file:///srv/initial",
		"--trust-root-file", keyPath,
	})
	GinkgoT().Setenv("XDG_CONFIG_HOME", dir)
	GinkgoT().Setenv("POLYPKG_PROFILE", "")
	err := root.Execute()
	Expect(err).NotTo(HaveOccurred(), "init failed: %s", buf.String())

	// init writes to <XDG_CONFIG_HOME>/polypkg/profile.yaml; return that path.
	initProfile := filepath.Join(dir, "polypkg", "profile.yaml")
	if _, serr := os.Stat(initProfile); serr == nil {
		return initProfile
	}
	// Fall through if init placed it somewhere else.
	return profilePath
}

// reparseSources opens profilePath and returns SourcesSpec from the parsed profile.
func reparseSources(profilePath string) schema.SourcesSpec {
	GinkgoHelper()
	f, err := os.Open(profilePath)
	Expect(err).NotTo(HaveOccurred())
	defer func() { _ = f.Close() }()
	p, err := schema.ParseProfile(f, profilePath)
	Expect(err).NotTo(HaveOccurred())
	return p.Sources
}

var _ = Describe("source commands", func() {
	var (
		tmpDir      string
		profilePath string
		extraPub    string
	)

	BeforeEach(func() {
		tmpDir = GinkgoT().TempDir()
		_ = os.Unsetenv("POLYPKG_PROFILE")
		profilePath = initMinimalProfile(tmpDir)

		// Write a second valid .pub for add tests.
		extraPub = filepath.Join(tmpDir, "extra.pub")
		Expect(os.WriteFile(extraPub, []byte(minisignPubFile()), 0o600)).To(Succeed())
	})

	Describe("source add", func() {
		It("adds a source and records it in the profile", func() {
			out, err := runSource(profilePath, "source", "add", "extra",
				"--url", "file:///srv/extra",
				"--trust-root", extraPub,
			)
			Expect(err).NotTo(HaveOccurred(), "source add failed: %s", out)
			Expect(out).To(ContainSubstring("added source extra"))

			sources := reparseSources(profilePath)
			Expect(sources.Sources).To(HaveKey("extra"))
			Expect(sources.Order).To(ContainElement("extra"))
		})

		It("pins --trust-root by content, recording a managed copy", func() {
			// Recording the operator's path would leave the anchor late-bound:
			// re-read on every verification, so whoever can write that path
			// controls what the source is checked against.
			out, err := runSource(profilePath, "source", "add", "extra",
				"--url", "file:///srv/extra",
				"--trust-root", extraPub,
			)
			Expect(err).NotTo(HaveOccurred(), "source add failed: %s", out)

			managed := filepath.Join(tmpDir, "polypkg", "trust", "extra.pub")
			Expect(reparseSources(profilePath).Sources["extra"].TrustRoot).To(Equal(managed))

			saved, rerr := os.ReadFile(managed)
			Expect(rerr).NotTo(HaveOccurred(), "managed copy must be written")
			original, oerr := os.ReadFile(extraPub)
			Expect(oerr).NotTo(HaveOccurred(), "the operator's own file must be left in place")
			Expect(string(saved)).To(Equal(string(original)))
		})

		It("normalizes a bare absolute path URL to file://", func() {
			out, err := runSource(profilePath, "source", "add", "extra",
				"--url", "/srv/extra",
				"--trust-root", extraPub,
			)
			Expect(err).NotTo(HaveOccurred(), "source add failed: %s", out)

			sources := reparseSources(profilePath)
			Expect(sources.Sources["extra"].URL).To(Equal("file:///srv/extra"))
		})

		It("errors when both --trust-root and --trust-root-url are supplied", func() {
			pub := extraPub
			_, err := runSource(profilePath, "source", "add", "extra",
				"--url", "file:///srv/extra",
				"--trust-root", pub,
				"--trust-root-url", "https://example.com/key.pub",
			)
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
			Expect(ce.Msg).To(ContainSubstring("use only one of"))
		})

		It("errors when neither --trust-root nor --trust-root-url is supplied", func() {
			_, err := runSource(profilePath, "source", "add", "extra",
				"--url", "file:///srv/extra",
			)
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
			Expect(ce.Msg).To(ContainSubstring("trust root is required"))
			Expect(ce.Hint).To(ContainSubstring("--trust-root"))
		})

		It("places the source first in order when --order-first is set", func() {
			out, err := runSource(profilePath, "source", "add", "prio",
				"--url", "file:///srv/prio",
				"--trust-root", extraPub,
				"--order-first",
			)
			Expect(err).NotTo(HaveOccurred(), "source add --order-first failed: %s", out)

			sources := reparseSources(profilePath)
			Expect(sources.Order).NotTo(BeEmpty())
			Expect(sources.Order[0]).To(Equal("prio"))
		})

		It("rejects a source name that fails the slug grammar", func() {
			out, err := runSource(profilePath, "source", "add", "bad name",
				"--url", "file:///srv/bad",
				"--trust-root", extraPub,
			)
			Expect(err).To(HaveOccurred(), "expected source add to fail for invalid slug, got: %s", out)
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
			Expect(ce.Msg).To(ContainSubstring("is not a valid slug"))
		})

		It("rejects a source named \"order\" because it collides with the reserved order key", func() {
			out, err := runSource(profilePath, "source", "add", "order",
				"--url", "file:///srv/order",
				"--trust-root", extraPub,
			)
			Expect(err).To(HaveOccurred(), "expected source add order to be rejected, got: %s", out)
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
			Expect(ce.Msg).To(ContainSubstring("order"))
			Expect(ce.Hint).NotTo(BeEmpty())

			// The profile must be untouched: no "order" source, and every entry
			// in sources.order must still map to a real source (i.e. the order
			// array was not corrupted by writing scalar fields into it).
			sources := reparseSources(profilePath)
			Expect(sources.Sources).NotTo(HaveKey("order"))
			for _, name := range sources.Order {
				Expect(sources.Sources).To(HaveKey(name),
					"order entry %q has no matching source — the order array was corrupted", name)
			}
		})

		It("emits JSON cli-result/v2 with source fields when --format json", func() {
			out, err := runSource(profilePath, "--format", "json", "source", "add", "extra",
				"--url", "file:///srv/extra",
				"--trust-root", extraPub,
			)
			Expect(err).NotTo(HaveOccurred(), "source add json failed: %s", out)
			result := parseSingleCLIResult(out)
			Expect(result.Status).To(Equal("ok"))
			Expect(result.Command).To(Equal("source add"))
			Expect(result.Data).NotTo(BeNil())
			Expect(result.Data["name"]).To(Equal("extra"))
			Expect(result.Data["url"]).To(Equal("file:///srv/extra"))
		})

		It("downloads, persists, and uses the .pub when --trust-root-url + --trust-root-yes", func() {
			pubContent := minisignPubFile()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(pubContent))
			}))
			defer srv.Close()

			// scopeConfigDir for user scope = XDG_CONFIG_HOME/polypkg. The
			// POLYPKG_PROFILE env points at a file inside there already from init.
			cfgDir := filepath.Dir(profilePath)
			GinkgoT().Setenv("XDG_CONFIG_HOME", filepath.Dir(cfgDir))

			out, err := runSource(profilePath, "source", "add", "withurl",
				"--url", "file:///srv/withurl",
				"--trust-root-url", srv.URL+"/key.pub",
				"--trust-root-yes",
			)
			Expect(err).NotTo(HaveOccurred(), "source add --trust-root-url failed: %s", out)

			sources := reparseSources(profilePath)
			Expect(sources.Sources).To(HaveKey("withurl"))
			// trust_root must be an absolute path to a persisted .pub, not the URL.
			tr := sources.Sources["withurl"].TrustRoot
			Expect(tr).To(HavePrefix("/"))
			Expect(tr).To(HaveSuffix(".pub"))
			Expect(tr).NotTo(ContainSubstring("http"))

			// The .pub file must exist on disk.
			_, statErr := os.Stat(tr)
			Expect(statErr).NotTo(HaveOccurred(), "persisted .pub must exist at trust_root path")
		})
	})

	Describe("source remove", func() {
		BeforeEach(func() {
			// Ensure 'extra' is present before remove tests.
			_, err := runSource(profilePath, "source", "add", "extra",
				"--url", "file:///srv/extra",
				"--trust-root", extraPub,
			)
			Expect(err).NotTo(HaveOccurred())
		})

		It("removes a source from the profile", func() {
			out, err := runSource(profilePath, "source", "remove", "extra")
			Expect(err).NotTo(HaveOccurred(), "source remove failed: %s", out)
			Expect(out).To(ContainSubstring("removed source extra"))

			sources := reparseSources(profilePath)
			Expect(sources.Sources).NotTo(HaveKey("extra"))
			Expect(sources.Order).NotTo(ContainElement("extra"))
		})

		It("returns a friendly CLIError when the source is not in the profile", func() {
			_, err := runSource(profilePath, "source", "remove", "ghost")
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
			Expect(ce.Msg).To(ContainSubstring("ghost"))
			Expect(ce.Msg).To(ContainSubstring("not in the profile"))
			Expect(ce.Hint).To(ContainSubstring("polypkg source list"))
		})

		It("names the configured sources in the error when a remove fails", func() {
			_, err := runSource(profilePath, "source", "remove", "ghost")
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue())
			// 'extra' (and possibly 'initial' from init) should appear in msg.
			Expect(ce.Msg).To(Or(
				ContainSubstring("extra"),
				ContainSubstring("initial"),
			))
		})

		It("deletes the orphaned managed trust-root key on remove", func() {
			// A source whose key was downloaded via --trust-root-url is persisted
			// under <configdir>/trust/<name>.pub. Removing the source should clean
			// up that now-orphaned managed key.
			pubContent := minisignPubFile()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(pubContent))
			}))
			defer srv.Close()

			// scopeConfigDir("user") = XDG_CONFIG_HOME/polypkg, which must match the
			// dir the init-created profile lives in so add and remove agree.
			cfgDir := filepath.Dir(profilePath)
			GinkgoT().Setenv("XDG_CONFIG_HOME", filepath.Dir(cfgDir))

			_, err := runSource(profilePath, "source", "add", "withurl",
				"--url", "file:///srv/withurl",
				"--trust-root-url", srv.URL+"/key.pub",
				"--trust-root-yes",
			)
			Expect(err).NotTo(HaveOccurred())

			keyPath := reparseSources(profilePath).Sources["withurl"].TrustRoot
			_, statErr := os.Stat(keyPath)
			Expect(statErr).NotTo(HaveOccurred(), "managed key should exist after add")

			_, err = runSource(profilePath, "source", "remove", "withurl")
			Expect(err).NotTo(HaveOccurred())

			_, statErr = os.Stat(keyPath)
			Expect(os.IsNotExist(statErr)).To(BeTrue(),
				"managed orphan key should be deleted on remove; stat err: %v", statErr)
		})

		It("keeps a managed key still referenced by another source", func() {
			// Every `source add` route now pins its own copy at
			// trust/<name>.pub, so the commands alone cannot make two sources
			// share one key. A hand-edited profile still can, which is what the
			// reference check in managedOrphanTrustRoot guards: removing one
			// source must not delete a key the other is still anchored to.
			pubContent := minisignPubFile()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(pubContent))
			}))
			defer srv.Close()

			cfgDir := filepath.Dir(profilePath)
			GinkgoT().Setenv("XDG_CONFIG_HOME", filepath.Dir(cfgDir))

			_, err := runSource(profilePath, "source", "add", "primary",
				"--url", "file:///srv/primary",
				"--trust-root-url", srv.URL+"/key.pub",
				"--trust-root-yes",
			)
			Expect(err).NotTo(HaveOccurred())
			keyPath := reparseSources(profilePath).Sources["primary"].TrustRoot

			_, err = runSource(profilePath, "source", "add", "secondary",
				"--url", "file:///srv/secondary",
				"--trust-root", extraPub,
			)
			Expect(err).NotTo(HaveOccurred())

			// Hand-edit secondary onto primary's key.
			secondaryKey := reparseSources(profilePath).Sources["secondary"].TrustRoot
			Expect(secondaryKey).NotTo(Equal(keyPath), "each add must pin its own copy")
			raw, rerr := os.ReadFile(profilePath)
			Expect(rerr).NotTo(HaveOccurred())
			edited := strings.Replace(string(raw), secondaryKey, keyPath, 1)
			Expect(edited).NotTo(Equal(string(raw)), "profile must reference the pinned copy")
			Expect(os.WriteFile(profilePath, []byte(edited), 0o600)).To(Succeed())

			_, err = runSource(profilePath, "source", "remove", "primary")
			Expect(err).NotTo(HaveOccurred())

			_, statErr := os.Stat(keyPath)
			Expect(statErr).NotTo(HaveOccurred(),
				"a managed key still referenced by another source must not be deleted")
		})

		It("leaves an externally-supplied --trust-root file in place on remove", func() {
			// 'extra' was added in BeforeEach with --trust-root extraPub. The
			// profile anchors to the pinned copy, so remove cleans that up —
			// but extraPub itself is the operator's own file, read once and
			// never owned by polypkg. Removing the source must not touch it.
			_, statErr := os.Stat(extraPub)
			Expect(statErr).NotTo(HaveOccurred())

			_, err := runSource(profilePath, "source", "remove", "extra")
			Expect(err).NotTo(HaveOccurred())

			_, statErr = os.Stat(extraPub)
			Expect(statErr).NotTo(HaveOccurred(), "external --trust-root file must be left intact")
		})

		It("emits JSON cli-result/v2 with the removed name when --format json", func() {
			out, err := runSource(profilePath, "--format", "json", "source", "remove", "extra")
			Expect(err).NotTo(HaveOccurred(), "source remove json failed: %s", out)
			result := parseSingleCLIResult(out)
			Expect(result.Status).To(Equal("ok"))
			Expect(result.Command).To(Equal("source remove"))
			Expect(result.Data["name"]).To(Equal("extra"))
		})

		It("refuses to remove the last source with a friendly CLIError", func() {
			// After BeforeEach we have two sources: native (from init) and extra.
			// Remove extra first so only native remains, then try to remove native.
			_, err := runSource(profilePath, "source", "remove", "extra")
			Expect(err).NotTo(HaveOccurred())

			_, err = runSource(profilePath, "source", "remove", "native")
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
			Expect(ce.Msg).To(ContainSubstring("last source"))
			Expect(ce.Msg).To(ContainSubstring("native"))
			Expect(ce.Hint).To(ContainSubstring("add another source"))

			// Profile must be unchanged.
			sources := reparseSources(profilePath)
			Expect(sources.Sources).To(HaveKey("native"))
			Expect(sources.Order).To(ContainElement("native"))
		})

		It("clears the persisted anti-rollback floor on remove so a later re-add starts clean", func() {
			// Pin the state home the CLI resolves (scopeHomes("user", "") ->
			// paths.UserStateHome(), which honors XDG_STATE_HOME but appends the
			// "polypkg" appName segment — see paths.xdgUserDir) so the
			// StoreSeen/LoadSeen calls below agree with what runSourceRemove uses.
			GinkgoT().Setenv("XDG_DATA_HOME", filepath.Join(tmpDir, "data"))
			GinkgoT().Setenv("XDG_STATE_HOME", filepath.Join(tmpDir, "state"))
			stateHome := filepath.Join(tmpDir, "state", "polypkg")

			Expect(trust.StoreSeen(stateHome, "extra", trust.Seen{TrustSerial: 4, BundleSerial: 2})).To(Succeed())

			out, err := runSource(profilePath, "source", "remove", "extra")
			Expect(err).NotTo(HaveOccurred(), "source remove failed: %s", out)

			seen, err := trust.LoadSeen(stateHome, "extra")
			Expect(err).NotTo(HaveOccurred())
			Expect(seen).To(Equal(trust.Seen{}), "expected the persisted floor to be cleared on remove")
		})

		It("succeeds when removing one of two sources", func() {
			// extra was added in BeforeEach; native (from init) also exists.
			out, err := runSource(profilePath, "source", "remove", "extra")
			Expect(err).NotTo(HaveOccurred(), "remove of one-of-two failed: %s", out)

			sources := reparseSources(profilePath)
			Expect(sources.Sources).NotTo(HaveKey("extra"))
			Expect(sources.Order).To(ContainElement("native"))
		})
	})

	Describe("source list", func() {
		BeforeEach(func() {
			// Add a second source so list has something to show beyond 'initial'.
			_, err := runSource(profilePath, "source", "add", "extra",
				"--url", "file:///srv/extra",
				"--trust-root", extraPub,
			)
			Expect(err).NotTo(HaveOccurred())
		})

		It("prints the configured source names", func() {
			out, err := runSource(profilePath, "source", "list")
			Expect(err).NotTo(HaveOccurred(), "source list failed: %s", out)
			Expect(out).To(ContainSubstring("initial"))
			Expect(out).To(ContainSubstring("extra"))
		})

		It("shows order position numbers in text output", func() {
			out, err := runSource(profilePath, "source", "list")
			Expect(err).NotTo(HaveOccurred(), "source list failed: %s", out)
			// First ordered source must appear with position "1:".
			Expect(out).To(ContainSubstring("1:"))
			// Second ordered source must appear with position "2:".
			Expect(out).To(ContainSubstring("2:"))
			// Header line must have a "#" column.
			Expect(out).To(ContainSubstring("#"))
		})

		It("emits a cli-result/v2 JSON envelope with sources and order arrays", func() {
			out, err := runSource(profilePath, "--format", "json", "source", "list")
			Expect(err).NotTo(HaveOccurred(), "source list json failed: %s", out)
			result := parseSingleCLIResult(out)
			Expect(result.Status).To(Equal("ok"))
			Expect(result.Command).To(Equal("source list"))
			Expect(result.Data).NotTo(BeNil())

			// 'sources' must be a non-empty list.
			raw, _ := json.Marshal(result.Data["sources"])
			var sources []map[string]any
			Expect(json.Unmarshal(raw, &sources)).To(Succeed())
			Expect(sources).NotTo(BeEmpty())

			// All source entries must have the required fields.
			for _, s := range sources {
				Expect(s).To(HaveKey("name"))
				Expect(s).To(HaveKey("type"))
				Expect(s).To(HaveKey("url"))
				Expect(s).To(HaveKey("trust_root"))
			}

			// 'order' must be a list.
			rawOrder, _ := json.Marshal(result.Data["order"])
			var order []string
			Expect(json.Unmarshal(rawOrder, &order)).To(Succeed())
			Expect(order).NotTo(BeEmpty())
		})

		It("returns a parse error (not a panic) when the profile has no sources at all", func() {
			// The profile schema requires sources.order to have at least 1 entry
			// (minItems: 1), so a truly empty sources block is schema-invalid.
			// Verify that source list returns a structured error rather than
			// panicking or emitting garbage.
			emptyProfilePath := filepath.Join(tmpDir, "empty-profile.yaml")
			const emptyProfile = `schema: polypkg.spec/v1
name: test-machine
scopes:
  user:
    substrate: xdg
sources:
  order: []
`
			Expect(os.WriteFile(emptyProfilePath, []byte(emptyProfile), 0o600)).To(Succeed())

			_, err := runSource(emptyProfilePath, "source", "list")
			// The command should return an error because the profile is schema-invalid,
			// not crash or produce undefined output.
			Expect(err).To(HaveOccurred())
		})
	})
})

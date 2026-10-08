package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/lock"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

// runSource runs the root command in-process with the given args, setting
// POLYPKG_PROFILE to profilePath, and returns combined output. Its stdin is
// empty and not a terminal.
func runSource(profilePath string, args ...string) (string, error) {
	return runWithStdin(profilePath, strings.NewReader(""), args...)
}

// runWithStdin is runSource with in as the command's stdin; pass ttyInput to
// answer a confirmation prompt.
func runWithStdin(profilePath string, in io.Reader, args ...string) (string, error) {
	root := NewRootCmd()
	root.SilenceUsage = true
	root.SilenceErrors = true
	var buf strings.Builder
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetIn(in)
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
		"--trust-root", keyPath,
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

// holdApplyLock takes the apply lock under stateHome as a running apply would,
// releasing it when the spec ends.
func holdApplyLock(stateHome string) {
	GinkgoHelper()
	held, err := lock.Acquire(context.Background(), filepath.Join(stateHome, "apply.lock"),
		lock.Options{TxID: "apply", Command: "polypkg apply"})
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(held.Release)
}

// expectApplyLockRefusal asserts err is the lock-holder CLIError naming the
// apply that holdApplyLock started.
func expectApplyLockRefusal(err error) {
	GinkgoHelper()
	var ce *CLIError
	Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
	Expect(ce.Msg).To(Equal("another polypkg command is already running (polypkg apply, pid " + strconv.Itoa(os.Getpid()) + ")"))
}

var _ = Describe("source commands", func() {
	var (
		tmpDir      string
		profilePath string
		extraPub    string
		stateHome   string
	)

	BeforeEach(func() {
		// The commands take the apply lock and clear trust state under the
		// user state home, so keep that inside the test's own tree.
		stateHome = filepath.Join(sandboxUserEnv(GinkgoTB()), "state", "polypkg")
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

		// The anchor is copied before the profile is edited, so a failed edit
		// would otherwise leave a key behind for a source that was never added.
		// A read-only config dir lets the profile parse (and the anchor land in
		// the writable trust/ subdir) but makes the atomic profile rewrite fail.
		It("removes the key it just pinned when the profile edit fails", func() {
			if os.Geteuid() == 0 {
				Skip("a read-only config directory does not stop root")
			}
			cfgDir := filepath.Dir(profilePath)
			Expect(os.Chmod(cfgDir, 0o500)).To(Succeed())
			DeferCleanup(os.Chmod, cfgDir, os.FileMode(0o700))

			_, err := runSource(profilePath, "source", "add", "extra",
				"--url", "file:///srv/extra",
				"--trust-root", extraPub,
			)
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
			Expect(ce.Msg).To(ContainSubstring(`cannot add source "extra" to profile`))

			_, statErr := os.Stat(filepath.Join(cfgDir, "trust", "extra.pub"))
			Expect(os.IsNotExist(statErr)).To(BeTrue(),
				"a failed add must not leave a stray anchor; stat err: %v", statErr)
			_, oErr := os.Stat(extraPub)
			Expect(oErr).NotTo(HaveOccurred(), "the operator's own file must be untouched")
		})

		It("keeps an identical anchor it did not create when the profile edit fails", func() {
			if os.Geteuid() == 0 {
				Skip("a read-only config directory does not stop root")
			}
			// A leftover anchor holding the same key is accepted, but it was
			// not this run's to delete.
			cfgDir := filepath.Dir(profilePath)
			managed := filepath.Join(cfgDir, "trust", "extra.pub")
			key, rerr := os.ReadFile(extraPub)
			Expect(rerr).NotTo(HaveOccurred())
			Expect(os.WriteFile(managed, key, 0o644)).To(Succeed())
			Expect(os.Chmod(cfgDir, 0o500)).To(Succeed())
			DeferCleanup(os.Chmod, cfgDir, os.FileMode(0o700))

			_, err := runSource(profilePath, "source", "add", "extra",
				"--url", "file:///srv/extra",
				"--trust-root", extraPub,
			)
			Expect(err).To(HaveOccurred())
			Expect(os.ReadFile(managed)).To(Equal(key))
		})

		It("refuses a name already in the profile before reading any trust root", func() {
			managed := filepath.Join(tmpDir, "polypkg", "trust", "native.pub")
			pinned, rerr := os.ReadFile(managed)
			Expect(rerr).NotTo(HaveOccurred())

			// The trust-root file does not exist: reaching the trust-root step
			// would fail with a different message.
			_, err := runSource(profilePath, "source", "add", "native",
				"--url", "file:///srv/elsewhere",
				"--trust-root", filepath.Join(tmpDir, "no-such.pub"),
			)
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
			Expect(ce.Msg).To(Equal(`source "native" already exists`))
			Expect(ce.Hint).To(ContainSubstring("polypkg source set-trust-root native"))
			Expect(ce.Hint).To(ContainSubstring("`source remove` then `source add`"))

			Expect(os.ReadFile(managed)).To(Equal(pinned))
			Expect(reparseSources(profilePath).Sources["native"].URL).To(Equal("file:///srv/initial"))
		})

		It("refuses while another command holds the apply lock and writes nothing", func() {
			before, rerr := os.ReadFile(profilePath)
			Expect(rerr).NotTo(HaveOccurred())
			holdApplyLock(stateHome)

			_, err := runSource(profilePath, "source", "add", "extra",
				"--url", "file:///srv/extra",
				"--trust-root", extraPub,
			)
			expectApplyLockRefusal(err)

			Expect(os.ReadFile(profilePath)).To(Equal(before))
			Expect(filepath.Join(tmpDir, "polypkg", "trust", "extra.pub")).NotTo(BeAnExistingFile())
		})

		It("refuses a name already in the profile without downloading anything", func() {
			var hits atomic.Int32
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				_, _ = w.Write([]byte(minisignPubFile()))
			}))
			DeferCleanup(srv.Close)
			useTrustRootServer(srv)

			_, err := runSource(profilePath, "source", "add", "native",
				"--url", "file:///srv/elsewhere",
				"--trust-root-url", srv.URL+"/key.pub",
			)
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
			Expect(ce.Msg).To(Equal(`source "native" already exists`))
			Expect(hits.Load()).To(BeZero(), "no trust root may be fetched for an existing name")
		})

		It("refuses to overwrite a different key already pinned for the name", func() {
			// A leftover anchor (e.g. from a source deleted by hand-editing the
			// profile) must not be silently re-pointed at another key.
			managed := filepath.Join(tmpDir, "polypkg", "trust", "extra.pub")
			leftover := []byte(minisignPubFile())
			Expect(os.WriteFile(managed, leftover, 0o644)).To(Succeed())

			_, err := runSource(profilePath, "source", "add", "extra",
				"--url", "file:///srv/extra",
				"--trust-root", extraPub,
			)
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
			Expect(ce.Msg).To(ContainSubstring("already pinned at " + managed))
			Expect(os.ReadFile(managed)).To(Equal(leftover))
			Expect(reparseSources(profilePath).Sources).NotTo(HaveKey("extra"))
		})

		It("refuses --trust-root-url with a mismatched fingerprint and adds nothing", func() {
			srv := serveTrustRoot(minisignPubFile())

			_, err := runSource(profilePath, "source", "add", "withurl",
				"--url", "file:///srv/withurl",
				"--trust-root-url", srv.URL+"/key.pub",
				"--trust-root-fingerprint", "0000000000000000",
			)
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
			Expect(ce.Msg).To(ContainSubstring(`not the expected "0000000000000000"`))
			Expect(filepath.Join(tmpDir, "polypkg", "trust", "withurl.pub")).NotTo(BeAnExistingFile())
			Expect(reparseSources(profilePath).Sources).NotTo(HaveKey("withurl"))
		})

		It("refuses --trust-root-url without a fingerprint on a non-TTY", func() {
			srv := serveTrustRoot(minisignPubFile())

			_, err := runSource(profilePath, "source", "add", "withurl",
				"--url", "file:///srv/withurl",
				"--trust-root-url", srv.URL+"/key.pub",
			)
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
			Expect(ce.Hint).To(ContainSubstring("--trust-root-fingerprint"))
			Expect(reparseSources(profilePath).Sources).NotTo(HaveKey("withurl"))
		})

		It("refuses --trust-root with a mismatched fingerprint", func() {
			_, err := runSource(profilePath, "source", "add", "extra",
				"--url", "file:///srv/extra",
				"--trust-root", extraPub,
				"--trust-root-fingerprint", "0000000000000000",
			)
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
			Expect(ce.Msg).To(ContainSubstring(`not the expected "0000000000000000"`))
			Expect(reparseSources(profilePath).Sources).NotTo(HaveKey("extra"))
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
			Expect(ce.Hint).To(ContainSubstring("e.g. team-mirror"))
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

		It("downloads, persists, and uses the .pub when --trust-root-url + --trust-root-fingerprint", func() {
			pubContent := minisignPubFile()
			srv := serveTrustRoot(pubContent)

			// scopeConfigDir for user scope = XDG_CONFIG_HOME/polypkg. The
			// POLYPKG_PROFILE env points at a file inside there already from init.
			cfgDir := filepath.Dir(profilePath)
			GinkgoT().Setenv("XDG_CONFIG_HOME", filepath.Dir(cfgDir))

			out, err := runSource(profilePath, "source", "add", "withurl",
				"--url", "file:///srv/withurl",
				"--trust-root-url", srv.URL+"/key.pub",
				"--trust-root-fingerprint", keyIDOf(pubContent),
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
			srv := serveTrustRoot(pubContent)

			// scopeConfigDir("user") = XDG_CONFIG_HOME/polypkg, which must match the
			// dir the init-created profile lives in so add and remove agree.
			cfgDir := filepath.Dir(profilePath)
			GinkgoT().Setenv("XDG_CONFIG_HOME", filepath.Dir(cfgDir))

			_, err := runSource(profilePath, "source", "add", "withurl",
				"--url", "file:///srv/withurl",
				"--trust-root-url", srv.URL+"/key.pub",
				"--trust-root-fingerprint", keyIDOf(pubContent),
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
			srv := serveTrustRoot(pubContent)

			cfgDir := filepath.Dir(profilePath)
			GinkgoT().Setenv("XDG_CONFIG_HOME", filepath.Dir(cfgDir))

			_, err := runSource(profilePath, "source", "add", "primary",
				"--url", "file:///srv/primary",
				"--trust-root-url", srv.URL+"/key.pub",
				"--trust-root-fingerprint", keyIDOf(pubContent),
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
			// stateHome (from BeforeEach's sandbox) is the state home the CLI
			// resolves, so the StoreSeen/LoadSeen calls below agree with what
			// runSourceRemove uses.
			Expect(trust.StoreSeen(stateHome, "extra", trust.Seen{TrustSerial: 4, BundleSerial: 2})).To(Succeed())

			out, err := runSource(profilePath, "source", "remove", "extra")
			Expect(err).NotTo(HaveOccurred(), "source remove failed: %s", out)

			seen, err := trust.LoadSeen(stateHome, "extra")
			Expect(err).NotTo(HaveOccurred())
			Expect(seen).To(Equal(trust.Seen{}), "expected the persisted floor to be cleared on remove")
		})

		It("refuses while another command holds the apply lock and writes nothing", func() {
			managed := filepath.Join(tmpDir, "polypkg", "trust", "extra.pub")
			Expect(managed).To(BeAnExistingFile())
			Expect(trust.StoreSeen(stateHome, "extra", trust.Seen{TrustSerial: 4})).To(Succeed())
			before, rerr := os.ReadFile(profilePath)
			Expect(rerr).NotTo(HaveOccurred())
			holdApplyLock(stateHome)

			_, err := runSource(profilePath, "source", "remove", "extra")
			expectApplyLockRefusal(err)

			Expect(os.ReadFile(profilePath)).To(Equal(before))
			Expect(managed).To(BeAnExistingFile())
			Expect(trust.LoadSeen(stateHome, "extra")).To(Equal(trust.Seen{TrustSerial: 4}))
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

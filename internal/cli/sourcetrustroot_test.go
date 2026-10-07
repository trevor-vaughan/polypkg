package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/jedisct1/go-minisign"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

// pubFileWithKeyID returns a minisign .pub file for a fresh Ed25519 key that
// carries the given key id, so two different keys can share an id.
func pubFileWithKeyID(keyID [8]byte) string {
	GinkgoHelper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	bin := append([]byte{'E', 'd'}, keyID[:]...)
	bin = append(bin, pub...)
	return "untrusted comment: polypkg test public key\n" + base64.StdEncoding.EncodeToString(bin) + "\n"
}

var _ = Describe("source set-trust-root", func() {
	var (
		tmpDir      string
		profilePath string
		managed     string // the managed anchor init pinned for "native"
		oldKey      []byte
		oldID       string
		newPub      string // a different key, as a local file
		newKey      []byte
		newID       string
		stateHome   string
	)

	BeforeEach(func() {
		tmpDir = sandboxUserEnv(GinkgoTB())
		_ = os.Unsetenv("POLYPKG_PROFILE")
		// initMinimalProfile sets XDG_CONFIG_HOME=tmpDir and writes a profile
		// whose only source is "native".
		profilePath = initMinimalProfile(tmpDir)
		// paths.UserStateHome appends the "polypkg" segment to XDG_STATE_HOME.
		stateHome = filepath.Join(tmpDir, "state", "polypkg")

		managed = filepath.Join(tmpDir, "polypkg", "trust", "native.pub")
		var err error
		oldKey, err = os.ReadFile(managed)
		Expect(err).NotTo(HaveOccurred())
		oldID = keyIDOf(string(oldKey))

		newKey = []byte(minisignPubFile())
		newID = keyIDOf(string(newKey))
		newPub = filepath.Join(tmpDir, "new.pub")
		Expect(os.WriteFile(newPub, newKey, 0o600)).To(Succeed())
	})

	It("replaces the key of the only source when the fingerprint matches", func() {
		Expect(reparseSources(profilePath).Order).To(Equal([]string{"native"}))

		out, err := runSource(profilePath, "source", "set-trust-root", "native",
			"--trust-root", newPub, "--trust-root-fingerprint", newID)
		Expect(err).NotTo(HaveOccurred(), "set-trust-root failed: %s", out)
		Expect(out).To(ContainSubstring("replaced trust root of source native"))
		Expect(out).To(ContainSubstring("old key id: " + oldID))
		Expect(out).To(ContainSubstring("new key id: " + newID))

		Expect(os.ReadFile(managed)).To(Equal(newKey))
		Expect(reparseSources(profilePath).Sources["native"].TrustRoot).To(Equal(managed))
	})

	It("clears the source's anti-rollback state so a re-created repository is accepted", func() {
		Expect(trust.StoreSeen(stateHome, "native", trust.Seen{TrustSerial: 7, IndexSerial: 7})).To(Succeed())

		out, err := runSource(profilePath, "source", "set-trust-root", "native",
			"--trust-root", newPub, "--trust-root-fingerprint", newID)
		Expect(err).NotTo(HaveOccurred(), "set-trust-root failed: %s", out)

		seen, err := trust.LoadSeen(stateHome, "native")
		Expect(err).NotTo(HaveOccurred())
		Expect(seen).To(Equal(trust.Seen{}))
	})

	It("refuses while another command holds the apply lock and writes nothing", func() {
		// An apply holding the lock may store fresh floors after a reset made
		// without it, restoring exactly what this command clears.
		Expect(trust.StoreSeen(stateHome, "native", trust.Seen{TrustSerial: 7, IndexSerial: 7})).To(Succeed())
		before, rerr := os.ReadFile(profilePath)
		Expect(rerr).NotTo(HaveOccurred())
		holdApplyLock(stateHome)

		_, err := runSource(profilePath, "source", "set-trust-root", "native",
			"--trust-root", newPub, "--trust-root-fingerprint", newID)
		expectApplyLockRefusal(err)

		Expect(os.ReadFile(profilePath)).To(Equal(before))
		Expect(os.ReadFile(managed)).To(Equal(oldKey))
		Expect(trust.LoadSeen(stateHome, "native")).To(Equal(trust.Seen{TrustSerial: 7, IndexSerial: 7}))
	})

	It("emits the old and new key ids in JSON", func() {
		out, err := runSource(profilePath, "--format", "json", "source", "set-trust-root", "native",
			"--trust-root", newPub, "--trust-root-fingerprint", newID)
		Expect(err).NotTo(HaveOccurred(), "set-trust-root json failed: %s", out)
		result := parseSingleCLIResult(out)
		Expect(result.Status).To(Equal("ok"))
		Expect(result.Command).To(Equal("source set-trust-root"))
		Expect(result.Data).To(Equal(map[string]any{
			"name":            "native",
			"old_fingerprint": oldID,
			"new_fingerprint": newID,
			"trust_root":      managed,
			"changed":         true,
			"state_reset":     true,
		}))
	})

	It("downloads the new key over https", func() {
		srv := serveTrustRoot(string(newKey))

		out, err := runSource(profilePath, "source", "set-trust-root", "native",
			"--trust-root-url", srv.URL+"/key.pub", "--trust-root-fingerprint", newID)
		Expect(err).NotTo(HaveOccurred(), "set-trust-root failed: %s", out)
		Expect(os.ReadFile(managed)).To(Equal(newKey))
	})

	It("reports unchanged, and keeps the anti-rollback state, for the key already pinned", func() {
		Expect(trust.StoreSeen(stateHome, "native", trust.Seen{TrustSerial: 7, IndexSerial: 7})).To(Succeed())
		samePub := filepath.Join(tmpDir, "same.pub")
		Expect(os.WriteFile(samePub, oldKey, 0o600)).To(Succeed())

		// No fingerprint and no TTY: an unchanged key needs no confirmation.
		out, err := runSource(profilePath, "--format", "json", "source", "set-trust-root", "native",
			"--trust-root", samePub)
		Expect(err).NotTo(HaveOccurred(), "set-trust-root failed: %s", out)
		result := parseSingleCLIResult(out)
		Expect(result.Data["changed"]).To(BeFalse())
		Expect(result.Data["state_reset"]).To(BeFalse())
		Expect(result.Data["old_fingerprint"]).To(Equal(oldID))

		seen, err := trust.LoadSeen(stateHome, "native")
		Expect(err).NotTo(HaveOccurred())
		Expect(seen).To(Equal(trust.Seen{TrustSerial: 7, IndexSerial: 7}))
	})

	It("treats the same key with a different comment line and trailing newline as unchanged", func() {
		Expect(trust.StoreSeen(stateHome, "native", trust.Seen{TrustSerial: 7, IndexSerial: 7})).To(Succeed())
		lines := strings.SplitN(string(oldKey), "\n", 2)
		reexported := "untrusted comment: same key, re-exported\n" + lines[1] + "\n"
		Expect(reexported).NotTo(Equal(string(oldKey)))
		samePub := filepath.Join(tmpDir, "reexported.pub")
		Expect(os.WriteFile(samePub, []byte(reexported), 0o600)).To(Succeed())

		// No fingerprint and no TTY: an unchanged key needs no confirmation.
		out, err := runSource(profilePath, "--format", "json", "source", "set-trust-root", "native",
			"--trust-root", samePub)
		Expect(err).NotTo(HaveOccurred(), "set-trust-root failed: %s", out)
		result := parseSingleCLIResult(out)
		Expect(result.Data["changed"]).To(BeFalse())
		Expect(result.Data["state_reset"]).To(BeFalse())

		seen, err := trust.LoadSeen(stateHome, "native")
		Expect(err).NotTo(HaveOccurred())
		Expect(seen).To(Equal(trust.Seen{TrustSerial: 7, IndexSerial: 7}))
		Expect(os.ReadFile(managed)).To(Equal(oldKey), "an unchanged key leaves the pinned file as it is")
	})

	It("treats a different key that reuses the pinned key id as changed", func() {
		Expect(trust.StoreSeen(stateHome, "native", trust.Seen{TrustSerial: 7})).To(Succeed())
		pinned, err := minisign.DecodePublicKey(string(oldKey))
		Expect(err).NotTo(HaveOccurred())
		impostor := []byte(pubFileWithKeyID(pinned.KeyId))
		impostorPub := filepath.Join(tmpDir, "impostor.pub")
		Expect(os.WriteFile(impostorPub, impostor, 0o600)).To(Succeed())

		out, err := runSource(profilePath, "--format", "json", "source", "set-trust-root", "native",
			"--trust-root", impostorPub, "--trust-root-fingerprint", oldID)
		Expect(err).NotTo(HaveOccurred(), "set-trust-root failed: %s", out)
		result := parseSingleCLIResult(out)
		Expect(result.Data["changed"]).To(BeTrue())
		Expect(result.Data["state_reset"]).To(BeTrue())
		Expect(os.ReadFile(managed)).To(Equal(impostor))
	})

	It("refuses a fingerprint that does not match the new key and changes nothing", func() {
		Expect(trust.StoreSeen(stateHome, "native", trust.Seen{TrustSerial: 7})).To(Succeed())

		_, err := runSource(profilePath, "source", "set-trust-root", "native",
			"--trust-root", newPub, "--trust-root-fingerprint", oldID)
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("has key id " + newID))
		Expect(ce.Msg).To(ContainSubstring(`not the expected "` + oldID + `"`))

		Expect(os.ReadFile(managed)).To(Equal(oldKey))
		seen, lerr := trust.LoadSeen(stateHome, "native")
		Expect(lerr).NotTo(HaveOccurred())
		Expect(seen.TrustSerial).To(Equal(uint64(7)))
	})

	It("refuses a wrong fingerprint even when the key is unchanged", func() {
		samePub := filepath.Join(tmpDir, "same.pub")
		Expect(os.WriteFile(samePub, oldKey, 0o600)).To(Succeed())

		_, err := runSource(profilePath, "source", "set-trust-root", "native",
			"--trust-root", samePub, "--trust-root-fingerprint", "0000000000000000")
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring(`not the expected "0000000000000000"`))
	})

	It("refuses without a fingerprint when stdin is not a terminal", func() {
		_, err := runSource(profilePath, "source", "set-trust-root", "native", "--trust-root", newPub)
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("stdin is not a terminal"))
		Expect(ce.Hint).To(ContainSubstring("--trust-root-fingerprint"))
		Expect(os.ReadFile(managed)).To(Equal(oldKey))
	})

	It("refuses without a fingerprint when stdin is /dev/null, which is not a terminal", func() {
		devNull, err := os.Open(os.DevNull)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(devNull.Close)

		out, err := runWithStdin(profilePath, devNull, "source", "set-trust-root", "native", "--trust-root", newPub)
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("stdin is not a terminal"))
		Expect(out).NotTo(ContainSubstring("[y/N]"), "a redirected stdin must not be prompted")
		Expect(os.ReadFile(managed)).To(Equal(oldKey))
	})

	It("prompts on a terminal with both key ids and refuses an answer that is not yes", func() {
		// End of input on a terminal is an answer that is not yes.
		out, err := runWithStdin(profilePath, ttyInput{strings.NewReader("")},
			"source", "set-trust-root", "native", "--trust-root", newPub)
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("not confirmed"))
		Expect(out).To(ContainSubstring(oldID))
		Expect(out).To(ContainSubstring(newID))
		Expect(os.ReadFile(managed)).To(Equal(oldKey))
	})

	It("replaces the key and clears the anti-rollback state when the terminal prompt is answered yes", func() {
		Expect(trust.StoreSeen(stateHome, "native", trust.Seen{TrustSerial: 7, IndexSerial: 7})).To(Succeed())

		out, err := runWithStdin(profilePath, ttyInput{strings.NewReader("y\n")},
			"source", "set-trust-root", "native", "--trust-root", newPub)
		Expect(err).NotTo(HaveOccurred(), "set-trust-root failed: %s", out)
		Expect(out).To(ContainSubstring("Replace the trust root? [y/N]"))
		Expect(out).To(ContainSubstring("replaced trust root of source native"))

		Expect(os.ReadFile(managed)).To(Equal(newKey))
		Expect(reparseSources(profilePath).Sources["native"].TrustRoot).To(Equal(managed))
		seen, err := trust.LoadSeen(stateHome, "native")
		Expect(err).NotTo(HaveOccurred())
		Expect(seen).To(Equal(trust.Seen{}))
	})

	It("keeps URL credentials out of the error when the downloaded key does not match", func() {
		srv := serveTrustRoot(string(newKey))
		withCreds := strings.Replace(srv.URL, "https://", "https://user:secret@", 1) + "/key.pub"

		_, err := runSource(profilePath, "source", "set-trust-root", "native",
			"--trust-root-url", withCreds, "--trust-root-fingerprint", oldID)
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("not the expected"))
		Expect(ce.Msg).NotTo(ContainSubstring("secret"))
	})

	It("refuses a plain http --trust-root-url", func() {
		_, err := runSource(profilePath, "source", "set-trust-root", "native",
			"--trust-root-url", "http://127.0.0.1:1/key.pub", "--trust-root-fingerprint", newID)
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("plain http"))
		Expect(os.ReadFile(managed)).To(Equal(oldKey))
	})

	It("refuses a new trust root that is not a minisign key", func() {
		bad := filepath.Join(tmpDir, "bad.pub")
		Expect(os.WriteFile(bad, []byte("not a key\n"), 0o600)).To(Succeed())

		_, err := runSource(profilePath, "source", "set-trust-root", "native", "--trust-root", bad)
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("is not a valid minisign public key"))
		Expect(os.ReadFile(managed)).To(Equal(oldKey))
	})

	It("names the configured sources when the source is not in the profile", func() {
		_, err := runSource(profilePath, "source", "set-trust-root", "ghost",
			"--trust-root", newPub, "--trust-root-fingerprint", newID)
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(Equal("source ghost is not in the profile (configured: native)"))
		Expect(ce.Hint).To(ContainSubstring("polypkg source list"))
		Expect(filepath.Join(tmpDir, "polypkg", "trust", "ghost.pub")).NotTo(BeAnExistingFile())
	})

	It("requires exactly one of --trust-root and --trust-root-url", func() {
		_, err := runSource(profilePath, "source", "set-trust-root", "native")
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("a new trust root is required"))

		_, err = runSource(profilePath, "source", "set-trust-root", "native",
			"--trust-root", newPub, "--trust-root-url", "https://example.com/key.pub")
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("use only one of"))
	})

	It("emits a null old fingerprint in JSON when the pinned file is gone", func() {
		Expect(os.Remove(managed)).To(Succeed())

		out, err := runSource(profilePath, "--format", "json", "source", "set-trust-root", "native",
			"--trust-root", newPub, "--trust-root-fingerprint", newID)
		Expect(err).NotTo(HaveOccurred(), "set-trust-root failed: %s", out)
		result := parseSingleCLIResult(out)
		Expect(result.Data).To(HaveKeyWithValue("old_fingerprint", BeNil()))
		Expect(result.Data["changed"]).To(BeTrue())
		Expect(os.ReadFile(managed)).To(Equal(newKey))
	})

	It("shows the old key as unreadable in text when the pinned file is gone", func() {
		Expect(os.Remove(managed)).To(Succeed())

		out, err := runSource(profilePath, "source", "set-trust-root", "native",
			"--trust-root", newPub, "--trust-root-fingerprint", newID)
		Expect(err).NotTo(HaveOccurred(), "set-trust-root failed: %s", out)
		Expect(out).To(ContainSubstring("old key id: unreadable"))
	})

	Context("when the profile records a trust root outside the managed dir", func() {
		var external string

		BeforeEach(func() {
			// A second source, so the order has a position to preserve.
			extraPub := filepath.Join(tmpDir, "extra.pub")
			Expect(os.WriteFile(extraPub, []byte(minisignPubFile()), 0o600)).To(Succeed())
			_, err := runSource(profilePath, "source", "add", "extra",
				"--url", "file:///srv/extra", "--trust-root", extraPub)
			Expect(err).NotTo(HaveOccurred())

			// Hand-edit native onto a key outside <config>/trust, as profiles
			// written before anchors were pinned by content still do.
			external = filepath.Join(tmpDir, "external.pub")
			Expect(os.WriteFile(external, oldKey, 0o600)).To(Succeed())
			raw, rerr := os.ReadFile(profilePath)
			Expect(rerr).NotTo(HaveOccurred())
			edited := strings.Replace(string(raw), "trust_root: "+managed, "trust_root: "+external, 1)
			Expect(edited).NotTo(Equal(string(raw)))
			Expect(os.WriteFile(profilePath, []byte(edited), 0o600)).To(Succeed())
		})

		It("pins the managed copy and repoints the entry, keeping type, URL and order", func() {
			out, err := runSource(profilePath, "source", "set-trust-root", "native",
				"--trust-root", newPub, "--trust-root-fingerprint", newID)
			Expect(err).NotTo(HaveOccurred(), "set-trust-root failed: %s", out)

			sources := reparseSources(profilePath)
			Expect(sources.Order).To(Equal([]string{"native", "extra"}))
			Expect(sources.Sources["native"].TrustRoot).To(Equal(managed))
			Expect(sources.Sources["native"].Type).To(Equal("polypkg-native"))
			Expect(sources.Sources["native"].URL).To(Equal("file:///srv/initial"))
			Expect(os.ReadFile(managed)).To(Equal(newKey))
			Expect(os.ReadFile(external)).To(Equal(oldKey), "the operator's own file must be untouched")
		})

		It("restores the managed file when the profile edit fails", func() {
			if os.Geteuid() == 0 {
				Skip("a read-only config directory does not stop root")
			}
			cfgDir := filepath.Dir(profilePath)
			Expect(os.Chmod(cfgDir, 0o500)).To(Succeed())
			DeferCleanup(os.Chmod, cfgDir, os.FileMode(0o700))

			_, err := runSource(profilePath, "source", "set-trust-root", "native",
				"--trust-root", newPub, "--trust-root-fingerprint", newID)
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
			Expect(ce.Msg).To(ContainSubstring(`cannot point source "native" at its new trust root`))
			Expect(os.ReadFile(managed)).To(Equal(oldKey))
			Expect(reparseSources(profilePath).Sources["native"].TrustRoot).To(Equal(external))
		})

		It("removes the managed file it created when the profile edit fails", func() {
			if os.Geteuid() == 0 {
				Skip("a read-only config directory does not stop root")
			}
			Expect(os.Remove(managed)).To(Succeed())
			cfgDir := filepath.Dir(profilePath)
			Expect(os.Chmod(cfgDir, 0o500)).To(Succeed())
			DeferCleanup(os.Chmod, cfgDir, os.FileMode(0o700))

			_, err := runSource(profilePath, "source", "set-trust-root", "native",
				"--trust-root", newPub, "--trust-root-fingerprint", newID)
			Expect(err).To(HaveOccurred())
			Expect(managed).NotTo(BeAnExistingFile())
		})
	})

	It("fails, rather than warns, when the anti-rollback state cannot be cleared", func() {
		if os.Geteuid() == 0 {
			Skip("a read-only state directory does not stop root")
		}
		Expect(trust.StoreSeen(stateHome, "native", trust.Seen{TrustSerial: 7})).To(Succeed())
		seenDir := filepath.Join(stateHome, "trust")
		Expect(os.Chmod(seenDir, 0o500)).To(Succeed())
		DeferCleanup(os.Chmod, seenDir, os.FileMode(0o700))

		_, err := runSource(profilePath, "source", "set-trust-root", "native",
			"--trust-root", newPub, "--trust-root-fingerprint", newID)
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("could not clear the anti-rollback state"))
		Expect(ce.Hint).To(ContainSubstring(filepath.Join(seenDir, "native.json")))
	})

	It("clears the anti-rollback state for an unchanged key with --reset-state and a matching fingerprint", func() {
		Expect(trust.StoreSeen(stateHome, "native", trust.Seen{TrustSerial: 7, IndexSerial: 7})).To(Succeed())
		samePub := filepath.Join(tmpDir, "same.pub")
		Expect(os.WriteFile(samePub, oldKey, 0o600)).To(Succeed())

		out, err := runSource(profilePath, "--format", "json", "source", "set-trust-root", "native",
			"--trust-root", samePub, "--trust-root-fingerprint", oldID, "--reset-state")
		Expect(err).NotTo(HaveOccurred(), "set-trust-root --reset-state failed: %s", out)
		result := parseSingleCLIResult(out)
		Expect(result.Data["changed"]).To(BeFalse())
		Expect(result.Data["state_reset"]).To(BeTrue())

		seen, err := trust.LoadSeen(stateHome, "native")
		Expect(err).NotTo(HaveOccurred())
		Expect(seen).To(Equal(trust.Seen{}))
		Expect(os.ReadFile(managed)).To(Equal(oldKey))
	})

	It("refuses --reset-state without --trust-root-fingerprint and keeps the state", func() {
		Expect(trust.StoreSeen(stateHome, "native", trust.Seen{TrustSerial: 7})).To(Succeed())
		samePub := filepath.Join(tmpDir, "same.pub")
		Expect(os.WriteFile(samePub, oldKey, 0o600)).To(Succeed())

		_, err := runSource(profilePath, "source", "set-trust-root", "native",
			"--trust-root", samePub, "--reset-state")
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("--reset-state requires --trust-root-fingerprint"))

		seen, lerr := trust.LoadSeen(stateHome, "native")
		Expect(lerr).NotTo(HaveOccurred())
		Expect(seen.TrustSerial).To(Equal(uint64(7)))
	})

	It("reports state_reset for a changed key, which always resets", func() {
		out, err := runSource(profilePath, "--format", "json", "source", "set-trust-root", "native",
			"--trust-root", newPub, "--trust-root-fingerprint", newID)
		Expect(err).NotTo(HaveOccurred(), "set-trust-root failed: %s", out)
		result := parseSingleCLIResult(out)
		Expect(result.Data["changed"]).To(BeTrue())
		Expect(result.Data["state_reset"]).To(BeTrue())
	})
})

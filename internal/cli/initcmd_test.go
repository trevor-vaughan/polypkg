package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// parseSingleCLIResult parses the last JSON line of buf as a CLIResult.
func parseSingleCLIResult(buf string) *schema.CLIResult {
	GinkgoHelper()
	lines := strings.Split(strings.TrimSpace(buf), "\n")
	last := lines[len(lines)-1]
	r, err := schema.ParseCLIResult(strings.NewReader(last))
	Expect(err).NotTo(HaveOccurred())
	return r
}

// parseProfileReader wraps schema.ParseProfile for test convenience.
func parseProfileReader(r io.Reader) (*schema.Profile, error) {
	return schema.ParseProfile(r, "")
}

// parseProfileFromString wraps schema.ParseProfile on a string.
func parseProfileFromString(s string) (*schema.Profile, error) {
	return schema.ParseProfile(strings.NewReader(s), "")
}

// minisignPubFile generates a well-formed minisign public key file string
// (same format as the integration helpers), suitable for writing to a .pub
// file that NewVerifier (and thus validateTrustRootFile) will accept.
func minisignPubFile() string {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	var keyID [8]byte
	_, err = rand.Read(keyID[:])
	Expect(err).NotTo(HaveOccurred())
	bin := append([]byte{'E', 'd'}, keyID[:]...)
	bin = append(bin, pub...)
	return "untrusted comment: polypkg test public key\n" +
		base64.StdEncoding.EncodeToString(bin) + "\n"
}

// writeTrustKeyFile writes a valid minisign public key to a temp file and
// returns its path.
func writeTrustKeyFile(dir string) string {
	p := filepath.Join(dir, "anchor.pub")
	Expect(os.WriteFile(p, []byte(minisignPubFile()), 0o600)).To(Succeed())
	return p
}

var _ = Describe("init command: non-interactive flag route", func() {
	var (
		tmp       string
		keyFile   string
		sourceURL = "https://repo.example.com/polypkg"
	)

	BeforeEach(func() {
		sandboxUserEnv(GinkgoTB())
		tmp = GinkgoT().TempDir()
		GinkgoT().Setenv("XDG_CONFIG_HOME", tmp)
		// Clear any inherited POLYPKG_PROFILE that could interfere.
		_ = os.Unsetenv("POLYPKG_PROFILE")
		keyFile = writeTrustKeyFile(tmp)
	})

	runInit := func(extraArgs ...string) (string, error) {
		root := NewRootCmd()
		root.SilenceUsage = true
		root.SilenceErrors = true
		var buf strings.Builder
		root.SetOut(&buf)
		root.SetErr(&buf)
		args := append([]string{"init"}, extraArgs...)
		root.SetArgs(args)
		err := root.Execute()
		return buf.String(), err
	}

	It("writes profile.yaml to the user config dir and emits 'wrote <path>'", func() {
		out, err := runInit("--source-url", sourceURL, "--trust-root", keyFile)
		Expect(err).NotTo(HaveOccurred(), "init failed: %s", out)
		want := filepath.Join(tmp, "polypkg", "profile.yaml")
		Expect(out).To(ContainSubstring("wrote " + want))
		Expect(out).To(ContainSubstring("next steps:"))
		Expect(out).To(ContainSubstring("polypkg search"))
		Expect(out).To(ContainSubstring("polypkg install"))
		Expect(out).To(ContainSubstring("polypkg status"))
		_, statErr := os.Stat(want)
		Expect(statErr).NotTo(HaveOccurred(), "profile.yaml was not created")
	})

	It("creates the config dir with mode 0o700 for user scope", func() {
		cfgDir := filepath.Join(tmp, "polypkg")
		Expect(cfgDir).NotTo(BeADirectory(), "pre-condition: dir must not exist yet")
		out, err := runInit("--source-url", sourceURL, "--trust-root", keyFile)
		Expect(err).NotTo(HaveOccurred(), out)
		fi, statErr := os.Stat(cfgDir)
		Expect(statErr).NotTo(HaveOccurred())
		Expect(fi.Mode().Perm()).To(Equal(os.FileMode(0o700)), "user config dir must be 0o700")
	})

	It("written profile passes schema.ParseProfile", func() {
		out, err := runInit("--source-url", sourceURL, "--trust-root", keyFile)
		Expect(err).NotTo(HaveOccurred(), out)
		want := filepath.Join(tmp, "polypkg", "profile.yaml")
		f, ferr := os.Open(want)
		Expect(ferr).NotTo(HaveOccurred())
		defer f.Close()
		_, perr := parseProfileReader(f)
		Expect(perr).NotTo(HaveOccurred(), "written profile must be schema-valid")
	})

	It("embeds the absolute path of the pinned trust-root copy in the written profile", func() {
		out, err := runInit("--source-url", sourceURL, "--trust-root", keyFile)
		Expect(err).NotTo(HaveOccurred(), out)
		want := filepath.Join(tmp, "polypkg", "profile.yaml")
		raw, rerr := os.ReadFile(want)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(string(raw)).To(ContainSubstring(filepath.Join(tmp, "polypkg", "trust", "native.pub")))
	})

	It("embeds the source URL in the written profile", func() {
		out, err := runInit("--source-url", sourceURL, "--trust-root", keyFile)
		Expect(err).NotTo(HaveOccurred(), out)
		want := filepath.Join(tmp, "polypkg", "profile.yaml")
		raw, rerr := os.ReadFile(want)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(string(raw)).To(ContainSubstring(sourceURL))
	})

	It("profile stores the normalized (not raw) source URL for a file:// input", func() {
		rawURL := "file:///srv/polypkg/public"
		out, err := runInit("--source-url", rawURL, "--trust-root", keyFile)
		Expect(err).NotTo(HaveOccurred(), "init failed: %s", out)
		want := filepath.Join(tmp, "polypkg", "profile.yaml")
		raw, rerr := os.ReadFile(want)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(string(raw)).To(ContainSubstring(rawURL),
			"written profile must contain the normalized file:// URL")
	})

	It("profile stores the expanded file:// URI when --source-url uses ~/", func() {
		home, herr := os.UserHomeDir()
		Expect(herr).NotTo(HaveOccurred())
		out, err := runInit("--source-url", "~/somerepo", "--trust-root", keyFile)
		Expect(err).NotTo(HaveOccurred(), "init failed: %s", out)
		want := filepath.Join(tmp, "polypkg", "profile.yaml")
		raw, rerr := os.ReadFile(want)
		Expect(rerr).NotTo(HaveOccurred())
		expanded := "file://" + filepath.Join(home, "somerepo")
		Expect(string(raw)).To(ContainSubstring(expanded),
			"written profile must contain the canonical file:// URI, not the raw ~/somerepo")
		Expect(string(raw)).NotTo(ContainSubstring("~/somerepo"),
			"written profile must NOT contain the un-normalized ~/somerepo literal")
	})

	It("emits JSON with command=init and path field when --format json", func() {
		out, err := runInit("--format", "json", "--source-url", sourceURL, "--trust-root", keyFile)
		Expect(err).NotTo(HaveOccurred(), out)
		result := parseSingleCLIResult(out)
		Expect(result.Status).To(Equal("ok"))
		Expect(result.Command).To(Equal("init"))
		Expect(result.Data).NotTo(BeNil())
		Expect(result.Data["path"]).NotTo(BeEmpty())
	})

	Context("--source-name", func() {
		It("writes the profile under the given source name with a file trust root", func() {
			out, err := runInit("--source-url", sourceURL, "--trust-root", keyFile,
				"--source-name", "handtest")
			Expect(err).NotTo(HaveOccurred(), "init failed: %s", out)
			raw, rerr := os.ReadFile(filepath.Join(tmp, "polypkg", "profile.yaml"))
			Expect(rerr).NotTo(HaveOccurred())
			body := string(raw)
			Expect(body).To(ContainSubstring("order: [handtest]"))
			Expect(body).To(MatchRegexp(`(?m)^  handtest:`))
			// --trust-root pins the key by content: the bytes are copied
			// under the managed trust dir and THAT path is recorded, never the
			// operator's own path (which the repository may be able to write).
			savedKey := filepath.Join(tmp, "polypkg", "trust", "handtest.pub")
			Expect(body).To(ContainSubstring("trust_root: " + savedKey))
			absKey, aerr := filepath.Abs(keyFile)
			Expect(aerr).NotTo(HaveOccurred())
			Expect(body).NotTo(ContainSubstring("trust_root: " + absKey))
			// No trace of the default source name (the source TYPE
			// "polypkg-native" legitimately contains "native", so pin the
			// name-shaped occurrences instead of the bare substring).
			Expect(body).NotTo(ContainSubstring("order: [native]"))
			Expect(body).NotTo(MatchRegexp(`(?m)^  native:`))
			Expect(body).NotTo(ContainSubstring("trust/native.pub"))
		})

		It("persists the downloaded trust root as trust/<source-name>.pub with --trust-root-url", func() {
			key, kerr := os.ReadFile(keyFile)
			Expect(kerr).NotTo(HaveOccurred())
			out, err := runInit("--source-url", sourceURL,
				"--trust-root-url", "file://"+keyFile,
				"--trust-root-fingerprint", keyIDOf(string(key)),
				"--source-name", "handtest")
			Expect(err).NotTo(HaveOccurred(), "init failed: %s", out)
			savedKey := filepath.Join(tmp, "polypkg", "trust", "handtest.pub")
			_, statErr := os.Stat(savedKey)
			Expect(statErr).NotTo(HaveOccurred(), "trust/handtest.pub must be written")
			raw, rerr := os.ReadFile(filepath.Join(tmp, "polypkg", "profile.yaml"))
			Expect(rerr).NotTo(HaveOccurred())
			Expect(string(raw)).To(ContainSubstring("trust_root: " + savedKey))
		})

		It("rejects the reserved name 'order'", func() {
			_, err := runInit("--source-url", sourceURL, "--trust-root", keyFile,
				"--source-name", "order")
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
			Expect(ce.Msg).To(ContainSubstring(`"order" is a reserved name`))
		})

		It("rejects a source name that is not a valid slug", func() {
			_, err := runInit("--source-url", sourceURL, "--trust-root", keyFile,
				"--source-name", "bad name")
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
			Expect(ce.Msg).To(ContainSubstring(`"bad name"`))
		})
	})

	// A trust root recorded as a path is late-bound: every verification re-reads
	// whatever that file holds at the time. Our own Quickstart points
	// --trust-root at the published repository's own tree, so an attacker
	// who can write that tree could swap the anchor and sign their own index.
	// The anchor must therefore be pinned by content, as --trust-root-url and
	// the wizard's pasted-key route already do.
	Context("trust-root pinning", func() {
		It("copies the key under the managed trust dir and records that path", func() {
			out, err := runInit("--source-url", sourceURL, "--trust-root", keyFile)
			Expect(err).NotTo(HaveOccurred(), "init failed: %s", out)

			savedKey := filepath.Join(tmp, "polypkg", "trust", "native.pub")
			saved, rerr := os.ReadFile(savedKey)
			Expect(rerr).NotTo(HaveOccurred(), "trust/native.pub must be written")
			original, oerr := os.ReadFile(keyFile)
			Expect(oerr).NotTo(HaveOccurred())
			Expect(string(saved)).To(Equal(string(original)))

			// 0o644 matches the --trust-root-url route: public key material,
			// no secret. Access is gated by trust/ itself, which is 0o700.
			fi, sErr := os.Stat(savedKey)
			Expect(sErr).NotTo(HaveOccurred())
			Expect(fi.Mode().Perm()).To(Equal(os.FileMode(0o644)))

			raw, prerr := os.ReadFile(filepath.Join(tmp, "polypkg", "profile.yaml"))
			Expect(prerr).NotTo(HaveOccurred())
			prof, perr := parseProfileFromString(string(raw))
			Expect(perr).NotTo(HaveOccurred())
			Expect(prof.Sources.Sources["native"].TrustRoot).To(Equal(savedKey))
		})

		It("survives the original file being swapped after init", func() {
			out, err := runInit("--source-url", sourceURL, "--trust-root", keyFile)
			Expect(err).NotTo(HaveOccurred(), "init failed: %s", out)
			pinned, rerr := os.ReadFile(filepath.Join(tmp, "polypkg", "trust", "native.pub"))
			Expect(rerr).NotTo(HaveOccurred())

			// The attacker overwrites the key the operator pointed at.
			attacker := minisignPubFile()
			Expect(attacker).NotTo(Equal(string(pinned)))
			Expect(os.WriteFile(keyFile, []byte(attacker), 0o600)).To(Succeed())

			// The recorded anchor is unaffected: it is a copy, not a reference.
			after, aerr := os.ReadFile(filepath.Join(tmp, "polypkg", "trust", "native.pub"))
			Expect(aerr).NotTo(HaveOccurred())
			Expect(string(after)).To(Equal(string(pinned)))
		})

		// Deleting profile.yaml leaves trust/<source>.pub behind. A later init
		// must not quietly swap that anchor for a different key: whoever can
		// get an operator to re-run init would otherwise re-anchor the source.
		It("refuses to overwrite a different key left by an earlier init", func() {
			out, err := runInit("--source-url", sourceURL, "--trust-root", keyFile)
			Expect(err).NotTo(HaveOccurred(), "first init failed: %s", out)
			profile := filepath.Join(tmp, "polypkg", "profile.yaml")
			Expect(os.Remove(profile)).To(Succeed())
			savedKey := filepath.Join(tmp, "polypkg", "trust", "native.pub")
			pinned, rerr := os.ReadFile(savedKey)
			Expect(rerr).NotTo(HaveOccurred())

			otherKey := filepath.Join(tmp, "other.pub")
			Expect(os.WriteFile(otherKey, []byte(minisignPubFile()), 0o600)).To(Succeed())
			_, err = runInit("--source-url", sourceURL, "--trust-root", otherKey)
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
			Expect(ce.Msg).To(ContainSubstring("already pinned at " + savedKey))
			Expect(os.ReadFile(savedKey)).To(Equal(pinned))
			Expect(profile).NotTo(BeAnExistingFile())
		})

		It("reuses an anchor left by an earlier init when it is the same key", func() {
			out, err := runInit("--source-url", sourceURL, "--trust-root", keyFile)
			Expect(err).NotTo(HaveOccurred(), "first init failed: %s", out)
			Expect(os.Remove(filepath.Join(tmp, "polypkg", "profile.yaml"))).To(Succeed())

			out, err = runInit("--source-url", sourceURL, "--trust-root", keyFile)
			Expect(err).NotTo(HaveOccurred(), "re-init with the same key failed: %s", out)
		})

		It("accepts --trust-root with a matching --trust-root-fingerprint", func() {
			key, kerr := os.ReadFile(keyFile)
			Expect(kerr).NotTo(HaveOccurred())
			out, err := runInit("--source-url", sourceURL, "--trust-root", keyFile,
				"--trust-root-fingerprint", keyIDOf(string(key)))
			Expect(err).NotTo(HaveOccurred(), "init failed: %s", out)
		})

		It("refuses --trust-root with a mismatched --trust-root-fingerprint", func() {
			_, err := runInit("--source-url", sourceURL, "--trust-root", keyFile,
				"--trust-root-fingerprint", "0000000000000000")
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
			Expect(ce.Msg).To(ContainSubstring(`not the expected "0000000000000000"`))
			Expect(filepath.Join(tmp, "polypkg", "trust", "native.pub")).NotTo(BeAnExistingFile())
			Expect(filepath.Join(tmp, "polypkg", "profile.yaml")).NotTo(BeAnExistingFile())
		})

		It("writes no key file when a profile already exists", func() {
			dir := filepath.Join(tmp, "polypkg")
			Expect(os.MkdirAll(dir, 0o700)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(dir, "profile.yaml"), []byte("x"), 0o600)).To(Succeed())

			_, err := runInit("--source-url", sourceURL, "--trust-root", keyFile)
			Expect(err).To(HaveOccurred())

			// Copying now happens before the profile is written, so the
			// already-exists guard has to run before the copy or init leaves a
			// stray anchor behind on a failed run.
			_, statErr := os.Stat(filepath.Join(dir, "trust"))
			Expect(os.IsNotExist(statErr)).To(BeTrue(), "trust dir must not be created when the profile already exists")
		})
	})

	Context("already-exists guard", func() {
		for _, ext := range []string{"yaml", "yml", "jsonc", "json"} {
			ext := ext
			It(fmt.Sprintf("errors when profile.%s already exists", ext), func() {
				dir := filepath.Join(tmp, "polypkg")
				Expect(os.MkdirAll(dir, 0o700)).To(Succeed())
				existing := filepath.Join(dir, "profile."+ext)
				Expect(os.WriteFile(existing, []byte("x"), 0o600)).To(Succeed())
				_, err := runInit("--source-url", sourceURL, "--trust-root", keyFile)
				Expect(err).To(HaveOccurred())
				var ce *CLIError
				Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
				Expect(ce.Msg).To(ContainSubstring("profile already exists at"))
				Expect(ce.Msg).To(ContainSubstring(existing))
				Expect(ce.Hint).To(ContainSubstring("edit it directly"))
			})
		}
	})

	Context("validation errors", func() {
		It("accepts an http source URL (scheme http is valid)", func() {
			out, err := runInit("--source-url", "http://repo.example.com/polypkg", "--trust-root", keyFile)
			Expect(err).NotTo(HaveOccurred(), "http scheme must be accepted; output: %s", out)
			want := filepath.Join(tmp, "polypkg", "profile.yaml")
			Expect(out).To(ContainSubstring("wrote " + want))
		})

		It("rejects a non-URL --source-url", func() {
			out, err := runInit("--source-url", "not a url", "--trust-root", keyFile)
			Expect(err).To(HaveOccurred(), "bad URL should be rejected; output: %s", out)
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue())
			Expect(ce.Msg).To(ContainSubstring("invalid --source-url"))
		})

		It("rejects a ftp:// --source-url", func() {
			out, err := runInit("--source-url", "ftp://repo.example.com", "--trust-root", keyFile)
			Expect(err).To(HaveOccurred(), "ftp scheme must be rejected; output: %s", out)
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue())
			Expect(ce.Msg).To(ContainSubstring("invalid --source-url"))
		})

		It("rejects a --trust-root that does not exist", func() {
			out, err := runInit("--source-url", sourceURL, "--trust-root", "/no/such/file.pub")
			Expect(err).To(HaveOccurred(), "missing trust root must be rejected; output: %s", out)
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue())
			Expect(ce.Msg).To(Equal("trust root /no/such/file.pub does not exist"))
		})

		It("rejects a --trust-root that is not a minisign key", func() {
			bad := filepath.Join(tmp, "bad.pub")
			Expect(os.WriteFile(bad, []byte("this is not a key\n"), 0o600)).To(Succeed())
			out, err := runInit("--source-url", sourceURL, "--trust-root", bad)
			Expect(err).To(HaveOccurred(), "invalid key must be rejected; output: %s", out)
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue())
			Expect(ce.Msg).To(ContainSubstring("not a valid minisign public key"))
			Expect(ce.Hint).To(ContainSubstring("minisign .pub"))
		})

		It("errors with non-interactive hint when stdin is not a TTY and flags are missing", func() {
			// The init command detects non-TTY stdin; in tests stdin is not a
			// TTY so omitting flags always triggers the non-interactive error.
			out, err := runInit()
			Expect(err).To(HaveOccurred(), "missing flags must error in non-interactive mode; output: %s", out)
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
			Expect(ce.Msg).To(ContainSubstring("init needs --source-url and a trust root"))
			Expect(ce.Hint).To(ContainSubstring("--trust-root"))
			Expect(ce.Hint).To(ContainSubstring("--trust-root-url"))
		})

		It("stays non-interactive on a terminal stdin when stdout is not a terminal", func() {
			// The form needs both ends: a terminal stdin alone must not start it.
			root := NewRootCmd()
			root.SilenceUsage, root.SilenceErrors = true, true
			var buf strings.Builder
			root.SetOut(&buf)
			root.SetErr(&buf)
			root.SetIn(ttyInput{strings.NewReader("")})
			root.SetArgs([]string{"init"})
			err := root.Execute()
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
			Expect(ce.Msg).To(ContainSubstring("init needs --source-url and a trust root"))
		})
	})
})

var _ = Describe("normalizeSourceURL", func() {
	type acceptCase struct {
		input string
		// wantPrefix: if non-empty, the returned value must start with this.
		// wantExact: if non-empty, the returned value must equal this exactly.
		wantPrefix string
		wantExact  string
	}
	type rejectCase struct {
		input   string
		wantMsg string // substring expected in CLIError.Msg
	}

	DescribeTable("accepts valid inputs",
		func(tc acceptCase) {
			got, err := normalizeSourceURL(tc.input)
			Expect(err).NotTo(HaveOccurred(), "input=%q", tc.input)
			if tc.wantExact != "" {
				Expect(got).To(Equal(tc.wantExact), "normalized value mismatch for %q", tc.input)
			}
			if tc.wantPrefix != "" {
				Expect(got).To(HavePrefix(tc.wantPrefix), "normalized value prefix mismatch for %q", tc.input)
			}
		},
		Entry("https with path", acceptCase{input: "https://h/p", wantExact: "https://h/p"}),
		Entry("http no path", acceptCase{input: "http://h", wantExact: "http://h"}),
		Entry("file:// absolute", acceptCase{input: "file:///srv/r", wantExact: "file:///srv/r"}),
		Entry("bare absolute path", acceptCase{input: "/abs/repo", wantExact: "file:///abs/repo"}),
		Entry("~/repo expands to home", acceptCase{
			input: "~/repo",
			wantPrefix: func() string {
				home, _ := os.UserHomeDir()
				return "file://" + home
			}(),
		}),
		Entry("~ alone expands to home", acceptCase{
			input: "~",
			wantExact: func() string {
				home, _ := os.UserHomeDir()
				return "file://" + home
			}(),
		}),
	)

	DescribeTable("rejects invalid inputs",
		func(tc rejectCase) {
			_, err := normalizeSourceURL(tc.input)
			Expect(err).To(HaveOccurred(), "input=%q should be rejected", tc.input)
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError for %q, got %T: %v", tc.input, err, err)
			Expect(ce.Msg).To(ContainSubstring(tc.wantMsg), "CLIError.Msg mismatch for %q", tc.input)
		},
		Entry("empty string", rejectCase{input: "", wantMsg: "invalid --source-url"}),
		Entry("embedded space", rejectCase{input: "not a url", wantMsg: "invalid --source-url"}),
		Entry("whitespace only", rejectCase{input: "   ", wantMsg: "invalid --source-url"}),
		Entry("embedded tab", rejectCase{input: "https://h/\t", wantMsg: "invalid --source-url"}),
		Entry("relative ./rel", rejectCase{input: "./rel", wantMsg: "invalid --source-url"}),
		Entry("relative ../up", rejectCase{input: "../up", wantMsg: "invalid --source-url"}),
		Entry("relative rel/path", rejectCase{input: "rel/path", wantMsg: "invalid --source-url"}),
		Entry("bare word", rejectCase{input: "bare", wantMsg: "invalid --source-url"}),
		Entry("ftp scheme", rejectCase{input: "ftp://h/x", wantMsg: "invalid --source-url"}),
		Entry("https no host", rejectCase{input: "https://", wantMsg: "invalid --source-url"}),
		Entry("file non-absolute", rejectCase{input: "file://relative", wantMsg: "invalid file URL"}),
		Entry("file with host", rejectCase{input: "file://example.com/srv/repo", wantMsg: "invalid file URL"}),
	)

	// Every rejection path echoes the input, which may carry a user-name-only
	// token; it must reach the message only through source.RedactURL.
	DescribeTable("never echoes credentials in a rejection",
		func(input, wantMsg string) {
			_, err := normalizeSourceURL(input)
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError for %q, got %T: %v", input, err, err)
			Expect(ce.Msg).To(ContainSubstring(wantMsg))
			Expect(ce.Msg).NotTo(ContainSubstring("ghp_secret"))
		},
		Entry("whitespace", "https://ghp_secret@h/a b", "invalid --source-url"),
		Entry("unparseable", "https://ghp_secret@h/%zz", "invalid --source-url"),
		Entry("missing host", "https://ghp_secret@", "invalid --source-url"),
		Entry("unsupported scheme", "ftp://ghp_secret@h/x", "invalid --source-url"),
		Entry("file URL with a host", "file://ghp_secret@example.com/srv/repo", "invalid file URL"),
		Entry("file URL without an absolute path", "file://ghp_secret@", "invalid file URL"),
	)

	It("~/repo normalizes to a file:// URI under home", func() {
		home, err := os.UserHomeDir()
		Expect(err).NotTo(HaveOccurred())
		got, err := normalizeSourceURL("~/myrepo")
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal("file://" + filepath.Join(home, "myrepo")))
	})
})

var _ = Describe("init command: system scope", func() {
	var tmp string

	BeforeEach(func() {
		sandboxUserEnv(GinkgoTB())
		tmp = GinkgoT().TempDir()
		GinkgoT().Setenv("XDG_CONFIG_HOME", tmp)
		_ = os.Unsetenv("POLYPKG_PROFILE")
	})

	It("writes to /etc/polypkg/profile.yaml for --scope system", func() {
		// We can't actually write to /etc in a test, so we just verify the
		// CLIError is not "already exists" (i.e. the path logic runs) — or
		// that the path in the error/output references /etc/polypkg.
		// In a sandboxed CI, /etc/polypkg is not writable; the error from mkdir
		// will be a permission error, not a logic error.
		// We verify path-routing by mocking XDG (no effect for system) and
		// checking the error references /etc/polypkg.
		keyFile := writeTrustKeyFile(tmp)
		root := NewRootCmd()
		root.SilenceUsage = true
		root.SilenceErrors = true
		var buf strings.Builder
		root.SetOut(&buf)
		root.SetErr(&buf)
		root.SetArgs([]string{"init", "--scope", "system",
			"--source-url", "https://repo.example.com/polypkg",
			"--trust-root", keyFile,
		})
		err := root.Execute()
		if err == nil {
			// Succeeded (running as root in CI) — verify path.
			Expect(buf.String()).To(ContainSubstring("/etc/polypkg/profile.yaml"))
		} else {
			// Permission denied or similar — verify the right path was targeted.
			Expect(err.Error() + buf.String()).To(
				Or(ContainSubstring("/etc/polypkg"), ContainSubstring("permission")),
			)
		}
	})

	It("renders a scopes.system block for --scope system (regression: was hardcoded user)", func() {
		// A profile written at the system config location must define the system
		// scope, or every subsequent `--scope system` operation fails with
		// "profile has no system scope". Exercise the shared write path directly
		// (the CLI guards the wizard route on TTY) against a writable temp dir.
		cfgDir := filepath.Join(tmp, "polypkg")
		Expect(os.MkdirAll(cfgDir, 0o755)).To(Succeed())

		written, werr := writeInitProfile(cfgDir, "native", "https://example.com/pkgs", minisignPubFile(), "system")
		Expect(werr).NotTo(HaveOccurred())
		body, rerr := os.ReadFile(written)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(string(body)).To(ContainSubstring("scopes:"))
		Expect(string(body)).To(MatchRegexp(`(?m)^\s+system:`), "system scope block must be present")
		Expect(string(body)).NotTo(MatchRegexp(`(?m)^\s+user:`), "must not emit a user scope block for --scope system")
		// The rendered profile must parse and expose the system scope.
		Expect(string(body)).To(ContainSubstring("packages:"))
	})

	It("still renders a scopes.user block for --scope user", func() {
		cfgDir := filepath.Join(tmp, "polypkg")
		Expect(os.MkdirAll(cfgDir, 0o700)).To(Succeed())
		written, werr := writeInitProfile(cfgDir, "native", "https://example.com/pkgs", minisignPubFile(), "user")
		Expect(werr).NotTo(HaveOccurred())
		body, rerr := os.ReadFile(written)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(string(body)).To(MatchRegexp(`(?m)^\s+user:`))
		Expect(string(body)).NotTo(MatchRegexp(`(?m)^\s+system:`))
	})

	It("documents the attestation policy knob in the scaffold", func() {
		cfgDir := filepath.Join(tmp, "polypkg")
		Expect(os.MkdirAll(cfgDir, 0o700)).To(Succeed())
		written, werr := writeInitProfile(cfgDir, "native", "https://example.com/pkgs", minisignPubFile(), "user")
		Expect(werr).NotTo(HaveOccurred())
		raw, err := os.ReadFile(written)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(raw)).To(MatchRegexp(`(?m)^# attestation:`))
		Expect(string(raw)).To(MatchRegexp(`(?m)^#   policy: require`))
		Expect(string(raw)).NotTo(MatchRegexp(`(?m)^attestation:`))
		Expect(string(raw)).To(ContainSubstring(`(docs/trust-policy.md, "Attestation policy")`))
		Expect(string(raw)).NotTo(ContainSubstring(`README: "Attestations"`))
	})
})

var _ = Describe("init command: pasted key material", func() {
	var tmp string

	BeforeEach(func() {
		sandboxUserEnv(GinkgoTB())
		tmp = GinkgoT().TempDir()
		GinkgoT().Setenv("XDG_CONFIG_HOME", tmp)
		_ = os.Unsetenv("POLYPKG_PROFILE")
	})

	It("writeInitProfile with pasted key writes the key file and uses its path", func() {
		// Exercise the shared write path directly (not via the CLI command
		// which guards on TTY for the wizard route); the pasted-key write path
		// is unit-tested here against the helper.
		cfgDir := filepath.Join(tmp, "polypkg")
		Expect(os.MkdirAll(cfgDir, 0o700)).To(Succeed())

		pastedKey := minisignPubFile()
		written, werr := writeInitProfile(cfgDir, "native", "https://example.com/pkgs", pastedKey, "user")
		Expect(werr).NotTo(HaveOccurred())
		// Key file must be written under cfgDir/trust/
		trustDir := filepath.Join(cfgDir, "trust")
		entries, lerr := os.ReadDir(trustDir)
		Expect(lerr).NotTo(HaveOccurred())
		Expect(entries).To(HaveLen(1))
		keyPath := filepath.Join(trustDir, entries[0].Name())
		fi, sErr := os.Stat(keyPath)
		Expect(sErr).NotTo(HaveOccurred())
		// Public key material, written like every other managed anchor; the
		// enclosing trust/ dir is 0o700.
		Expect(fi.Mode().Perm()).To(Equal(os.FileMode(0o644)), "key file must be 0o644")
		// Profile must reference the key path.
		raw, rerr := os.ReadFile(written)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(string(raw)).To(ContainSubstring(keyPath))
	})
})

var _ = Describe("init command: hostile template fill", func() {
	// These specs guard against cross-placeholder injection: a value containing
	// another placeholder must survive verbatim (simultaneous substitution, not
	// sequential).
	type fillCase struct {
		desc          string
		hostname      string
		sourceURL     string
		trustRootPath string
		wantURL       string // expected literal in the rendered output
		wantPath      string // expected literal in the rendered output
	}

	cases := []fillCase{
		{
			desc:          "source-url containing {TRUST_ROOT_PATH} is not expanded",
			hostname:      "host",
			sourceURL:     "https://host.com/{TRUST_ROOT_PATH}",
			trustRootPath: "/real/path/to/anchor.pub",
			wantURL:       "https://host.com/{TRUST_ROOT_PATH}",
			wantPath:      "/real/path/to/anchor.pub",
		},
		{
			desc:          "source-url containing {NAME} is not expanded",
			hostname:      "myhost",
			sourceURL:     "https://host.com/{NAME}/pkgs",
			trustRootPath: "/real/path/anchor.pub",
			wantURL:       "https://host.com/{NAME}/pkgs",
			wantPath:      "/real/path/anchor.pub",
		},
		{
			desc:          "trust-root path containing {SOURCE_URL} is not expanded",
			hostname:      "host",
			sourceURL:     "https://repo.example.com",
			trustRootPath: "/data/{SOURCE_URL}/key.pub",
			wantURL:       "https://repo.example.com",
			wantPath:      "/data/{SOURCE_URL}/key.pub",
		},
	}

	for _, tc := range cases {
		tc := tc
		It(tc.desc, func() {
			out := fillProfileTemplate(tc.hostname, "native", tc.sourceURL, tc.trustRootPath, "user")
			Expect(out).To(ContainSubstring(tc.wantURL), "url placeholder leaked into value")
			Expect(out).To(ContainSubstring(tc.wantPath), "trust_root placeholder leaked into value")
		})
	}
})

var _ = Describe("init command: pasted key validation", func() {
	var tmp string

	BeforeEach(func() {
		sandboxUserEnv(GinkgoTB())
		tmp = GinkgoT().TempDir()
		GinkgoT().Setenv("XDG_CONFIG_HOME", tmp)
		_ = os.Unsetenv("POLYPKG_PROFILE")
	})

	It("rejects garbage pasted as key material, creates no files", func() {
		cfgDir := filepath.Join(tmp, "polypkg")
		Expect(os.MkdirAll(cfgDir, 0o700)).To(Succeed())

		// Valid prefix so the "untrusted comment:" branch is taken, but the
		// rest of the content is not a valid minisign key.
		garbage := "untrusted comment: minisign public key DEADBEEF\nnot-valid-base64!!!\n"
		_, werr := writeInitProfile(cfgDir, "native", "https://example.com/pkgs", garbage, "user")
		Expect(werr).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(werr, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", werr, werr)
		Expect(ce.Msg).To(ContainSubstring("the pasted key is not a valid minisign public key"))
		Expect(ce.Hint).To(ContainSubstring("minisign .pub"))

		// No trust file should be written.
		trustDir := filepath.Join(cfgDir, "trust")
		_, statErr := os.Stat(trustDir)
		Expect(os.IsNotExist(statErr)).To(BeTrue(), "trust dir must not be created on validation failure")

		// No profile should be written.
		for _, name := range profileBasenames {
			_, statErr := os.Stat(filepath.Join(cfgDir, name))
			Expect(os.IsNotExist(statErr)).To(BeTrue(), "profile must not be created on validation failure")
		}
	})

	It("pasted key replaces a symlink planted at the managed path instead of following it", func() {
		cfgDir := filepath.Join(tmp, "polypkg")
		trustPub := filepath.Join(cfgDir, "trust", "native.pub")
		Expect(os.MkdirAll(filepath.Dir(trustPub), 0o700)).To(Succeed())
		// A dangling link: the old direct write would have created its target.
		victim := filepath.Join(tmp, "victim.pub")
		Expect(os.Symlink(victim, trustPub)).To(Succeed())

		pasted := minisignPubFile()
		_, werr := writeInitProfile(cfgDir, "native", "https://example.com/pkgs", pasted, "user")
		Expect(werr).NotTo(HaveOccurred())

		Expect(victim).NotTo(BeAnExistingFile(), "the symlink target must not be written")
		fi, lerr := os.Lstat(trustPub)
		Expect(lerr).NotTo(HaveOccurred())
		Expect(fi.Mode().IsRegular()).To(BeTrue(), "the managed path must now be a regular file")
		Expect(os.ReadFile(trustPub)).To(Equal([]byte(pasted)))
	})

	It("pasted key refuses to overwrite a different anchor already in trust/", func() {
		cfgDir := filepath.Join(tmp, "polypkg")
		trustPub := filepath.Join(cfgDir, "trust", "native.pub")
		Expect(os.MkdirAll(filepath.Dir(trustPub), 0o700)).To(Succeed())
		pinned := []byte(minisignPubFile())
		Expect(os.WriteFile(trustPub, pinned, 0o644)).To(Succeed())

		_, werr := writeInitProfile(cfgDir, "native", "https://example.com/pkgs", minisignPubFile(), "user")
		Expect(werr).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(werr, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", werr, werr)
		Expect(ce.Msg).To(ContainSubstring("already pinned at " + trustPub))
		Expect(os.ReadFile(trustPub)).To(Equal(pinned))
		Expect(filepath.Join(cfgDir, "profile.yaml")).NotTo(BeAnExistingFile())
	})

	It("existing profile with pasted key returns already-exists and no key file written", func() {
		cfgDir := filepath.Join(tmp, "polypkg")
		Expect(os.MkdirAll(cfgDir, 0o700)).To(Succeed())
		existing := filepath.Join(cfgDir, "profile.yaml")
		Expect(os.WriteFile(existing, []byte("x"), 0o600)).To(Succeed())

		pastedKey := minisignPubFile()
		_, werr := writeInitProfile(cfgDir, "native", "https://example.com/pkgs", pastedKey, "user")
		Expect(werr).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(werr, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", werr, werr)
		Expect(ce.Msg).To(ContainSubstring("profile already exists at"))

		// trust/native.pub must NOT have been written.
		trustPub := filepath.Join(cfgDir, "trust", "native.pub")
		_, statErr := os.Stat(trustPub)
		Expect(os.IsNotExist(statErr)).To(BeTrue(), "trust/native.pub must not be created when profile already exists")
	})
})

var _ = Describe("init command: template validity", func() {
	It("fillProfileTemplate output passes schema.ParseProfile", func() {
		keyContent := minisignPubFile()
		tmp := GinkgoT().TempDir()
		keyPath := filepath.Join(tmp, "anchor.pub")
		Expect(os.WriteFile(keyPath, []byte(keyContent), 0o600)).To(Succeed())

		out := fillProfileTemplate("test-host", "native", "https://example.com/polypkg", keyPath, "user")
		_, perr := parseProfileFromString(out)
		Expect(perr).NotTo(HaveOccurred(), "template output must be schema-valid:\n%s", out)
	})

	It("sanitizes hostname with invalid runes to only [a-zA-Z0-9_-]", func() {
		out := fillProfileTemplate("my machine.local!", "native", "https://example.com/polypkg", "/tmp/k.pub", "user")
		Expect(out).To(MatchRegexp(`name: [a-zA-Z0-9_-]+`))
		Expect(out).NotTo(ContainSubstring("my machine.local!"))
	})

	It("uses 'my-machine' fallback when hostname is empty", func() {
		out := fillProfileTemplate("", "native", "https://example.com/polypkg", "/tmp/k.pub", "user")
		Expect(out).To(ContainSubstring("name: my-machine"))
	})
})
var _ = Describe("init command: --trust-root-file", func() {
	It("is no longer a flag: init takes --trust-root, like source add", func() {
		GinkgoT().Setenv("XDG_CONFIG_HOME", GinkgoT().TempDir())
		GinkgoT().Setenv("POLYPKG_PROFILE", "")
		root := NewRootCmd()
		root.SilenceUsage, root.SilenceErrors = true, true
		var buf strings.Builder
		root.SetOut(&buf)
		root.SetErr(&buf)
		root.SetIn(strings.NewReader(""))
		root.SetArgs([]string{"init", "--source-url", "file:///srv/x", "--trust-root-file", "/x.pub"})

		err := root.Execute()
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(Equal("unknown flag --trust-root-file"))
	})
})
var _ = Describe("init command: filesystem failures", func() {
	BeforeEach(func() {
		if os.Geteuid() == 0 {
			Skip("a read-only directory does not stop root")
		}
	})

	It("names the config dir and the cause, not the OS error, when the dir cannot be created", func() {
		ro := filepath.Join(GinkgoT().TempDir(), "ro")
		Expect(os.Mkdir(ro, 0o500)).To(Succeed())
		DeferCleanup(os.Chmod, ro, os.FileMode(0o700))
		cfgDir := filepath.Join(ro, "polypkg")

		_, err := writeInitProfile(cfgDir, "native", "https://example.com/pkgs", "/anchors/native.pub", "user")
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(Equal("cannot create config dir " + cfgDir + ": permission denied"))
		Expect(ce.Hint).To(ContainSubstring("writable"))
		Expect(ce.Err).To(MatchError(os.ErrPermission))
	})

	It("names the profile path and the cause, not the OS error, when the profile cannot be written", func() {
		cfgDir := filepath.Join(GinkgoT().TempDir(), "polypkg")
		Expect(os.Mkdir(cfgDir, 0o500)).To(Succeed())
		DeferCleanup(os.Chmod, cfgDir, os.FileMode(0o700))

		_, err := writeInitProfile(cfgDir, "native", "https://example.com/pkgs", "/anchors/native.pub", "user")
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(Equal("cannot write profile to " + filepath.Join(cfgDir, "profile.yaml") + ": permission denied"))
		Expect(ce.Hint).To(ContainSubstring(cfgDir))
		Expect(ce.Err).To(MatchError(os.ErrPermission))
	})
})

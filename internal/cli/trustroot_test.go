package cli

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	"github.com/jedisct1/go-minisign"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/cobra"
)

// newTestCmd returns a *cobra.Command wired with a bytes.Buffer as stdin/stdout
// for testing helpers that take cmd *cobra.Command. The command's stdin is a
// strings.Reader (not a char device), so isInteractive returns false.
func newTestCmd(stdinContent string) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader(stdinContent))
	var buf strings.Builder
	cmd.SetOut(&buf)
	return cmd
}

var _ = Describe("fetchTrustRootBytes", func() {
	var pubContent string

	BeforeEach(func() {
		pubContent = minisignPubFile()
	})

	Context("http(s) URL", func() {
		It("downloads and returns bytes on 200 OK", func() {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(pubContent))
			}))
			defer srv.Close()

			data, err := fetchTrustRootBytes(srv.URL + "/key.pub")
			Expect(err).NotTo(HaveOccurred())
			Expect(string(data)).To(Equal(pubContent))
		})

		It("returns CLIError on non-200 response", func() {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			}))
			defer srv.Close()

			_, err := fetchTrustRootBytes(srv.URL + "/missing.pub")
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue())
			Expect(ce.Msg).To(ContainSubstring("trust root download failed"))
			Expect(ce.Msg).To(ContainSubstring("404"))
		})

		It("returns CLIError on connection failure", func() {
			_, err := fetchTrustRootBytes("http://127.0.0.1:1") // nothing listening
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue())
			Expect(ce.Msg).To(ContainSubstring("cannot download trust root"))
		})
	})

	Context("file:// URL", func() {
		It("reads a local file", func() {
			tmp := GinkgoT().TempDir()
			p := filepath.Join(tmp, "key.pub")
			Expect(os.WriteFile(p, []byte(pubContent), 0o644)).To(Succeed())

			data, err := fetchTrustRootBytes("file://" + p)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(data)).To(Equal(pubContent))
		})

		It("returns CLIError when the file does not exist", func() {
			_, err := fetchTrustRootBytes("file:///no/such/file.pub")
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue())
			Expect(ce.Msg).To(ContainSubstring("cannot read trust root"))
		})
	})

	Context("absolute path", func() {
		It("reads a local file via absolute path", func() {
			tmp := GinkgoT().TempDir()
			p := filepath.Join(tmp, "key.pub")
			Expect(os.WriteFile(p, []byte(pubContent), 0o644)).To(Succeed())

			data, err := fetchTrustRootBytes(p)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(data)).To(Equal(pubContent))
		})

		It("returns CLIError when absolute path does not exist", func() {
			_, err := fetchTrustRootBytes("/no/such/path/key.pub")
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue())
			Expect(ce.Msg).To(ContainSubstring("cannot read trust root"))
		})
	})

	Context("invalid scheme", func() {
		It("returns CLIError for unsupported scheme", func() {
			_, err := fetchTrustRootBytes("ftp://example.com/key.pub")
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue())
			Expect(ce.Msg).To(ContainSubstring("invalid --trust-root-url"))
		})
	})

	Context("size cap", func() {
		It("returns CLIError when response body exceeds maxTrustRootBytes", func() {
			// Serve exactly maxTrustRootBytes+1 bytes — one byte over the cap.
			oversized := make([]byte, maxTrustRootBytes+1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(oversized)
			}))
			defer srv.Close()

			_, err := fetchTrustRootBytes(srv.URL + "/key.pub")
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue())
			Expect(ce.Msg).To(ContainSubstring("large"))
		})
	})
})

var _ = Describe("confirmTrustRoot", func() {
	const origin = "https://example.com/key.pub"
	const fingerprint = "aabbccdd11223344"

	It("returns true for 'y'", func() {
		ok, err := confirmTrustRoot(strings.NewReader("y\n"), &strings.Builder{}, origin, fingerprint)
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())
	})

	It("returns true for 'Y'", func() {
		ok, err := confirmTrustRoot(strings.NewReader("Y\n"), &strings.Builder{}, origin, fingerprint)
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())
	})

	It("returns false for 'n'", func() {
		ok, err := confirmTrustRoot(strings.NewReader("n\n"), &strings.Builder{}, origin, fingerprint)
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeFalse())
	})

	It("returns false for empty input (EOF)", func() {
		ok, err := confirmTrustRoot(strings.NewReader(""), &strings.Builder{}, origin, fingerprint)
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeFalse())
	})

	It("returns false for empty line", func() {
		ok, err := confirmTrustRoot(strings.NewReader("\n"), &strings.Builder{}, origin, fingerprint)
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeFalse())
	})

	It("includes the fingerprint in the output prompt", func() {
		var out strings.Builder
		_, err := confirmTrustRoot(strings.NewReader("n\n"), &out, origin, fingerprint)
		Expect(err).NotTo(HaveOccurred())
		Expect(out.String()).To(ContainSubstring(fingerprint))
		Expect(out.String()).To(ContainSubstring(origin))
	})
})

var _ = Describe("acquireTrustRoot", func() {
	var (
		pubContent string
		srv        *httptest.Server
	)

	BeforeEach(func() {
		pubContent = minisignPubFile()
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(pubContent))
		}))
	})

	AfterEach(func() {
		srv.Close()
	})

	It("with assumeYes=true downloads and persists <source>.pub, returns its path", func() {
		tmp := GinkgoT().TempDir()
		cmd := newTestCmd("")

		got, err := acquireTrustRoot(cmd, "native", srv.URL+"/key.pub", true, tmp)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(filepath.Join(tmp, "trust", "native.pub")))

		// File must exist and be parseable as a minisign key.
		data, rerr := os.ReadFile(got)
		Expect(rerr).NotTo(HaveOccurred())
		_, perr := minisign.DecodePublicKey(string(data))
		Expect(perr).NotTo(HaveOccurred())
	})

	It("with assumeYes=true persists with mode 0o644", func() {
		tmp := GinkgoT().TempDir()
		cmd := newTestCmd("")

		got, err := acquireTrustRoot(cmd, "native", srv.URL+"/key.pub", true, tmp)
		Expect(err).NotTo(HaveOccurred())

		fi, statErr := os.Stat(got)
		Expect(statErr).NotTo(HaveOccurred())
		Expect(fi.Mode().Perm()).To(Equal(os.FileMode(0o644)))
	})

	It("returns CLIError when downloaded content is not a valid minisign key", func() {
		bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not a minisign key\n"))
		}))
		defer bad.Close()

		tmp := GinkgoT().TempDir()
		cmd := newTestCmd("")
		_, err := acquireTrustRoot(cmd, "native", bad.URL+"/key.pub", true, tmp)
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Msg).To(ContainSubstring("not a valid minisign public key"))
	})

	It("with assumeYes=false and non-TTY stdin returns CLIError (no silent trust)", func() {
		tmp := GinkgoT().TempDir()
		// newTestCmd uses a strings.Reader (not a char device) → isInteractive returns false.
		cmd := newTestCmd("y\n")

		_, err := acquireTrustRoot(cmd, "native", srv.URL+"/key.pub", false, tmp)
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Msg).To(ContainSubstring("stdin is not a terminal"))
		Expect(ce.Hint).To(ContainSubstring("--trust-root-yes"))
	})

	It("persists the key under trust/<source>.pub (source name in filename)", func() {
		tmp := GinkgoT().TempDir()
		cmd := newTestCmd("")

		got, err := acquireTrustRoot(cmd, "myrepo", srv.URL+"/key.pub", true, tmp)
		Expect(err).NotTo(HaveOccurred())
		Expect(filepath.Base(got)).To(Equal("myrepo.pub"))
	})
})

var _ = Describe("init command: --trust-root-url flag", func() {
	var (
		tmp        string
		pubContent string
		srv        *httptest.Server
		sourceURL  = "https://repo.example.com/polypkg"
	)

	BeforeEach(func() {
		tmp = GinkgoT().TempDir()
		GinkgoT().Setenv("XDG_CONFIG_HOME", tmp)
		_ = os.Unsetenv("POLYPKG_PROFILE")

		pubContent = minisignPubFile()
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(pubContent))
		}))
	})

	AfterEach(func() {
		srv.Close()
	})

	runInitWithTrustURL := func(extraArgs ...string) (string, error) {
		root := NewRootCmd()
		root.SilenceUsage = true
		root.SilenceErrors = true
		var buf strings.Builder
		root.SetOut(&buf)
		root.SetErr(&buf)
		// Force stdin to a non-TTY so isInteractive returns false consistently,
		// matching the existing init tests which use the same pattern.
		root.SetIn(strings.NewReader(""))
		root.SetArgs(append([]string{"init"}, extraArgs...))
		err := root.Execute()
		return buf.String(), err
	}

	It("writes profile.yaml with trust_root pointing at the persisted .pub", func() {
		out, err := runInitWithTrustURL(
			"--source-url", sourceURL,
			"--trust-root-url", srv.URL+"/key.pub",
			"--trust-root-yes",
		)
		Expect(err).NotTo(HaveOccurred(), "init failed: %s", out)

		profilePath := filepath.Join(tmp, "polypkg", "profile.yaml")
		Expect(out).To(ContainSubstring("wrote " + profilePath))

		raw, rerr := os.ReadFile(profilePath)
		Expect(rerr).NotTo(HaveOccurred())

		// trust_root in the profile must point at the persisted .pub, not the URL.
		expectedPub := filepath.Join(tmp, "polypkg", "trust", "native.pub")
		Expect(string(raw)).To(ContainSubstring(expectedPub))
	})

	It("the persisted .pub is a valid minisign public key", func() {
		_, err := runInitWithTrustURL(
			"--source-url", sourceURL,
			"--trust-root-url", srv.URL+"/key.pub",
			"--trust-root-yes",
		)
		Expect(err).NotTo(HaveOccurred())

		pubPath := filepath.Join(tmp, "polypkg", "trust", "native.pub")
		data, rerr := os.ReadFile(pubPath)
		Expect(rerr).NotTo(HaveOccurred())
		_, perr := minisign.DecodePublicKey(string(data))
		Expect(perr).NotTo(HaveOccurred(), "persisted .pub must be a valid minisign key")
	})

	It("the written profile passes schema.ParseProfile", func() {
		_, err := runInitWithTrustURL(
			"--source-url", sourceURL,
			"--trust-root-url", srv.URL+"/key.pub",
			"--trust-root-yes",
		)
		Expect(err).NotTo(HaveOccurred())

		profilePath := filepath.Join(tmp, "polypkg", "profile.yaml")
		f, ferr := os.Open(profilePath)
		Expect(ferr).NotTo(HaveOccurred())
		defer f.Close()
		_, perr := parseProfileReader(f)
		Expect(perr).NotTo(HaveOccurred(), "written profile must be schema-valid")
	})

	It("mutual exclusion: --trust-root-file and --trust-root-url together return CLIError", func() {
		tmp2 := GinkgoT().TempDir()
		keyFile := writeTrustKeyFile(tmp2)

		_, err := runInitWithTrustURL(
			"--source-url", sourceURL,
			"--trust-root-file", keyFile,
			"--trust-root-url", srv.URL+"/key.pub",
		)
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("use only one of --trust-root-file or --trust-root-url"))
	})

	It("--trust-root-url without --trust-root-yes in non-TTY mode returns CLIError", func() {
		// In tests, stdin is not a TTY, so omitting --trust-root-yes must error.
		_, err := runInitWithTrustURL(
			"--source-url", sourceURL,
			"--trust-root-url", srv.URL+"/key.pub",
		)
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("stdin is not a terminal"))
		Expect(ce.Hint).To(ContainSubstring("--trust-root-yes"))
	})

	It("--trust-root-url counts as flagsProvided (triggers non-interactive route)", func() {
		// With --trust-root-url alone (no --source-url), should get the
		// non-interactive missing-flags error, not the TTY wizard.
		_, err := runInitWithTrustURL("--trust-root-url", srv.URL+"/key.pub")
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		// Must hit the non-interactive path (missing --source-url), not the wizard.
		Expect(ce.Msg).To(ContainSubstring("init needs --source-url and a trust root"))
	})

	It("returns profile-already-exists error without downloading when profile is present", func() {
		// Pre-create a profile so the fast-fail guard fires before any download.
		cfgDir := filepath.Join(tmp, "polypkg")
		Expect(os.MkdirAll(cfgDir, 0o700)).To(Succeed())
		existing := filepath.Join(cfgDir, "profile.yaml")
		Expect(os.WriteFile(existing, []byte("x"), 0o600)).To(Succeed())

		// Use a server that would fail if hit — any download means the guard was bypassed.
		noDownload := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer noDownload.Close()

		_, err := runInitWithTrustURL(
			"--source-url", sourceURL,
			"--trust-root-url", noDownload.URL+"/key.pub",
			"--trust-root-yes",
		)
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("profile already exists at"))
		Expect(ce.Msg).To(ContainSubstring(existing))
	})
})

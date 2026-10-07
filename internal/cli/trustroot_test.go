package cli

import (
	"encoding/hex"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/jedisct1/go-minisign"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/cobra"

	"github.com/trevor-vaughan/polypkg/internal/source"
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

// keyIDOf returns the hex key id of a minisign public key file's contents,
// the value --trust-root-fingerprint expects. Computed here rather than with
// trustRootFingerprint so the tests do not check that function against itself.
func keyIDOf(pubFile string) string {
	GinkgoHelper()
	pub, err := minisign.DecodePublicKey(pubFile)
	Expect(err).NotTo(HaveOccurred())
	return hex.EncodeToString(pub.KeyId[:])
}

// useTrustRootServer routes trust-root downloads through srv's client, which
// trusts the test server's self-signed certificate, for the rest of the spec.
// The production timeout and redirect policy are carried over so the specs
// exercise them. The production transport is not: srv's client replaces
// NewHTTPClient's idle-read transport and header timeout, so these specs
// never pass through them. That behaviour is covered by internal/source's
// specs; these cover the CLI's error mapping and the redirect policy.
func useTrustRootServer(srv *httptest.Server) {
	prev := trustRootHTTPClient
	c := srv.Client()
	c.Timeout = prev.Timeout
	c.CheckRedirect = prev.CheckRedirect
	trustRootHTTPClient = c
	DeferCleanup(func() { trustRootHTTPClient = prev })
}

// serveTrustRoot starts an HTTPS test server that answers every request with
// body, routes trust-root downloads through it, and closes it after the spec.
func serveTrustRoot(body string) *httptest.Server {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	DeferCleanup(srv.Close)
	useTrustRootServer(srv)
	return srv
}

var _ = Describe("fetchTrustRootBytes", func() {
	var pubContent string

	BeforeEach(func() {
		pubContent = minisignPubFile()
	})

	Context("https URL", func() {
		It("downloads and returns bytes on 200 OK", func() {
			srv := serveTrustRoot(pubContent)

			data, err := fetchTrustRootBytes(srv.URL + "/key.pub")
			Expect(err).NotTo(HaveOccurred())
			Expect(string(data)).To(Equal(pubContent))
		})

		It("returns CLIError on non-200 response", func() {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			}))
			DeferCleanup(srv.Close)
			useTrustRootServer(srv)

			_, err := fetchTrustRootBytes(srv.URL + "/missing.pub")
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue())
			Expect(ce.Msg).To(ContainSubstring("trust root download failed"))
			Expect(ce.Msg).To(ContainSubstring("404"))
		})

		It("returns CLIError on connection failure", func() {
			_, err := fetchTrustRootBytes("https://127.0.0.1:1") // nothing listening
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue())
			Expect(ce.Msg).To(ContainSubstring("cannot download trust root"))
		})

		It("refuses a redirect from https to plain http without following it", func() {
			var plainHits atomic.Int32
			plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				plainHits.Add(1)
				_, _ = w.Write([]byte(pubContent))
			}))
			DeferCleanup(plain.Close)
			redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, plain.URL+"/key.pub", http.StatusFound)
			}))
			DeferCleanup(redirector.Close)
			useTrustRootServer(redirector)

			_, err := fetchTrustRootBytes(redirector.URL + "/key.pub")
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
			Expect(ce.Msg).To(Equal("trust root download from " + redirector.URL + "/key.pub redirected to a non-https URL; refused"))
			Expect(ce.Hint).To(Equal("use the final https URL directly"))
			Expect(errors.Is(err, source.ErrInsecureRedirect)).To(BeTrue(), "got %v", err)
			Expect(plainHits.Load()).To(BeZero(), "the plain-http target must never be contacted")
		})

		It("follows a cross-host https to https redirect", func() {
			cdn := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(pubContent))
			}))
			DeferCleanup(cdn.Close)
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, cdn.URL+r.URL.Path, http.StatusFound)
			}))
			DeferCleanup(origin.Close)
			// Every httptest TLS server presents the same certificate, so origin's
			// client also trusts cdn, a different host:port on loopback.
			useTrustRootServer(origin)

			data, err := fetchTrustRootBytes(origin.URL + "/key.pub")
			Expect(err).NotTo(HaveOccurred())
			Expect(string(data)).To(Equal(pubContent))
		})
	})

	It("does not echo a URL that fails to parse, so its credentials stay hidden", func() {
		_, err := fetchTrustRootBytes("https://u:secret@h/%zz")
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(Equal("invalid --trust-root-url: not a parseable URL"))
		Expect(ce.Msg).NotTo(ContainSubstring("secret"))
		Expect(ce.Hint).To(Equal("use an https URL, a file:// URL, or an absolute path"))
	})

	It("never puts URL credentials in Msg", func() {
		notFound := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		DeferCleanup(notFound.Close)
		useTrustRootServer(notFound)
		host := strings.TrimPrefix(notFound.URL, "https://")

		// Both a user:password pair and a user-name-only token (the form
		// GitHub-style tokens take) must be kept out of Msg.
		for _, creds := range []string{"user:secret", "ghp_secret"} {
			for _, u := range []string{
				"http://" + creds + "@repo.example.com/key.pub", // plain http refused
				"https://" + creds + "@" + host + "/key.pub",    // non-200 status
				"https://" + creds + "@127.0.0.1:1/key.pub",     // connection failure
				"ftp://" + creds + "@repo.example.com/key.pub",  // unsupported scheme
			} {
				_, err := fetchTrustRootBytes(u)
				var ce *CLIError
				Expect(errors.As(err, &ce)).To(BeTrue(), "%s: expected CLIError, got %T: %v", u, err, err)
				Expect(ce.Msg).NotTo(ContainSubstring("secret"), u)
				Expect(ce.Msg).To(ContainSubstring("://xxxxx@"), u)
			}
		}
	})

	Context("plain http URL", func() {
		It("refuses it without making a request", func() {
			var hits atomic.Int32
			plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				_, _ = w.Write([]byte(pubContent))
			}))
			DeferCleanup(plain.Close)

			_, err := fetchTrustRootBytes(plain.URL + "/key.pub")
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
			Expect(ce.Msg).To(ContainSubstring("plain http"))
			Expect(ce.Hint).To(ContainSubstring("https://"))
			Expect(hits.Load()).To(BeZero())
		})

		It("refuses an upper-case HTTP scheme too", func() {
			_, err := fetchTrustRootBytes("HTTP://repo.example.com/trust_root.pub")
			Expect(err).To(HaveOccurred())
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
			Expect(ce.Msg).To(ContainSubstring("plain http"))
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
			srv := serveTrustRoot(string(make([]byte, maxTrustRootBytes+1)))

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

var _ = Describe("confirmTrustRootReplacement", func() {
	const (
		origin = "/srv/new/trust_root.pub"
		oldID  = "1111111111111111"
		newID  = "2222222222222222"
	)

	It("returns true for 'y'", func() {
		ok, err := confirmTrustRootReplacement(strings.NewReader("y\n"), &strings.Builder{}, "native", origin, oldID, newID)
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())
	})

	It("returns false for 'n'", func() {
		ok, err := confirmTrustRootReplacement(strings.NewReader("n\n"), &strings.Builder{}, "native", origin, oldID, newID)
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeFalse())
	})

	It("returns false for empty input (EOF)", func() {
		ok, err := confirmTrustRootReplacement(strings.NewReader(""), &strings.Builder{}, "native", origin, oldID, newID)
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeFalse())
	})

	It("shows the source, both key ids, and the new key's origin", func() {
		var out strings.Builder
		_, err := confirmTrustRootReplacement(strings.NewReader("n\n"), &out, "native", origin, oldID, newID)
		Expect(err).NotTo(HaveOccurred())
		Expect(out.String()).To(ContainSubstring("native"))
		Expect(out.String()).To(ContainSubstring("pinned key id: " + oldID))
		Expect(out.String()).To(ContainSubstring(newID))
		Expect(out.String()).To(ContainSubstring(origin))
		Expect(out.String()).To(ContainSubstring("This also clears the source's anti-rollback state."))
	})
})

var _ = Describe("matchTrustRootFingerprint", func() {
	It("quotes the operator-supplied fingerprint, escaping control characters", func() {
		err := matchTrustRootFingerprint("abc\x1b[31m", "1111111111111111", "/srv/trust_root.pub")
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring(`not the expected "abc\x1b[31m"`))
		Expect(ce.Msg).NotTo(ContainSubstring("\x1b"))
	})
})

var _ = Describe("trustRootFingerprint", func() {
	It("returns the key id as lowercase hex, the form repo key show prints", func() {
		pubContent := minisignPubFile()
		got, err := trustRootFingerprint([]byte(pubContent))
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(keyIDOf(pubContent)))
		Expect(got).To(MatchRegexp(`^[0-9a-f]{16}$`))
	})

	It("rejects bytes that are not a minisign public key", func() {
		_, err := trustRootFingerprint([]byte("not a minisign key\n"))
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("acquireTrustRoot", func() {
	var (
		pubContent string
		keyID      string
		srv        *httptest.Server
		tmp        string
	)

	BeforeEach(func() {
		pubContent = minisignPubFile()
		keyID = keyIDOf(pubContent)
		srv = serveTrustRoot(pubContent)
		tmp = GinkgoT().TempDir()
	})

	It("with a matching fingerprint downloads and persists <source>.pub, returns its path", func() {
		got, err := acquireTrustRoot(newTestCmd(""), "native", srv.URL+"/key.pub", keyID, tmp)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(filepath.Join(tmp, "trust", "native.pub")))

		// File must hold exactly the downloaded key.
		Expect(os.ReadFile(got)).To(Equal([]byte(pubContent)))
	})

	It("compares the fingerprint without regard to case", func() {
		_, err := acquireTrustRoot(newTestCmd(""), "native", srv.URL+"/key.pub", strings.ToUpper(keyID), tmp)
		Expect(err).NotTo(HaveOccurred())
	})

	It("persists with mode 0o644", func() {
		got, err := acquireTrustRoot(newTestCmd(""), "native", srv.URL+"/key.pub", keyID, tmp)
		Expect(err).NotTo(HaveOccurred())

		fi, statErr := os.Stat(got)
		Expect(statErr).NotTo(HaveOccurred())
		Expect(fi.Mode().Perm()).To(Equal(os.FileMode(0o644)))
	})

	It("refuses a fingerprint that does not match the downloaded key and persists nothing", func() {
		_, err := acquireTrustRoot(newTestCmd(""), "native", srv.URL+"/key.pub", "0000000000000000", tmp)
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("has key id " + keyID))
		Expect(ce.Msg).To(ContainSubstring(`not the expected "0000000000000000"`))
		Expect(filepath.Join(tmp, "trust", "native.pub")).NotTo(BeAnExistingFile())
	})

	It("returns CLIError when downloaded content is not a valid minisign key", func() {
		bad := serveTrustRoot("not a minisign key\n")

		_, err := acquireTrustRoot(newTestCmd(""), "native", bad.URL+"/key.pub", keyID, tmp)
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Msg).To(ContainSubstring("not a valid minisign public key"))
	})

	It("without a fingerprint and with non-TTY stdin returns CLIError (no silent trust)", func() {
		// newTestCmd uses a strings.Reader (not a char device) → isInteractive returns false.
		_, err := acquireTrustRoot(newTestCmd("y\n"), "native", srv.URL+"/key.pub", "", tmp)
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Msg).To(ContainSubstring("stdin is not a terminal"))
		Expect(ce.Hint).To(ContainSubstring("--trust-root-fingerprint"))
		Expect(filepath.Join(tmp, "trust", "native.pub")).NotTo(BeAnExistingFile())
	})

	It("keeps URL credentials out of a fingerprint mismatch and a bad-key error", func() {
		withCreds := strings.Replace(srv.URL, "https://", "https://user:secret@", 1) + "/key.pub"
		_, err := acquireTrustRoot(newTestCmd(""), "native", withCreds, "0000000000000000", tmp)
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("not the expected"))
		Expect(ce.Msg).NotTo(ContainSubstring("secret"))

		bad := serveTrustRoot("not a minisign key\n")
		badWithCreds := strings.Replace(bad.URL, "https://", "https://user:secret@", 1) + "/key.pub"
		_, err = acquireTrustRoot(newTestCmd(""), "native", badWithCreds, keyID, tmp)
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("not a valid minisign public key"))
		Expect(ce.Msg).NotTo(ContainSubstring("secret"))
	})

	It("persists the key under trust/<source>.pub (source name in filename)", func() {
		got, err := acquireTrustRoot(newTestCmd(""), "myrepo", srv.URL+"/key.pub", keyID, tmp)
		Expect(err).NotTo(HaveOccurred())
		Expect(filepath.Base(got)).To(Equal("myrepo.pub"))
	})
})

var _ = Describe("pinTrustRootFile", func() {
	var (
		tmp        string
		keyFile    string
		pubContent string
	)

	BeforeEach(func() {
		tmp = GinkgoT().TempDir()
		pubContent = minisignPubFile()
		keyFile = filepath.Join(tmp, "anchor.pub")
		Expect(os.WriteFile(keyFile, []byte(pubContent), 0o600)).To(Succeed())
	})

	It("pins the file without a fingerprint", func() {
		got, err := pinTrustRootFile(keyFile, tmp, "native", "")
		Expect(err).NotTo(HaveOccurred())
		Expect(os.ReadFile(got)).To(Equal([]byte(pubContent)))
	})

	It("pins the file when the fingerprint matches", func() {
		_, err := pinTrustRootFile(keyFile, tmp, "native", keyIDOf(pubContent))
		Expect(err).NotTo(HaveOccurred())
	})

	It("refuses a mismatched fingerprint and pins nothing", func() {
		_, err := pinTrustRootFile(keyFile, tmp, "native", "0000000000000000")
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring(`not the expected "0000000000000000"`))
		Expect(filepath.Join(tmp, "trust", "native.pub")).NotTo(BeAnExistingFile())
	})
})

var _ = Describe("persistTrustRoot", func() {
	var (
		destDir string
		dest    string
		pinned  []byte
	)

	BeforeEach(func() {
		destDir = GinkgoT().TempDir()
		dest = filepath.Join(destDir, "trust", "native.pub")
		pinned = []byte(minisignPubFile())
		_, err := persistTrustRoot(destDir, "native", pinned)
		Expect(err).NotTo(HaveOccurred())
	})

	It("accepts the bytes already pinned (idempotent re-run)", func() {
		got, err := persistTrustRoot(destDir, "native", pinned)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(dest))
		Expect(os.ReadFile(dest)).To(Equal(pinned))
	})

	It("refuses to replace an anchor holding a different key and leaves it untouched", func() {
		_, err := persistTrustRoot(destDir, "native", []byte(minisignPubFile()))
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("already pinned at " + dest))
		Expect(ce.Hint).To(ContainSubstring("polypkg source set-trust-root native"))
		Expect(ce.Hint).To(ContainSubstring("delete it"))
		Expect(os.ReadFile(dest)).To(Equal(pinned))
		Expect(dest + ".tmp").NotTo(BeAnExistingFile())
	})

	It("writeManagedTrustRoot replaces the anchor (the explicit set-trust-root path)", func() {
		replacement := []byte(minisignPubFile())
		got, err := writeManagedTrustRoot(destDir, "native", replacement)
		Expect(err).NotTo(HaveOccurred())
		Expect(got).To(Equal(dest))
		Expect(os.ReadFile(dest)).To(Equal(replacement))
	})

	It("does not follow a symlink planted at the old predictable temp path", func() {
		victim := filepath.Join(GinkgoT().TempDir(), "victim")
		Expect(os.WriteFile(victim, []byte("untouched"), 0o600)).To(Succeed())
		Expect(os.Symlink(victim, dest+".tmp")).To(Succeed())

		replacement := []byte(minisignPubFile())
		_, err := writeManagedTrustRoot(destDir, "native", replacement)
		Expect(err).NotTo(HaveOccurred())
		Expect(os.ReadFile(victim)).To(Equal([]byte("untouched")))
		Expect(os.ReadFile(dest)).To(Equal(replacement))
		fi, serr := os.Lstat(dest)
		Expect(serr).NotTo(HaveOccurred())
		Expect(fi.Mode().IsRegular()).To(BeTrue())
		Expect(fi.Mode().Perm()).To(Equal(os.FileMode(0o644)))
	})

	It("removes its temp file when the final rename fails", func() {
		// A non-empty directory at the anchor path makes the rename fail.
		Expect(os.Remove(dest)).To(Succeed())
		Expect(os.MkdirAll(filepath.Join(dest, "occupied"), 0o700)).To(Succeed())

		_, err := writeManagedTrustRoot(destDir, "native", []byte(minisignPubFile()))
		Expect(err).To(HaveOccurred())
		leftovers, gerr := filepath.Glob(filepath.Join(destDir, "trust", "native.pub.*"))
		Expect(gerr).NotTo(HaveOccurred())
		Expect(leftovers).To(BeEmpty())
	})

	It("names the path, not the OS error, when the trust directory cannot be created", func() {
		if os.Geteuid() == 0 {
			Skip("a read-only directory does not stop root")
		}
		roDir := filepath.Join(GinkgoT().TempDir(), "ro")
		Expect(os.Mkdir(roDir, 0o500)).To(Succeed())
		DeferCleanup(os.Chmod, roDir, os.FileMode(0o700))

		_, err := writeManagedTrustRoot(roDir, "native", pinned)
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(Equal("cannot create trust directory " + filepath.Join(roDir, "trust") + ": permission denied"))
		Expect(ce.Err).To(MatchError(os.ErrPermission))
	})
})

var _ = DescribeTable("fsFailureMsg names the cause in words, never the raw error",
	func(cause error, want string) {
		err := &fs.PathError{Op: "open", Path: "/cfg/trust/native.pub.tmp", Err: cause}
		Expect(fsFailureMsg("cannot write trust root /cfg/trust/native.pub.tmp", err)).To(Equal(want))
	},
	Entry("permission", syscall.EACCES, "cannot write trust root /cfg/trust/native.pub.tmp: permission denied"),
	Entry("no space", syscall.ENOSPC, "cannot write trust root /cfg/trust/native.pub.tmp: no space left on device"),
	Entry("read-only file system", syscall.EROFS, "cannot write trust root /cfg/trust/native.pub.tmp: read-only file system"),
	Entry("anything else: path only", syscall.EIO, "cannot write trust root /cfg/trust/native.pub.tmp"),
)

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
		srv = serveTrustRoot(pubContent)
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
			"--trust-root-fingerprint", keyIDOf(pubContent),
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
			"--trust-root-fingerprint", keyIDOf(pubContent),
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
			"--trust-root-fingerprint", keyIDOf(pubContent),
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

	It("refuses a plain http --trust-root-url and writes nothing", func() {
		_, err := runInitWithTrustURL(
			"--source-url", sourceURL,
			"--trust-root-url", "http://repo.example.com/trust_root.pub",
		)
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("plain http"))
		Expect(filepath.Join(tmp, "polypkg", "trust", "native.pub")).NotTo(BeAnExistingFile())
		Expect(filepath.Join(tmp, "polypkg", "profile.yaml")).NotTo(BeAnExistingFile())
	})

	It("--trust-root-url without --trust-root-fingerprint in non-TTY mode returns CLIError", func() {
		// In tests, stdin is not a TTY, so omitting the fingerprint must error.
		_, err := runInitWithTrustURL(
			"--source-url", sourceURL,
			"--trust-root-url", srv.URL+"/key.pub",
		)
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("stdin is not a terminal"))
		Expect(ce.Hint).To(ContainSubstring("--trust-root-fingerprint"))
	})

	It("refuses a --trust-root-fingerprint that does not match and writes nothing", func() {
		_, err := runInitWithTrustURL(
			"--source-url", sourceURL,
			"--trust-root-url", srv.URL+"/key.pub",
			"--trust-root-fingerprint", "0000000000000000",
		)
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring(`not the expected "0000000000000000"`))
		Expect(filepath.Join(tmp, "polypkg", "trust", "native.pub")).NotTo(BeAnExistingFile())
		Expect(filepath.Join(tmp, "polypkg", "profile.yaml")).NotTo(BeAnExistingFile())
	})

	It("no longer accepts --trust-root-yes", func() {
		_, err := runInitWithTrustURL(
			"--source-url", sourceURL,
			"--trust-root-url", srv.URL+"/key.pub",
			"--trust-root-yes",
		)
		Expect(err).To(MatchError(ContainSubstring("unknown flag --trust-root-yes")))
		Expect(filepath.Join(tmp, "polypkg", "trust", "native.pub")).NotTo(BeAnExistingFile())
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
		noDownload := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		DeferCleanup(noDownload.Close)
		useTrustRootServer(noDownload)

		_, err := runInitWithTrustURL(
			"--source-url", sourceURL,
			"--trust-root-url", noDownload.URL+"/key.pub",
			"--trust-root-fingerprint", keyIDOf(pubContent),
		)
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(ContainSubstring("profile already exists at"))
		Expect(ce.Msg).To(ContainSubstring(existing))
	})
})

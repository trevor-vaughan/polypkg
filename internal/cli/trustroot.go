package cli

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jedisct1/go-minisign"
	"github.com/spf13/cobra"
)

// maxTrustRootBytes caps a downloaded trust-root .pub (a minisign public key is
// ~100 bytes; this is generous but bounded).
const maxTrustRootBytes = 64 << 10

// fetchTrustRootBytes retrieves the trust-root public-key bytes from a URL that
// may be http(s), file://, or an absolute local path.
func fetchTrustRootBytes(trustRootURL string) ([]byte, error) {
	// Local forms: absolute path (no scheme).
	if strings.HasPrefix(trustRootURL, "/") {
		return readTrustRootFile(trustRootURL)
	}
	u, err := url.Parse(trustRootURL)
	if err != nil {
		return nil, &CLIError{Msg: fmt.Sprintf("invalid --trust-root-url %q", trustRootURL), Hint: "use an http(s) URL, a file:// URL, or an absolute path", Err: err}
	}
	switch u.Scheme {
	case "file":
		return readTrustRootFile(u.Path)
	case "http", "https":
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(trustRootURL) //nolint:gosec // operator-supplied trust-root URL; the downloaded key is shown + confirmed (TOFU) before use
		if err != nil {
			return nil, &CLIError{Msg: fmt.Sprintf("cannot download trust root from %s", trustRootURL), Hint: "check the URL and network", Err: err}
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, &CLIError{Msg: fmt.Sprintf("trust root download failed: %s returned status %d", trustRootURL, resp.StatusCode), Hint: "verify the URL points at the repository's trust_root.pub"}
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxTrustRootBytes+1))
		if err != nil {
			return nil, &CLIError{Msg: "error reading trust root download", Err: err}
		}
		if int64(len(data)) > maxTrustRootBytes {
			return nil, &CLIError{Msg: "trust root is implausibly large", Hint: "expected a minisign .pub file (a few hundred bytes)"}
		}
		return data, nil
	default:
		return nil, &CLIError{Msg: fmt.Sprintf("invalid --trust-root-url %q", trustRootURL), Hint: "use an http(s) URL, a file:// URL, or an absolute path"}
	}
}

func readTrustRootFile(p string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Clean(p)) //nolint:gosec // operator-supplied trust-root path; content validated as a minisign key + TOFU-confirmed
	if err != nil {
		return nil, &CLIError{Msg: fmt.Sprintf("cannot read trust root %s", p), Hint: "check the path", Err: err}
	}
	return data, nil
}

// acquireTrustRoot downloads the trust root from trustRootURL, parses it as a
// minisign public key, shows its fingerprint, obtains TOFU confirmation (unless
// assumeYes is true), persists it under destDir/trust/<source>.pub (mode 0o644),
// and returns the saved absolute path. assumeYes is REQUIRED when stdin is not
// a terminal.
func acquireTrustRoot(cmd *cobra.Command, source, trustRootURL string, assumeYes bool, destDir string) (string, error) {
	data, err := fetchTrustRootBytes(trustRootURL)
	if err != nil {
		return "", err
	}
	pub, err := minisign.DecodePublicKey(string(data))
	if err != nil {
		return "", &CLIError{Msg: fmt.Sprintf("downloaded trust root from %s is not a valid minisign public key", trustRootURL), Hint: "the URL must point at the repository's minisign .pub file", Err: err}
	}
	fingerprint := hex.EncodeToString(pub.KeyId[:])

	if !assumeYes {
		if !isInteractive(cmd) {
			return "", &CLIError{
				Msg:  "trust root needs confirmation but stdin is not a terminal",
				Hint: "re-run with --trust-root-yes to trust the downloaded key non-interactively",
			}
		}
		ok, err := confirmTrustRoot(cmd.InOrStdin(), cmd.OutOrStdout(), trustRootURL, fingerprint)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", &CLIError{Msg: "trust root not confirmed (answer was not yes)"}
		}
	}

	trustDir := filepath.Join(destDir, "trust")
	if err := os.MkdirAll(trustDir, 0o700); err != nil {
		return "", &CLIError{Msg: "cannot create trust directory", Err: err}
	}
	dest := filepath.Join(trustDir, source+".pub")
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil { //nolint:gosec // 0o644: public key material; no secrets
		return "", &CLIError{Msg: "cannot write trust root", Err: err}
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp) // don't leave a stray .tmp on a failed rename
		return "", &CLIError{Msg: "cannot save trust root", Err: err}
	}
	return dest, nil
}

// confirmTrustRoot prompts on out and reads a y/N answer from in, showing the
// key fingerprint and origin so the operator can verify out-of-band (TOFU).
// Only "y" or "Y" confirms; empty or anything else declines.
func confirmTrustRoot(in io.Reader, out io.Writer, origin, fingerprint string) (bool, error) {
	fmt.Fprintf(out, "Downloaded trust root from %s\n  key fingerprint: %s\nVerify this matches the publisher's key id (e.g. from `polypkg repo key show`).\nTrust this key? [y/N]: ", origin, fingerprint)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	line = strings.TrimSpace(line)
	return line == "y" || line == "Y", nil
}

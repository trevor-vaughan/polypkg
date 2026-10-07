package cli

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jedisct1/go-minisign"
	"github.com/spf13/cobra"

	"github.com/trevor-vaughan/polypkg/internal/source"
)

// maxTrustRootBytes caps a downloaded trust-root .pub (a minisign public key is
// ~100 bytes; this is generous but bounded).
const maxTrustRootBytes = 64 << 10

// trustRootHTTPClient downloads --trust-root-url keys. It is the source
// client (response-header timeout, no redirect off https) with a 30s
// whole-request bound, which a ~100-byte key never needs to approach. It is a
// variable only so tests can route it through an httptest TLS server's
// client; production code never reassigns it.
var trustRootHTTPClient = func() *http.Client {
	c := source.NewHTTPClient()
	c.Timeout = 30 * time.Second
	return c
}()

// fetchTrustRootBytes retrieves the trust-root public-key bytes from an https
// URL, a file:// URL, or an absolute local path. Plain http is refused: the
// key anchors every later signature check, and over an unauthenticated channel
// anyone on the path could substitute their own.
func fetchTrustRootBytes(trustRootURL string) ([]byte, error) {
	// Local forms: absolute path (no scheme).
	if strings.HasPrefix(trustRootURL, "/") {
		return readTrustRootFile(trustRootURL)
	}
	u, err := url.Parse(trustRootURL)
	if err != nil {
		// Not echoed: an unparseable URL cannot be redacted, and it may carry
		// credentials.
		return nil, &CLIError{Msg: "invalid --trust-root-url: not a parseable URL", Hint: "use an https URL, a file:// URL, or an absolute path", Err: err}
	}
	switch u.Scheme {
	case "file":
		return readTrustRootFile(u.Path)
	case "http":
		return nil, &CLIError{
			Msg:  fmt.Sprintf("refusing to download a trust root over plain http: %s", source.RedactURL(trustRootURL)),
			Hint: "use an https:// URL, or fetch the key yourself, check its key id with the publisher, and pass the local file instead",
		}
	case "https":
		resp, err := trustRootHTTPClient.Get(trustRootURL) //nolint:gosec // operator-supplied trust-root URL; the downloaded key is confirmed (fingerprint or TOFU prompt) before use
		if errors.Is(err, source.ErrInsecureRedirect) {
			return nil, &CLIError{
				Msg:  fmt.Sprintf("trust root download from %s redirected to a non-https URL; refused", source.RedactURL(trustRootURL)),
				Hint: "use the final https URL directly",
				Err:  err,
			}
		}
		if err != nil {
			return nil, &CLIError{Msg: fmt.Sprintf("cannot download trust root from %s", source.RedactURL(trustRootURL)), Hint: "check the URL and network", Err: err}
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, &CLIError{Msg: fmt.Sprintf("trust root download failed: %s returned status %d", source.RedactURL(trustRootURL), resp.StatusCode), Hint: "verify the URL points at the repository's trust_root.pub"}
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
		return nil, &CLIError{Msg: fmt.Sprintf("invalid --trust-root-url %q", source.RedactURL(trustRootURL)), Hint: "use an https URL, a file:// URL, or an absolute path"}
	}
}

func readTrustRootFile(p string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Clean(p)) //nolint:gosec // operator-supplied trust-root path; content validated as a minisign key + TOFU-confirmed
	if err != nil {
		return nil, &CLIError{Msg: fmt.Sprintf("cannot read trust root %s", p), Hint: "check the path", Err: err}
	}
	return data, nil
}

// trustRootFingerprint decodes data as a minisign public key and returns its
// key id as lowercase hex: the form `polypkg repo key show` prints and
// --trust-root-fingerprint expects.
func trustRootFingerprint(data []byte) (string, error) {
	pub, err := minisign.DecodePublicKey(string(data))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pub.KeyId[:]), nil
}

// matchTrustRootFingerprint returns nil when want, an operator-supplied
// --trust-root-fingerprint, names the key id got (hex, compared without regard
// to case), and a CLIError naming both ids and the key's origin otherwise.
func matchTrustRootFingerprint(want, got, origin string) error {
	if strings.EqualFold(strings.TrimSpace(want), got) {
		return nil
	}
	return &CLIError{
		Msg:  fmt.Sprintf("trust root from %s has key id %s, not the expected %q", origin, got, want),
		Hint: "confirm the key id with the publisher (`polypkg repo key show` on the repository host); do not use this key until they match",
	}
}

// acquireTrustRoot downloads the trust root from trustRootURL, parses it as a
// minisign public key, confirms it, persists it under
// destDir/trust/<source>.pub (mode 0o644), and returns the saved path.
//
// Confirmation is wantFingerprint matching the key's id when the operator
// supplied one, and otherwise an interactive TOFU prompt showing that id. With
// neither a fingerprint nor a terminal it refuses: there is no way to accept
// downloaded bytes nobody has checked.
func acquireTrustRoot(cmd *cobra.Command, sourceName, trustRootURL, wantFingerprint, destDir string) (string, error) {
	data, err := fetchTrustRootBytes(trustRootURL)
	if err != nil {
		return "", err
	}
	// The URL can carry credentials; only the redacted form is shown.
	origin := source.RedactURL(trustRootURL)
	fingerprint, err := trustRootFingerprint(data)
	if err != nil {
		return "", &CLIError{Msg: fmt.Sprintf("downloaded trust root from %s is not a valid minisign public key", origin), Hint: "the URL must point at the repository's minisign .pub file", Err: err}
	}

	if wantFingerprint != "" {
		if err := matchTrustRootFingerprint(wantFingerprint, fingerprint, origin); err != nil {
			return "", err
		}
		return persistTrustRoot(destDir, sourceName, data)
	}
	if !isInteractive(cmd) {
		return "", &CLIError{
			Msg:  "trust root needs confirmation but stdin is not a terminal",
			Hint: "re-run with --trust-root-fingerprint <key id>, using the key id the publisher printed with `polypkg repo key show`",
		}
	}
	ok, err := confirmTrustRoot(cmd.InOrStdin(), cmd.OutOrStdout(), origin, fingerprint)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", &CLIError{Msg: "trust root not confirmed (answer was not yes)"}
	}
	return persistTrustRoot(destDir, sourceName, data)
}

// pinTrustRootFile reads the minisign public key at path, validates it, and
// copies it under destDir/trust/<source>.pub, returning the saved path. A
// non-empty wantFingerprint must match the key's id.
//
// The copy is the point: recording the operator's own path instead would leave
// the anchor late-bound, re-read from that path on every verification. Our
// guidance points --trust-root-file at the published repository's own tree, so
// an attacker who can write that tree could otherwise swap the anchor and have
// their index verify under it. No TOFU prompt here, unlike acquireTrustRoot: a
// local file the operator named is already material they chose, whereas a
// download is bytes they have not seen.
func pinTrustRootFile(path, destDir, sourceName, wantFingerprint string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", &CLIError{
			Msg: fmt.Sprintf("trust_root %q: cannot resolve path", path),
			Err: err,
		}
	}
	data, err := os.ReadFile(abs) //nolint:gosec // path is resolved from a user-supplied flag and sanitized to absolute
	if err != nil {
		return "", &CLIError{
			Msg:  fmt.Sprintf("trust_root %s is not a valid minisign public key", path),
			Hint: "trust_root must point at the repository's minisign .pub file",
			Err:  err,
		}
	}
	fingerprint, err := trustRootFingerprint(data)
	if err != nil {
		return "", &CLIError{
			Msg:  fmt.Sprintf("trust_root %s is not a valid minisign public key", path),
			Hint: "trust_root must point at the repository's minisign .pub file",
			Err:  err,
		}
	}
	if wantFingerprint != "" {
		if err := matchTrustRootFingerprint(wantFingerprint, fingerprint, path); err != nil {
			return "", err
		}
	}
	return persistTrustRoot(destDir, sourceName, data)
}

// managedTrustRootPath returns the canonical location of a source's pinned
// trust root. Every route that persists an anchor writes here, and
// managedOrphanTrustRoot decides what `source remove` may delete by comparing
// a profile's recorded path against it — so the formula lives in one place.
func managedTrustRootPath(cfgDir, sourceName string) string {
	return filepath.Clean(filepath.Join(cfgDir, "trust", sourceName+".pub"))
}

// persistTrustRoot pins validated public-key bytes as source's managed anchor
// (destDir/trust/<source>.pub) and returns that path. It never replaces an
// anchor that already holds different bytes: init and source add only create
// anchors, and swapping one is the explicit job of `source set-trust-root`,
// which calls writeManagedTrustRoot itself. Identical bytes are accepted, so
// re-running an interrupted command is harmless.
func persistTrustRoot(destDir, sourceName string, data []byte) (string, error) {
	if err := refuseAnchorReplacement(managedTrustRootPath(destDir, sourceName), sourceName, data); err != nil {
		return "", err
	}
	return writeManagedTrustRoot(destDir, sourceName, data)
}

// refuseAnchorReplacement returns a CLIError when dest already holds a trust
// root whose bytes differ from data. A missing dest, or one holding exactly
// data, is fine.
func refuseAnchorReplacement(dest, sourceName string, data []byte) error {
	existing, err := os.ReadFile(dest) //nolint:gosec // dest is the managed anchor path under the scope config dir
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return &CLIError{
			Msg:  fmt.Sprintf("cannot read the trust root already pinned at %s", dest),
			Hint: "check the file's permissions",
			Err:  err,
		}
	}
	if bytes.Equal(existing, data) {
		return nil
	}
	return &CLIError{
		Msg:  fmt.Sprintf("a different trust root is already pinned at %s", dest),
		Hint: fmt.Sprintf("to replace the key of a configured source, run `polypkg source set-trust-root %s`; if no profile uses this file, delete it and retry", sourceName),
	}
}

// writeManagedTrustRoot writes validated public-key bytes to
// destDir/trust/<source>.pub atomically, replacing whatever is there, and
// returns that path. Mode 0o644 because this is public key material and
// carries no secret; the enclosing trust/ dir is 0o700, so under --scope
// system only root reaches the anchor either way, which matches how system
// scope is operated.
func writeManagedTrustRoot(destDir, sourceName string, data []byte) (string, error) {
	// CLIError.Error() renders Msg alone, so each message names the path it
	// tried: this is the first write of an init run, and under --scope system
	// it is where an unprivileged operator lands.
	dest := managedTrustRootPath(destDir, sourceName)
	trustDir := filepath.Dir(dest)
	if err := os.MkdirAll(trustDir, 0o700); err != nil {
		return "", &CLIError{
			Msg:  fsFailureMsg("cannot create trust directory "+trustDir, err),
			Hint: "check that the config directory is writable (--scope system needs root)",
			Err:  err,
		}
	}
	// An unpredictable temp name, created exclusively, so nothing planted in
	// trust/ beforehand (a symlink at a guessable name, say) is followed.
	f, err := os.CreateTemp(trustDir, sourceName+".pub.*")
	if err != nil {
		return "", &CLIError{
			Msg:  fsFailureMsg("cannot create a temporary file in "+trustDir, err),
			Hint: fmt.Sprintf("check that %s is writable and has free space", trustDir),
			Err:  err,
		}
	}
	tmp := f.Name()
	writeErr := writeSyncClose(f, data)
	if writeErr == nil {
		writeErr = os.Chmod(tmp, 0o644) //nolint:gosec // 0o644: public key material; no secrets
	}
	if writeErr != nil {
		_ = os.Remove(tmp)
		return "", &CLIError{
			Msg:  fsFailureMsg("cannot write trust root "+tmp, writeErr),
			Hint: fmt.Sprintf("check that %s is writable and has free space", trustDir),
			Err:  writeErr,
		}
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp) // don't leave a stray temp file on a failed rename
		return "", &CLIError{
			Msg:  fsFailureMsg("cannot save trust root "+dest, err),
			Hint: fmt.Sprintf("check that %s is writable", trustDir),
			Err:  err,
		}
	}
	return dest, nil
}

// writeSyncClose writes data to f, flushes it to stable storage and closes
// it, so a crash after the rename cannot leave an anchor with no contents. f
// is closed on every path.
func writeSyncClose(f *os.File, data []byte) error {
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// fsFailureMsg appends the cause of a filesystem failure to failed (an action
// plus the path it acted on) in plain words, for the causes an operator can
// act on. Any other cause leaves failed as is: CLIError.Msg must not carry raw
// Go or syscall text, so that stays in the CLIError's Err.
func fsFailureMsg(failed string, err error) string {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return failed + ": permission denied"
	case errors.Is(err, syscall.ENOSPC):
		return failed + ": no space left on device"
	case errors.Is(err, syscall.EROFS):
		return failed + ": read-only file system"
	default:
		return failed
	}
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

// confirmTrustRootReplacement prompts on out and reads a y/N answer from in,
// showing the source, the currently pinned key id, and the new key id with its
// origin, so the operator can check the new id with the publisher. Only "y" or
// "Y" confirms; empty or anything else declines.
func confirmTrustRootReplacement(in io.Reader, out io.Writer, sourceName, origin, oldFingerprint, newFingerprint string) (bool, error) {
	fmt.Fprintf(out, "Replacing the trust root of source %s\n  pinned key id: %s\n  new key id:    %s (from %s)\nVerify the new key id with the publisher (e.g. from `polypkg repo key show`).\nThis also clears the source's anti-rollback state.\nReplace the trust root? [y/N]: ", sourceName, oldFingerprint, newFingerprint, origin)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	line = strings.TrimSpace(line)
	return line == "y" || line == "Y", nil
}

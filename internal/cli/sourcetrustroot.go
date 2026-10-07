package cli

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/jedisct1/go-minisign"
	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/profileedit"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/source"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

// newSourceSetTrustRootCmd implements 'polypkg source set-trust-root <name>'.
func newSourceSetTrustRootCmd() *cobra.Command {
	var (
		trustRoot    string
		trustRootURL string
		fingerprint  string
		resetState   bool
	)
	cmd := &cobra.Command{
		Use:   "set-trust-root <name>",
		Short: "Replace the trust root a source is pinned to",
		Long: `Replace the minisign public key a configured source is pinned to.

This is the only command that changes a pinned key: 'source add' refuses a
name that is already in the profile. Use it when a repository rotated its
signing key or was re-created from scratch, including on a profile whose only
source is the one being changed.

Exactly one of --trust-root <file> or --trust-root-url <url> supplies the new
key (https, file://, or an absolute path; plain http is refused). When the new
key differs from the pinned one the change must be confirmed, either by
--trust-root-fingerprint <key id> (the id 'polypkg repo key show' prints on the
repository host) or, on a TTY, by a prompt that shows the old and new key ids.
Without a TTY the fingerprint is required. If --trust-root-fingerprint is
given it must match the new key even when the key is unchanged.

The new key is saved to <config>/trust/<name>.pub and the profile entry is
pointed at it; the source's type, URL and preference-order position are kept.
The source's anti-rollback state is then cleared, so the next fetch pins its
serials afresh: a re-created repository whose serials restarted is accepted
again. Supplying the key that is already pinned changes nothing, unless
--reset-state is given: that clears the anti-rollback state anyway, for a
repository that was re-created with the same key and restarted its serials.
Because it lowers rollback protection until the next fetch, --reset-state
requires --trust-root-fingerprint.

Output honors --format json, emitting a cli-result/v2 envelope with the old and
new key ids.`,
		Args: needsArgs(1, 1, "<name>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "source set-trust-root",
				runSourceSetTrustRoot(cmd, args[0], trustRoot, trustRootURL, fingerprint, resetState, format))
		},
	}
	addScopeFlags(cmd)
	cmd.Flags().StringVar(&trustRoot, "trust-root", "", "Path to the new minisign .pub file")
	cmd.Flags().StringVar(&trustRootURL, "trust-root-url", "", "Download the new trust root from this URL (https, file://, or absolute path)")
	cmd.Flags().StringVar(&fingerprint, "trust-root-fingerprint", "", "Expected key id of the new trust root (hex, as printed by 'polypkg repo key show'); required when not on a TTY")
	cmd.Flags().BoolVar(&resetState, "reset-state", false, "Clear the source's anti-rollback state even when the key is unchanged (requires --trust-root-fingerprint)")
	return cmd
}

func runSourceSetTrustRoot(cmd *cobra.Command, name, trustRoot, trustRootURL, fingerprint string, resetState bool, format Format) error {
	hasTrustRoot := cmd.Flags().Changed("trust-root")
	hasTrustRootURL := cmd.Flags().Changed("trust-root-url")
	if hasTrustRoot && hasTrustRootURL {
		return &CLIError{
			Msg:  "use only one of --trust-root or --trust-root-url",
			Hint: "supply the new trust root either as a local file path (--trust-root) or a URL to download (--trust-root-url), not both",
		}
	}
	if !hasTrustRoot && !hasTrustRootURL {
		return &CLIError{
			Msg:  "a new trust root is required for source set-trust-root",
			Hint: "supply --trust-root <path-to-.pub> or --trust-root-url <url>",
		}
	}
	if resetState && fingerprint == "" {
		return &CLIError{
			Msg:  "--reset-state requires --trust-root-fingerprint",
			Hint: "pass the source's key id (from `polypkg repo key show` on the repository host) with --trust-root-fingerprint",
		}
	}

	profilePath, err := resolveProfilePath(cmd, nil)
	if err != nil {
		return err
	}
	// Held through the anti-rollback reset: an apply running alongside could
	// otherwise store the old floors again after they were cleared.
	p, scope, stateHome, release, err := lockSourceProfile(cmd, profilePath, "source set-trust-root")
	if err != nil {
		return err
	}
	defer release()
	b, ok := p.Sources.Sources[name]
	if !ok {
		known := make([]string, 0, len(p.Sources.Sources))
		for k := range p.Sources.Sources {
			known = append(known, k)
		}
		sort.Strings(known)
		return sourceNotInProfileError(name, known)
	}

	// Resolve the config dir before reading or writing anything, so a failure
	// leaves nothing changed.
	cfgDir, err := scopeConfigDir(scope)
	if err != nil {
		return err
	}

	origin := trustRoot
	var data []byte
	if hasTrustRoot {
		data, err = readTrustRootFile(trustRoot)
	} else {
		// The URL can carry credentials; only the redacted form is shown.
		origin = source.RedactURL(trustRootURL)
		data, err = fetchTrustRootBytes(trustRootURL)
	}
	if err != nil {
		return err
	}
	newKey, err := minisign.DecodePublicKey(string(data))
	if err != nil {
		return &CLIError{
			Msg:  fmt.Sprintf("new trust root %s is not a valid minisign public key", origin),
			Hint: "point at the repository's minisign .pub file (its trust_root.pub)",
			Err:  err,
		}
	}
	newFingerprint := hex.EncodeToString(newKey.KeyId[:])
	if fingerprint != "" {
		if err := matchTrustRootFingerprint(fingerprint, newFingerprint, origin); err != nil {
			return err
		}
	}

	// The old key is shown, not trusted: a missing or corrupt anchor is exactly
	// the state this command repairs, so it degrades to "unreadable".
	oldFingerprint := "unreadable"
	var oldKey minisign.PublicKey
	oldReadable := false
	if oldData, rerr := os.ReadFile(filepath.Clean(b.TrustRoot)); rerr == nil { //nolint:gosec // path comes from the operator's own profile
		if k, derr := minisign.DecodePublicKey(string(oldData)); derr == nil {
			oldKey, oldReadable = k, true
			oldFingerprint = hex.EncodeToString(k.KeyId[:])
		}
	}

	// Keys are compared decoded, in full (algorithm, key id and key bytes), so
	// a re-exported .pub that differs only in its comment or whitespace is the
	// same key: it is left as pinned and, above all, does not clear the
	// anti-rollback state, which only a real key change or --reset-state may.
	changed := !oldReadable || oldKey != newKey
	stateReset := changed || resetState
	trustRootPath := b.TrustRoot
	if changed {
		if fingerprint == "" {
			if err := promptTrustRootChange(cmd, name, origin, oldFingerprint, newFingerprint); err != nil {
				return err
			}
		}
		if trustRootPath, err = repinSourceAnchor(cmd, profilePath, cfgDir, name, b, data); err != nil {
			return err
		}
	}
	if stateReset {
		// Cleared last: if pinning failed, the old floors still guard the old
		// key. A failure here leaves the key pinned behind floors a re-created
		// repository cannot meet, which defeats the command's purpose, so it is
		// an error rather than a warning.
		if err := trust.ForgetSeen(stateHome, name); err != nil {
			return &CLIError{
				Msg:  fmt.Sprintf("could not clear the anti-rollback state of source %q", name),
				Hint: fmt.Sprintf("delete %s by hand; until then fetches still enforce the old serials", filepath.Join(stateHome, "trust", name+".json")),
				Err:  err,
			}
		}
	}

	// JSON carries null for an unreadable old key, so consumers cannot mistake
	// the text placeholder "unreadable" for a key id.
	var oldFingerprintJSON any
	if oldReadable {
		oldFingerprintJSON = oldFingerprint
	}
	EmitResult(cmd, format, "source set-trust-root",
		map[string]any{
			"name":            name,
			"old_fingerprint": oldFingerprintJSON,
			"new_fingerprint": newFingerprint,
			"trust_root":      trustRootPath,
			"changed":         changed,
			"state_reset":     stateReset,
		},
		func(w *bytes.Buffer, _ map[string]any) {
			if !changed {
				fmt.Fprintf(w, "trust root of source %s unchanged (key id %s)\n", name, newFingerprint)
				if stateReset {
					fmt.Fprintf(w, "cleared the anti-rollback state of source %s\n", name)
				}
				return
			}
			fmt.Fprintf(w, "replaced trust root of source %s\n  old key id: %s\n  new key id: %s\n", name, oldFingerprint, newFingerprint)
		})
	return nil
}

// promptTrustRootChange asks the operator on a terminal to approve replacing
// source name's pinned key, showing both key ids. Without a terminal it
// refuses and points at --trust-root-fingerprint.
func promptTrustRootChange(cmd *cobra.Command, name, origin, oldFingerprint, newFingerprint string) error {
	if !isInteractive(cmd) {
		return &CLIError{
			Msg:  fmt.Sprintf("replacing the trust root of source %q needs confirmation but stdin is not a terminal", name),
			Hint: "re-run with --trust-root-fingerprint <key id>, using the key id the publisher printed with `polypkg repo key show`",
		}
	}
	ok, err := confirmTrustRootReplacement(cmd.InOrStdin(), cmd.OutOrStdout(), name, origin, oldFingerprint, newFingerprint)
	if err != nil {
		return err
	}
	if !ok {
		return &CLIError{Msg: "trust root replacement not confirmed (answer was not yes)"}
	}
	return nil
}

// repinSourceAnchor writes data as source name's managed anchor and, when the
// profile entry b records any other path, points the entry at the anchor with
// type and URL unchanged (an update keeps the source's sources.order position).
// If that profile edit fails, the managed file is put back as it was, so the
// profile and the anchor on disk never disagree. Returns the path the profile
// now records.
func repinSourceAnchor(cmd *cobra.Command, profilePath, cfgDir, name string, b schema.SourceBackend, data []byte) (string, error) {
	dest := managedTrustRootPath(cfgDir, name)
	previous, prevErr := os.ReadFile(dest) //nolint:gosec // dest is the managed anchor path under the scope config dir
	if prevErr != nil && !errors.Is(prevErr, fs.ErrNotExist) {
		return "", &CLIError{
			Msg:  fmt.Sprintf("cannot read the trust root pinned at %s", dest),
			Hint: "check the file's permissions",
			Err:  prevErr,
		}
	}
	if _, err := writeManagedTrustRoot(cfgDir, name, data); err != nil {
		return "", err
	}
	if filepath.Clean(b.TrustRoot) == dest {
		return dest, nil
	}
	_, err := profileedit.ApplySourceEdits(profilePath, []profileedit.SourceEdit{{
		Name:      name,
		Type:      b.Type,
		URL:       b.URL,
		TrustRoot: dest,
	}})
	if err == nil {
		return dest, nil
	}
	var restoreErr error
	if prevErr == nil {
		_, restoreErr = writeManagedTrustRoot(cfgDir, name, previous)
	} else if rmErr := os.Remove(dest); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
		restoreErr = rmErr
	}
	if restoreErr != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not restore %s: %v\n", dest, restoreErr)
	}
	return "", &CLIError{Msg: fmt.Sprintf("cannot point source %q at its new trust root in the profile", name), Err: err}
}

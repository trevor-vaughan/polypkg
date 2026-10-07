package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/lock"
	"github.com/trevor-vaughan/polypkg/internal/profileedit"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/trust"
)

func newSourceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "source",
		Short: "Manage package sources and their trust roots",
		Long: `List, add, and remove the package sources in your profile, and replace
their trust roots.

'source add' validates the URL (http(s), file://, or an absolute path) and the
trust root (a local .pub file or a downloaded+confirmed key), then edits the
profile in place while preserving comments. 'source remove' drops a source and
its order entry. 'source set-trust-root' replaces the key a source is pinned
to, after confirmation. 'source list' shows all configured sources in
preference order.`,
		Args: cobra.ArbitraryArgs,
		RunE: requireSubcommand(""),
	}
	// Subcommands are grouped read-vs-write so the safe query is visually
	// separated from the profile-mutating verbs (see AGENTS.md). The table is
	// the single source of truth: each entry registers its group and tags its
	// commands, and slice order drives display order.
	for _, g := range []struct {
		id    string
		title string
		cmds  []*cobra.Command
	}{
		{"inspect", "Inspect:", []*cobra.Command{
			newSourceListCmd(),
		}},
		{"modify", "Modify:", []*cobra.Command{
			newSourceAddCmd(), newSourceRemoveCmd(), newSourceSetTrustRootCmd(),
		}},
	} {
		cmd.AddGroup(&cobra.Group{ID: g.id, Title: g.title})
		for _, c := range g.cmds {
			c.GroupID = g.id
			cmd.AddCommand(c)
		}
	}
	return cmd
}

// newSourceListCmd implements 'polypkg source list'.
func newSourceListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List configured package sources",
		Long: `Print every source in the active profile, in preference order.

Human-readable output shows name, type, URL, and trust-root path for each
source. With --format json the command emits a cli-result/v2 envelope with a
structured 'sources' list and an 'order' array.

Exit 0 when there are no sources configured.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "source list", runSourceList(cmd, format))
		},
	}
	addScopeFlags(cmd)
	return cmd
}

func runSourceList(cmd *cobra.Command, format Format) error {
	profilePath, err := resolveProfilePath(cmd, nil)
	if err != nil {
		return err
	}
	f, err := openProfileFile(cmd, profilePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	p, err := schema.ParseProfile(f, profilePath)
	if err != nil {
		return &CLIError{Msg: fmt.Sprintf("cannot parse profile %s", profilePath), Err: err}
	}

	order := p.Sources.Order
	sources := p.Sources.Sources

	// Build an ordered list of source info maps for JSON output and aligned
	// text rendering.
	type sourceRow struct {
		Name      string
		Type      string
		URL       string
		TrustRoot string
	}
	var rows []sourceRow
	for _, name := range order {
		b, ok := sources[name]
		if !ok {
			continue
		}
		rows = append(rows, sourceRow{
			Name:      name,
			Type:      b.Type,
			URL:       b.URL,
			TrustRoot: b.TrustRoot,
		})
	}
	// Append any sources not in the order list.
	inOrder := make(map[string]bool, len(order))
	for _, n := range order {
		inOrder[n] = true
	}
	var unordered []string
	for name := range sources {
		if !inOrder[name] {
			unordered = append(unordered, name)
		}
	}
	sort.Strings(unordered)
	for _, name := range unordered {
		b := sources[name]
		rows = append(rows, sourceRow{
			Name:      name,
			Type:      b.Type,
			URL:       b.URL,
			TrustRoot: b.TrustRoot,
		})
	}

	// Build the JSON-friendly data shape.
	sourcesData := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		sourcesData = append(sourcesData, map[string]any{
			"name":       r.Name,
			"type":       r.Type,
			"url":        r.URL,
			"trust_root": r.TrustRoot,
		})
	}

	EmitResult(cmd, format, "source list",
		map[string]any{
			"sources": sourcesData,
			"order":   order,
		},
		func(w *bytes.Buffer, _ map[string]any) {
			if len(rows) == 0 {
				fmt.Fprintln(w, "no sources configured")
				return
			}
			// Compute column widths for aligned output.
			nameW, typeW, urlW := len("NAME"), len("TYPE"), len("URL")
			for _, r := range rows {
				if len(r.Name) > nameW {
					nameW = len(r.Name)
				}
				if len(r.Type) > typeW {
					typeW = len(r.Type)
				}
				if len(r.URL) > urlW {
					urlW = len(r.URL)
				}
			}
			// Compute prefix width: widest position number + colon (e.g. "10:"),
			// or "  -" for sources outside the order list.
			prefixW := len(fmt.Sprintf("%d:", len(order)))
			if prefixW < 2 {
				prefixW = 2
			}
			fmt.Fprintf(w, "%-*s  %-*s  %-*s  %-*s  %s\n", prefixW, "#", nameW, "NAME", typeW, "TYPE", urlW, "URL", "TRUST_ROOT")
			for i, r := range rows {
				var prefix string
				if i < len(order) {
					prefix = fmt.Sprintf("%d:", i+1)
				} else {
					prefix = "-"
				}
				fmt.Fprintf(w, "%-*s  %-*s  %-*s  %-*s  %s\n", prefixW, prefix, nameW, r.Name, typeW, r.Type, urlW, r.URL, r.TrustRoot)
			}
		})
	return nil
}

// newSourceAddCmd implements 'polypkg source add <name>'.
func newSourceAddCmd() *cobra.Command {
	var (
		sourceURL    string
		trustRoot    string
		trustRootURL string
		fingerprint  string
		sourceType   string
		orderFirst   bool
	)
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a package source to the profile",
		Long: `Add a named source to the active profile.

The name must not already be in the profile. To change a source's trust root
use 'source set-trust-root'; to change anything else, 'source remove' it and
add it again.

The source URL (--url) must be an http(s) URL, a file:// URL, or an absolute
local path. Exactly one of --trust-root or --trust-root-url is required:

  --trust-root <file>      local minisign .pub file (validated, then copied
                           into the config dir and pinned by content)
  --trust-root-url <url>   download the public key (https, file://, or an
                           absolute path; plain http is refused), confirm it,
                           then persist it

A downloaded key is confirmed by --trust-root-fingerprint <key id>, the id
'polypkg repo key show' prints on the repository host, or else by a prompt on
a TTY that shows the key id (trust on first use). Without a TTY the
fingerprint is required. With --trust-root the fingerprint is optional and, if
given, must match.

The default source type is "polypkg-native". Use --order-first to prepend this
source to the preference list instead of appending it.

Output honors --format json, emitting a cli-result/v2 envelope with the added source fields.`,
		Args: needsArgs(1, 1, "<name>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "source add",
				runSourceAdd(cmd, args[0], sourceURL, trustRoot, trustRootURL, fingerprint, sourceType, orderFirst, format))
		},
	}
	addScopeFlags(cmd)
	cmd.Flags().StringVar(&sourceURL, "url", "", "Source URL: http(s), file://, or an absolute local path (required)")
	cmd.Flags().StringVar(&trustRoot, "trust-root", "", "Path to the source's minisign .pub file")
	cmd.Flags().StringVar(&trustRootURL, "trust-root-url", "", "Download the trust root from this URL (https, file://, or absolute path) and confirm it")
	cmd.Flags().StringVar(&fingerprint, "trust-root-fingerprint", "", "Expected key id of the trust root (hex, as printed by 'polypkg repo key show'); required with --trust-root-url when not on a TTY")
	cmd.Flags().StringVar(&sourceType, "type", "polypkg-native", "Source backend type")
	cmd.Flags().BoolVar(&orderFirst, "order-first", false, "Prepend this source to the preference order instead of appending")
	requireFlags(cmd, "url")
	return cmd
}

// sourceNamePattern is the grammar for source names: the same ^[a-zA-Z0-9_-]+$
// slug the profile schema uses for its other property names. The JSONC edit
// path additionally relies on it (names never contain '/' or '~', so RFC 6901
// pointers need no escaping).
var sourceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// validateSourceName rejects source names that can never be written to a
// profile: the reserved "order" key and anything outside the slug grammar.
// Shared by `source add` and `init --source-name` so both fail fast with the
// same message before any trust root is downloaded.
func validateSourceName(name string) error {
	// "order" is the reserved key for the source preference list under the
	// profile's `sources` map, so a source literally named "order" would collide
	// with it. profileedit.ApplySourceEdits rejects this too (the load-bearing
	// guard); reject it here as well to fail fast with a friendly message before
	// downloading a trust root we would only discard.
	if name == profileedit.ReservedSourceName {
		return &CLIError{
			Msg:  `"order" is a reserved name and cannot be used as a source`,
			Hint: "the profile reserves `order` for the source preference list; choose a different source name",
		}
	}
	if !sourceNamePattern.MatchString(name) {
		return &CLIError{
			Msg:  fmt.Sprintf("source name %q is not a valid slug", name),
			Hint: "source names must match ^[a-zA-Z0-9_-]+$ (e.g. team-mirror)",
		}
	}
	return nil
}

func runSourceAdd(cmd *cobra.Command, name, sourceURL, trustRoot, trustRootURL, fingerprint, sourceType string, orderFirst bool, format Format) error {
	if err := validateSourceName(name); err != nil {
		return err
	}

	// Mutual exclusion: at most one trust-root form.
	hasTrustRoot := cmd.Flags().Changed("trust-root")
	hasTrustRootURL := cmd.Flags().Changed("trust-root-url")

	if hasTrustRoot && hasTrustRootURL {
		return &CLIError{
			Msg:  "use only one of --trust-root or --trust-root-url",
			Hint: "supply the trust root either as a local file path (--trust-root) or a URL to download (--trust-root-url), not both",
		}
	}
	if !hasTrustRoot && !hasTrustRootURL {
		return &CLIError{
			Msg:  "a trust root is required for source add",
			Hint: "supply --trust-root <path-to-.pub> or --trust-root-url <url>",
		}
	}

	normalizedURL, err := normalizeSourceURL(sourceURL)
	if err != nil {
		return err
	}

	profilePath, err := resolveProfilePath(cmd, nil)
	if err != nil {
		return err
	}
	p, scope, _, release, err := lockSourceProfile(cmd, profilePath, "source add")
	if err != nil {
		return err
	}
	defer release()

	// An existing name is refused before any trust root is read or fetched.
	// Re-adding used to update the entry in place, so one `source add` after a
	// repository compromise silently re-anchored the source to the attacker's
	// key; replacing a key is now the explicit job of set-trust-root.
	if _, exists := p.Sources.Sources[name]; exists {
		return sourceExistsError(name)
	}

	// Both routes persist the anchor under the scope config dir and record that
	// copy, so the profile never points at a path someone else could rewrite.
	cfgDir, err := scopeConfigDir(scope)
	if err != nil {
		return err
	}
	// persistTrustRoot accepts an anchor already on disk only when it holds
	// the same key (a leftover from an interrupted add, say). A failed edit
	// must leave such a file alone, so note whether it was there first.
	_, statErr := os.Stat(managedTrustRootPath(cfgDir, name))
	anchorPreExisted := statErr == nil

	var trustRootPath string
	if hasTrustRoot {
		trustRootPath, err = pinTrustRootFile(trustRoot, cfgDir, name, fingerprint)
	} else {
		// --trust-root-url: download and confirm (fingerprint or TOFU prompt)
		// before persisting.
		trustRootPath, err = acquireTrustRoot(cmd, name, trustRootURL, fingerprint, cfgDir)
	}
	if err != nil {
		return err
	}

	// The anchor is written before the profile edit, so a source that never
	// makes it into the profile would leave one behind. Only an anchor this
	// run created is ours to remove.
	discardAnchor := func() {
		if anchorPreExisted {
			return
		}
		if rmErr := os.Remove(trustRootPath); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not remove unused trust root %s: %v\n", trustRootPath, rmErr)
		}
	}

	warning, err := probeSource(cmd, p, name, sourceType, normalizedURL, trustRootPath)
	if err != nil {
		discardAnchor()
		return err
	}
	if warning != "" {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", warning)
	}

	_, err = profileedit.ApplySourceEdits(profilePath, []profileedit.SourceEdit{{
		Name:       name,
		Type:       sourceType,
		URL:        normalizedURL,
		TrustRoot:  trustRootPath,
		OrderFirst: orderFirst,
		// The pre-check above fails fast before any fetch and runs under the
		// apply lock, but a hand edit of the profile does not take the lock,
		// so this repeats the check on the parse that is written back.
		CreateOnly: true,
	}})
	var exists *profileedit.SourceExistsError
	if errors.As(err, &exists) {
		// The name was added after the pre-check. Its entry may point at the
		// same managed path, so the anchor is left alone.
		return sourceExistsError(name)
	}
	if err != nil {
		discardAnchor()
		return &CLIError{Msg: fmt.Sprintf("cannot add source %q to profile", name), Err: err}
	}

	data := map[string]any{
		"name":        name,
		"type":        sourceType,
		"url":         normalizedURL,
		"trust_root":  trustRootPath,
		"order_first": orderFirst,
		"verified":    warning == "",
	}
	if warning != "" {
		data["warning"] = warning
	}
	EmitResult(cmd, format, "source add", data,
		func(w *bytes.Buffer, _ map[string]any) {
			fmt.Fprintf(w, "added source %s\n", name)
		})
	return nil
}

// newSourceRemoveCmd implements 'polypkg source remove <name>'.
func newSourceRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a package source from the profile",
		Long: `Remove the named source from the active profile.

Both the source definition and its entry in the preference order are deleted.
The profile is rewritten in place with comments preserved.

If the source's trust root was downloaded via 'source add --trust-root-url'
(persisted under <config>/trust/<name>.pub), that now-orphaned key is also
deleted, unless another source still references it. A trust root supplied as a
local file (--trust-root) is left untouched.

If the source is not present in the profile a descriptive error is returned
listing the names that are configured.

Output honors --format json, emitting a cli-result/v2 envelope with the removed source name.`,
		Args: needsArgs(1, 1, "<name>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "source remove", runSourceRemove(cmd, args[0], format))
		},
	}
	addScopeFlags(cmd)
	return cmd
}

func runSourceRemove(cmd *cobra.Command, name string, format Format) error {
	profilePath, err := resolveProfilePath(cmd, nil)
	if err != nil {
		return err
	}

	p, _, stateHome, release, err := lockSourceProfile(cmd, profilePath, "source remove")
	if err != nil {
		return err
	}
	defer release()

	// Pre-check: refuse to remove the last source so we never hit the schema
	// minItems:1 violation with a raw jsonschema error.
	if len(p.Sources.Order) == 1 && p.Sources.Order[0] == name {
		return &CLIError{
			Msg:  fmt.Sprintf("cannot remove the last source %q", name),
			Hint: "a profile needs at least one source; add another source first, or edit the profile directly",
		}
	}

	// Decide, from the pre-removal profile, whether removing this source orphans
	// a managed trust-root key we should clean up. Computed before the edit so we
	// can still see the source's trust_root and any other source that shares it.
	orphanKey := managedOrphanTrustRoot(cmd, name, p)

	_, err = profileedit.ApplySourceEdits(profilePath, []profileedit.SourceEdit{{
		Name:   name,
		Remove: true,
	}})
	if err != nil {
		var notIn *profileedit.SourceNotInProfileError
		if errors.As(err, &notIn) {
			return sourceNotInProfileError(name, notIn.Known)
		}
		return &CLIError{Msg: fmt.Sprintf("cannot remove source %q from profile", name), Err: err}
	}

	// Best-effort cleanup of the now-orphaned managed key. The profile edit (the
	// command's real work) has already committed, so a failure here only leaves
	// a stale file behind and must not fail the command — warn instead.
	if orphanKey != "" {
		if rmErr := os.Remove(orphanKey); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not remove orphaned trust root %s: %v\n", orphanKey, rmErr)
		}
	}

	// Clear the source's persisted anti-rollback floors so a later re-add of the
	// same name re-pins from a clean trust-on-first-use baseline (the documented
	// way to accept a legitimately re-created repository). Best-effort: a stale
	// floor file left behind is a latent bug but not fatal to the removal that
	// already succeeded, so warn rather than fail.
	if err := trust.ForgetSeen(stateHome, name); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not clear trust state for source %q: %v\n", name, err)
	}

	EmitResult(cmd, format, "source remove",
		map[string]any{"name": name},
		func(w *bytes.Buffer, _ map[string]any) {
			fmt.Fprintf(w, "removed source %s\n", name)
		})
	return nil

}

// lockSourceProfile takes the apply lock of the scope the command targets,
// failing fast if another command holds it, and returns the profile as parsed
// under the lock together with the resolved scope and state home. The source
// commands edit the profile and the per-source anti-rollback state that a
// running apply reads and writes, so they must not interleave with one. The
// scope is resolved the way apply resolves it, which needs the profile for
// its scopes.<scope>.prefix; the profile is then read again under the lock,
// so every check the caller makes is against the profile it goes on to edit.
// The caller calls release after its last write.
func lockSourceProfile(cmd *cobra.Command, profilePath, command string) (p *schema.Profile, scope, stateHome string, release func(), err error) {
	readProfile := func() (*schema.Profile, error) {
		f, err := openProfileFile(cmd, profilePath)
		if err != nil {
			return nil, err
		}
		p, parseErr := schema.ParseProfile(f, profilePath)
		_ = f.Close()
		if parseErr != nil {
			return nil, &CLIError{Msg: fmt.Sprintf("cannot parse profile %s", profilePath), Err: parseErr}
		}
		return p, nil
	}

	p, err = readProfile()
	if err != nil {
		return nil, "", "", nil, err
	}
	scope, prefix, err := resolveScope(cmd, p)
	if err != nil {
		return nil, "", "", nil, err
	}
	_, stateHome, err = scopeHomes(scope, prefix)
	if err != nil {
		return nil, "", "", nil, err
	}
	if err := os.MkdirAll(stateHome, scopeDirMode(scope)); err != nil {
		return nil, "", "", nil, fmt.Errorf("create state home: %w", err)
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	lockPath := filepath.Join(stateHome, "apply.lock")
	l, err := lock.Acquire(ctx, lockPath, lock.Options{
		TxID:    strings.ReplaceAll(command, " ", "-"),
		Command: "polypkg " + command,
	})
	if err != nil {
		return nil, "", "", nil, lockError(lockPath, err)
	}
	release = func() { _ = l.Release() }

	if p, err = readProfile(); err != nil {
		release()
		return nil, "", "", nil, err
	}
	return p, scope, stateHome, release, nil
}

// sourceExistsError is the user-facing error for `source add` of a name the
// profile already defines.
func sourceExistsError(name string) *CLIError {
	return &CLIError{
		Msg:  fmt.Sprintf("source %q already exists", name),
		Hint: fmt.Sprintf("to change its trust root use `polypkg source set-trust-root %s`; to change anything else, `source remove` then `source add`", name),
	}
}

// sourceNotInProfileError is the user-facing error for a command naming a
// source the profile does not define; known lists the configured names, sorted.
func sourceNotInProfileError(name string, known []string) *CLIError {
	msg := fmt.Sprintf("source %s is not in the profile", name)
	if len(known) > 0 {
		msg = fmt.Sprintf("source %s is not in the profile (configured: %s)", name, strings.Join(known, ", "))
	}
	return &CLIError{Msg: msg, Hint: "run `polypkg source list` to see configured sources"}
}

// managedOrphanTrustRoot returns the absolute path of the trust-root key that
// removing source name would orphan, or "" if nothing should be deleted. A key
// is eligible only when it is this source's canonical managed key
// (<configdir>/trust/<name>.pub, as written by every `source add` route), the
// source actually references that path, and no other source references it. A
// hand-written trust_root pointing outside the managed trust dir, and a key
// shared with another source, are never returned.
func managedOrphanTrustRoot(cmd *cobra.Command, name string, p *schema.Profile) string {
	b, ok := p.Sources.Sources[name]
	if !ok || b.TrustRoot == "" {
		return ""
	}
	scope, _ := cmd.Flags().GetString("scope")
	cfgDir, err := scopeConfigDir(scope)
	if err != nil {
		return ""
	}
	managed := managedTrustRootPath(cfgDir, name)
	if filepath.Clean(b.TrustRoot) != managed {
		return "" // external or non-canonical key; leave it
	}
	for other, ob := range p.Sources.Sources {
		if other == name {
			continue
		}
		if filepath.Clean(ob.TrustRoot) == managed {
			return "" // shared with another source; keep it
		}
	}
	return managed
}

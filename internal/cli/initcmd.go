package cli

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"charm.land/huh/v2"
	"github.com/charmbracelet/x/term"
	"github.com/jedisct1/go-minisign"
	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/paths"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func newInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a polypkg profile for this machine",
		Long: `Create a polypkg profile at the scope's default location.

With --source-url and --trust-root-file the command runs non-interactively.
Without them (on a TTY) it presents a short wizard.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return WrapError(cmd, format, "init", ferr)
			}
			return WrapError(cmd, format, "init", runInit(cmd, format))
		},
	}
	addScopeFlags(cmd)
	cmd.Flags().String("source-url", "", "Repository URL: http(s), file://, or an absolute local path")
	cmd.Flags().String("trust-root-file", "", "Path to the repository's minisign .pub file")
	cmd.Flags().String("trust-root-url", "", "Download the trust root from this URL (http(s), file://, or absolute path) and confirm it interactively")
	cmd.Flags().Bool("trust-root-yes", false, "Trust the downloaded --trust-root-url key without prompting (required when not on a TTY)")
	cmd.Flags().String("source-name", "native", "Source name to record in the profile (must match the name the repository was published under)")
	return cmd
}

// runInit is the init implementation. It selects the flag route when both
// --source-url and --trust-root-file are provided (or stdin is not a TTY),
// and falls back to the interactive wizard when both are absent and both
// stdin and stdout are TTYs.
func runInit(cmd *cobra.Command, format Format) error {
	sourceURL, _ := cmd.Flags().GetString("source-url")
	trustRootFile, _ := cmd.Flags().GetString("trust-root-file")
	trustRootURL, _ := cmd.Flags().GetString("trust-root-url")
	assumeYes, _ := cmd.Flags().GetBool("trust-root-yes")
	scope, _ := cmd.Flags().GetString("scope")
	sourceName, _ := cmd.Flags().GetString("source-name")
	if err := validateSourceName(sourceName); err != nil {
		return err
	}

	// Mutual exclusion: cannot specify both local file and remote URL for trust root.
	if cmd.Flags().Changed("trust-root-file") && cmd.Flags().Changed("trust-root-url") {
		return &CLIError{
			Msg:  "use only one of --trust-root-file or --trust-root-url",
			Hint: "supply the trust root either as a local file path (--trust-root-file) or a URL to download (--trust-root-url), not both",
		}
	}

	flagsProvided := cmd.Flags().Changed("source-url") ||
		cmd.Flags().Changed("trust-root-file") ||
		cmd.Flags().Changed("trust-root-url")

	// Non-interactive: use flag route when running without a TTY, or when any
	// flag is present (partial flags are an error caught below).
	stdinTTY := term.IsTerminal(os.Stdin.Fd())
	stdoutTTY := term.IsTerminal(os.Stdout.Fd())
	interactive := stdinTTY && stdoutTTY && !flagsProvided

	if !interactive {
		if sourceURL == "" || (trustRootFile == "" && trustRootURL == "") {
			return &CLIError{
				Msg:  "init needs --source-url and a trust root when not run interactively",
				Hint: "provide a trust root with --trust-root-file <path> or --trust-root-url <url>; e.g. polypkg init --source-url <url> --trust-root-file <path>",
			}
		}
		normalizedURL, err := normalizeSourceURL(sourceURL)
		if err != nil {
			return err
		}
		cfgDir, err := scopeConfigDir(scope)
		if err != nil {
			return err
		}
		// Fast-fail before downloading if a profile already exists.
		if trustRootURL != "" {
			for _, name := range profileBasenames {
				p := filepath.Join(cfgDir, name)
				if _, statErr := os.Stat(p); statErr == nil {
					return &CLIError{
						Msg:  fmt.Sprintf("profile already exists at %s", p),
						Hint: "edit it directly, or remove it first",
					}
				}
			}
		}
		var absKey string
		if trustRootURL != "" {
			absKey, err = acquireTrustRoot(cmd, sourceName, trustRootURL, assumeYes, cfgDir)
		} else {
			absKey, err = validateAndAbsTrustRoot(trustRootFile)
		}
		if err != nil {
			return err
		}
		written, err := writeInitProfile(cfgDir, sourceName, normalizedURL, absKey, scope)
		if err != nil {
			return err
		}
		return emitInitResult(cmd, format, written)
	}

	// Interactive wizard path.
	return runInitWizard(cmd, format, scope)
}

// runInitWizard presents a huh form and then calls the shared write path.
func runInitWizard(cmd *cobra.Command, format Format, scope string) error {
	var (
		scopeVal     = scope
		sourceURLVal string
		trustRootVal string
	)

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Scope").
				Description("'system' scope installs machine-wide and requires root.").
				Options(
					huh.NewOption("user (no root needed)", "user"),
					huh.NewOption("system (requires root)", "system"),
				).
				Value(&scopeVal),
			huh.NewInput().
				Title("Source URL").
				Description("http(s) URL, file:// URL, or absolute local path to your package repository.").
				Value(&sourceURLVal).
				Validate(validateSourceURL),
			huh.NewInput().
				Title("Trust root").
				Description("Path to the repo's minisign .pub file, OR paste the key material directly.").
				Value(&trustRootVal),
		),
	)

	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return &CLIError{Msg: "init cancelled"}
		}
		return err
	}

	// If the trust root input is a file path (not pasted key material),
	// validate and resolve it to an absolute path before the write path.
	trustRootResolved := strings.TrimSpace(trustRootVal)
	if !strings.HasPrefix(trustRootResolved, "untrusted comment:") {
		abs, verr := validateAndAbsTrustRoot(trustRootResolved)
		if verr != nil {
			return verr
		}
		trustRootResolved = abs
	}

	normalizedURL, err := normalizeSourceURL(sourceURLVal)
	if err != nil {
		// Defensive: the huh validator already ran normalizeSourceURL, but
		// normalize is the source of truth for what gets persisted.
		return err
	}

	cfgDir, err := scopeConfigDir(scopeVal)
	if err != nil {
		return err
	}
	// writeInitProfile handles both pasted key material and file paths.
	// The wizard always records the default source name; --source-name is a
	// flag-route affordance.
	written, err := writeInitProfile(cfgDir, "native", normalizedURL, trustRootResolved, scopeVal)
	if err != nil {
		return err
	}
	return emitInitResult(cmd, format, written)
}

// writeInitProfile is the shared write path: given cfgDir, a source name, a
// source URL, and the trust-root value (either an absolute path or raw key
// material prefixed with "untrusted comment:"), it:
//   - Checks for an existing profile.{yaml,yml,jsonc,json} FIRST (fast-fail).
//   - Validates pasted key material before writing it to
//     cfgDir/trust/<sourceName>.pub (0o600).
//   - Writes the rendered template to cfgDir/profile.yaml.
//
// sourceName is validated upstream (validateSourceName; the wizard passes the
// literal "native"). scope controls the config dir permission on creation
// (0o700 user / 0o755 system). Returns the path written.
func writeInitProfile(cfgDir, sourceName, sourceURL, trustRootInput, scope string) (string, error) {
	// Check for existing profile BEFORE writing any files so that a
	// conflict never leaves a stray key file on disk.
	for _, name := range profileBasenames {
		p := filepath.Join(cfgDir, name)
		if _, err := os.Stat(p); err == nil {
			return "", &CLIError{
				Msg:  fmt.Sprintf("profile already exists at %s", p),
				Hint: "edit it directly, or remove it first",
			}
		}
	}

	// Resolve the trust root: pasted key material or file path.
	var trustRootPath string
	if strings.HasPrefix(strings.TrimSpace(trustRootInput), "untrusted comment:") {
		// Validate the pasted material before touching the filesystem.
		if _, err := minisign.DecodePublicKey(strings.TrimSpace(trustRootInput)); err != nil {
			return "", &CLIError{
				Msg:  "the pasted key is not a valid minisign public key",
				Hint: "trust_root must point at the repository's minisign .pub file",
				Err:  err,
			}
		}
		// trust/ uses 0o700: the key store holds sensitive material and its
		// permissions must be restrictive in both user and system scope.
		trustDir := filepath.Join(cfgDir, "trust")
		if err := os.MkdirAll(trustDir, 0o700); err != nil {
			return "", fmt.Errorf("create trust dir: %w", err)
		}
		keyPath := filepath.Join(trustDir, sourceName+".pub")
		if err := os.WriteFile(keyPath, []byte(trustRootInput), 0o600); err != nil {
			return "", fmt.Errorf("write key file: %w", err)
		}
		trustRootPath = keyPath
	} else {
		trustRootPath = trustRootInput
	}

	// Create the config dir if needed.
	dirMode := scopeDirMode(scope)
	if err := os.MkdirAll(cfgDir, dirMode); err != nil {
		return "", &CLIError{
			Msg: fmt.Sprintf("cannot create config dir %s: %s", cfgDir, err),
			Err: err,
		}
	}

	hostname, _ := os.Hostname()
	rendered := fillProfileTemplate(hostname, sourceName, sourceURL, trustRootPath, scope)

	destPath := filepath.Join(cfgDir, "profile.yaml")
	if err := os.WriteFile(destPath, []byte(rendered), 0o600); err != nil {
		return "", &CLIError{
			Msg: fmt.Sprintf("cannot write profile to %s: %s", destPath, err),
			Err: err,
		}
	}

	// Validate the written profile so we catch template bugs early.
	if _, perr := schema.ParseProfile(strings.NewReader(rendered), destPath); perr != nil {
		// Remove the invalid file to avoid leaving garbage.
		_ = os.Remove(destPath)
		return "", &CLIError{
			Msg: fmt.Sprintf("generated profile failed schema validation: %s", perr),
			Err: perr,
		}
	}

	return destPath, nil
}

// emitInitResult writes the success output (text or JSON).
func emitInitResult(cmd *cobra.Command, format Format, writtenPath string) error {
	EmitResult(cmd, format, "init", map[string]any{
		"path": writtenPath,
	}, func(w *bytes.Buffer, _ map[string]any) {
		fmt.Fprint(w, formatQuickstart(writtenPath))
	})
	return nil
}

// scopeConfigDir returns the config directory for the given scope.
func scopeConfigDir(scope string) (string, error) {
	if scope == "system" {
		return paths.SystemConfigDir(), nil
	}
	return paths.UserConfigHome()
}

// normalizeSourceURL validates a source URL and returns the canonical form to
// persist. Accepts http(s) URLs (host required), file:// URLs with an absolute
// path, and absolute local paths (~ expanded). Bare absolute paths and ~-paths
// are canonicalized to file:// URIs so the written profile passes the schema's
// "format: uri" constraint. Relative paths are rejected.
func normalizeSourceURL(s string) (string, error) {
	if s == "" || strings.ContainsAny(s, " \t\n") {
		return "", &CLIError{
			Msg:  fmt.Sprintf("invalid --source-url %q", s),
			Hint: "use an http(s) URL, a file:// URL, or an absolute local path",
		}
	}
	// Expand a leading ~ or ~/ to the user's home directory.
	if s == "~" || strings.HasPrefix(s, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", &CLIError{
				Msg: "cannot expand ~ in --source-url",
				Err: err,
			}
		}
		s = filepath.Join(home, strings.TrimPrefix(s[1:], "/"))
	}
	// Bare absolute path — canonicalize to a file:// URI so the profile's
	// "format: uri" schema constraint is satisfied.
	if strings.HasPrefix(s, "/") {
		return "file://" + s, nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", &CLIError{
			Msg:  fmt.Sprintf("invalid --source-url %q", s),
			Hint: "use an http(s) URL, a file:// URL, or an absolute local path",
		}
	}
	switch u.Scheme {
	case "http", "https":
		if u.Host == "" {
			return "", &CLIError{
				Msg:  fmt.Sprintf("invalid --source-url %q (missing host)", s),
				Hint: "e.g. https://repo.example.com/polypkg",
			}
		}
		return s, nil
	case "file":
		if u.Host != "" && u.Host != "localhost" {
			return "", &CLIError{
				Msg:  fmt.Sprintf("invalid file URL %q (must not have a host)", s),
				Hint: "use file:// with an absolute local path, e.g. file:///srv/polypkg/public",
			}
		}
		if u.Path == "" || !filepath.IsAbs(u.Path) {
			return "", &CLIError{
				Msg:  fmt.Sprintf("invalid file URL %q", s),
				Hint: "use file:// with an absolute path, e.g. file:///srv/polypkg/public",
			}
		}
		return s, nil
	default:
		return "", &CLIError{
			Msg:  fmt.Sprintf("invalid --source-url %q", s),
			Hint: "use an http(s) URL, a file:// URL, or an absolute local path",
		}
	}
}

// validateSourceURL is a thin wrapper around normalizeSourceURL that satisfies
// the func(string) error signature required by huh form validators.
func validateSourceURL(s string) error {
	_, err := normalizeSourceURL(s)
	return err
}

// validateAndAbsTrustRoot reads the file at path, checks that it is a valid
// minisign public key, and returns the absolute path. Returns a CLIError on
// any failure.
func validateAndAbsTrustRoot(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", &CLIError{
			Msg: fmt.Sprintf("trust_root %q: cannot resolve path", path),
			Err: err,
		}
	}
	data, err := os.ReadFile(abs) //nolint:gosec // path is resolved from user-supplied --trust-root-file and sanitized to absolute
	if err != nil {
		return "", &CLIError{
			Msg:  fmt.Sprintf("trust_root %s is not a valid minisign public key", path),
			Hint: "trust_root must point at the repository's minisign .pub file",
			Err:  err,
		}
	}
	if _, err := minisign.DecodePublicKey(string(data)); err != nil {
		return "", &CLIError{
			Msg:  fmt.Sprintf("trust_root %s is not a valid minisign public key", path),
			Hint: "trust_root must point at the repository's minisign .pub file",
			Err:  err,
		}
	}
	return abs, nil
}

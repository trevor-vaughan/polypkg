package cli

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/trevor-vaughan/polypkg/internal/config"
	"github.com/trevor-vaughan/polypkg/internal/paths"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

// addScopeFlags registers the shared --scope/--prefix flags on a scope-aware
// command (apply, plan). --scope selects user or system; --prefix redirects
// every system-scope write under a DESTDIR root (system scope only).
func addScopeFlags(cmd *cobra.Command) {
	cmd.Flags().String("scope", "user", "Scope to apply: user or system")
	cmd.Flags().String("prefix", "", "System-scope DESTDIR prefix; redirects every system write under <prefix> (system scope only)")
	_ = cmd.RegisterFlagCompletionFunc("scope", completeStatic("user", "system"))
}

// resolveScope reads --scope/--prefix from cmd and resolves the effective prefix
// for a system apply by precedence: --prefix flag > POLYPKG_SYSTEM_PREFIX env >
// the profile's scopes.<scope>.prefix > empty (real FHS). A prefix is meaningful
// for system scope only; supplying --prefix with --scope user is an error
// (fail-closed, no silent no-op). An unknown scope is an error.
func resolveScope(cmd *cobra.Command, p *schema.Profile) (scope, prefix string, err error) {
	scope, _ = cmd.Flags().GetString("scope")
	if scope != "user" && scope != "system" {
		return "", "", &CLIError{
			Msg:  fmt.Sprintf("invalid --scope %q", scope),
			Hint: "expected user or system",
		}
	}
	prefixChanged := cmd.Flags().Changed("prefix")
	prefixFlag, _ := cmd.Flags().GetString("prefix")
	if scope == "user" {
		if prefixChanged {
			return "", "", &CLIError{
				Msg:  "--prefix applies only to --scope system",
				Hint: "drop --prefix, or pass --scope system",
			}
		}
		return "user", "", nil
	}
	switch {
	case prefixChanged:
		prefix = prefixFlag
	case os.Getenv("POLYPKG_SYSTEM_PREFIX") != "":
		prefix = os.Getenv("POLYPKG_SYSTEM_PREFIX")
	default:
		if sp, ok := p.Scopes[scope]; ok {
			prefix = sp.Prefix
		}
	}
	return "system", prefix, nil
}

// scopeHomes resolves the substrate data home and state home for a scope,
// applying prefix (system scope only). prefix must be empty for user scope.
// For system scope a path P resolves to filepath.Join(prefix, P): an empty
// prefix yields the real FHS path, a non-empty prefix a DESTDIR-relative one.
func scopeHomes(scope, prefix string) (dataHome, stateHome string, err error) {
	// Unreachable via resolveScope (which validates scope and rejects user-scope
	// prefix first); kept as a defensive contract guard and exercised directly by tests.
	switch scope {
	case "user":
		if prefix != "" {
			return "", "", &CLIError{
				Msg:  "--prefix applies only to --scope system",
				Hint: "drop --prefix, or pass --scope system",
			}
		}
		dataHome, err = paths.UserDataHome()
		if err != nil {
			return "", "", fmt.Errorf("resolve data home: %w", err)
		}
		stateHome, err = paths.UserStateHome()
		if err != nil {
			return "", "", fmt.Errorf("resolve state home: %w", err)
		}
		return dataHome, stateHome, nil
	case "system":
		return filepath.Join(prefix, paths.SystemDataDir()),
			filepath.Join(prefix, paths.SystemStateDir()), nil
	default:
		return "", "", &CLIError{
			Msg:  fmt.Sprintf("invalid --scope %q", scope),
			Hint: "expected user or system",
		}
	}
}

// openUserStore opens the user-scope "store" substrate and returns it together
// with the user state home (where the apply lock lives). It is the shared
// data-home/state-home/substrate preamble for the non-scope-aware commands
// (purge, config reset, accept-drift); scope-aware commands (apply, plan) use
// scopeHomes and substrate.New directly so they can honor --scope/--prefix.
func openUserStore() (substrate.Substrate, string, error) {
	dataHome, stateHome, err := scopeHomes("user", "")
	if err != nil {
		return nil, "", err
	}
	sub, err := substrate.New("store", dataHome)
	if err != nil {
		return nil, "", fmt.Errorf("open substrate: %w", err)
	}
	return sub, stateHome, nil
}

// scopeDirMode is the directory-creation mode for a scope's substrate and state
// trees: 0o755 for system (multi-user traversable) and 0o700 for user
// (private). It governs the apply/plan pre-create of the scoped homes, the
// substrate's WithDirMode option, and the runner's action DirMode.
func scopeDirMode(scope string) os.FileMode {
	if scope == "system" {
		return 0o755
	}
	return 0o700
}

// scopeNames returns the sorted scope names defined in p, for use in error
// messages. Returns "(none)" when the profile defines no scopes.
func scopeNames(p *schema.Profile) []string {
	return slices.Sorted(maps.Keys(p.Scopes))
}

// scopeNamesStr is the comma-joined form of scopeNames, for inline messages.
func scopeNamesStr(p *schema.Profile) string {
	names := scopeNames(p)
	if len(names) == 0 {
		return "(none)"
	}
	return strings.Join(names, ", ")
}

// scopeConfigEnabled reports whether a host-integration feature (key, e.g.
// "bridge.enabled") is enabled for the scope. The gate is read from the
// scope-appropriate config dir — user: ~/.config/polypkg; system:
// <prefix>/etc/polypkg — with POLYPKG_<KEY> env overrides. A missing config dir
// yields the gate's default (true), so a fresh prefix / a host without
// /etc/polypkg is default-on, consistent with user scope.
func scopeConfigEnabled(scope, prefix, key string) (bool, error) {
	var configDir string
	if scope == "system" {
		configDir = filepath.Join(prefix, paths.SystemConfigDir())
	} else {
		h, err := paths.UserConfigHome()
		if err != nil {
			return false, err
		}
		configDir = h
	}
	v, err := config.Load(config.Options{ConfigPaths: []string{configDir}, EnvPrefix: "POLYPKG"})
	if err != nil {
		return false, err
	}
	return v.GetBool(key), nil
}

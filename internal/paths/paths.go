// Package paths resolves polypkg's data, config, and state directories
// across *NIX platforms using XDG conventions on Linux/BSD and
// platform-native conventions on macOS (with XDG honored if set).
package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const appName = "polypkg"

// xdgUserDir resolves a per-user, app-scoped XDG directory. When env is set to
// an absolute path it is honored as the base and appName is appended;
// otherwise the home dir is joined with darwinParts on macOS or defaultParts
// elsewhere (each already including the appName segment).
func xdgUserDir(env string, darwinParts, defaultParts []string) (string, error) {
	if x := os.Getenv(env); x != "" && filepath.IsAbs(x) {
		return filepath.Join(x, appName), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, filepath.Join(darwinParts...)), nil
	}
	return filepath.Join(home, filepath.Join(defaultParts...)), nil
}

// UserDataHome returns the per-user data directory.
func UserDataHome() (string, error) {
	return xdgUserDir("XDG_DATA_HOME",
		[]string{"Library", "Application Support", appName},
		[]string{".local", "share", appName})
}

// UserStateHome returns the per-user state directory.
func UserStateHome() (string, error) {
	return xdgUserDir("XDG_STATE_HOME",
		[]string{"Library", "Application Support", appName, "state"},
		[]string{".local", "state", appName})
}

// UserConfigHome returns the per-user config directory.
func UserConfigHome() (string, error) {
	return xdgUserDir("XDG_CONFIG_HOME",
		[]string{"Library", "Preferences", appName},
		[]string{".config", appName})
}

// UserCacheHome returns the per-user cache directory: data polypkg can fetch
// again at any time, such as Sigstore's TUF metadata.
func UserCacheHome() (string, error) {
	return xdgUserDir("XDG_CACHE_HOME",
		[]string{"Library", "Caches", appName},
		[]string{".cache", appName})
}

// UserBinHome returns the directory polypkg links commands into so they land on
// the user's $PATH. It honors $XDG_BIN_HOME when absolute (an emerging
// convention), otherwise ~/.local/bin — the cross-platform user bin directory
// modern Linux already places on $PATH. There is no macOS-native equivalent, so
// ~/.local/bin is used there too.
func UserBinHome() (string, error) {
	return xdgBase("XDG_BIN_HOME", ".local", "bin")
}

// xdgBase resolves an XDG base directory with no appName suffix: $env when set
// to an absolute path, otherwise the home dir joined with defaultParts.
func xdgBase(env string, defaultParts ...string) (string, error) {
	if x := os.Getenv(env); x != "" && filepath.IsAbs(x) {
		return x, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, filepath.Join(defaultParts...)), nil
}

// xdgDataBase returns $XDG_DATA_HOME when absolute, else the platform default
// data base (no appName suffix — callers append shell-specific conventions).
func xdgDataBase() (string, error) {
	return xdgBase("XDG_DATA_HOME", ".local", "share")
}

// xdgConfigBase returns $XDG_CONFIG_HOME when absolute, else ~/.config.
func xdgConfigBase() (string, error) {
	return xdgBase("XDG_CONFIG_HOME", ".config")
}

// UserApplicationsDir is the user's desktop-entry dir, auto-discovered by the
// desktop environment (no polypkg subdir).
func UserApplicationsDir() (string, error) {
	base, err := xdgDataBase()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "applications"), nil
}

// UserMimePackagesDir is the user's shared-mime-info packages dir
// (${XDG_DATA_HOME}/mime/packages); update-mime-database compiles the .xml
// files here into the user's MIME caches.
func UserMimePackagesDir() (string, error) {
	base, err := xdgDataBase()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "mime", "packages"), nil
}

// UserBashCompletionDir is bash-completion's user dir, auto-loaded on demand.
func UserBashCompletionDir() (string, error) {
	base, err := xdgDataBase()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "bash-completion", "completions"), nil
}

// UserZshCompletionDir is a user site-functions dir; the user must add it to
// $fpath before compinit (polypkg nudges).
func UserZshCompletionDir() (string, error) {
	base, err := xdgDataBase()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "zsh", "site-functions"), nil
}

// UserFishCompletionDir is fish's user completions dir, auto-loaded.
func UserFishCompletionDir() (string, error) {
	base, err := xdgConfigBase()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "fish", "completions"), nil
}

// SystemDataDir returns the system-wide data directory.
func SystemDataDir() string { return "/var/lib/" + appName }

// SystemConfigDir returns the system-wide config directory.
func SystemConfigDir() string { return "/etc/" + appName }

// SystemStateDir returns the system-wide state directory.
func SystemStateDir() string { return "/var/lib/" + appName }

// SystemBinDir is the system-wide command dir polypkg links into for a system
// install. /usr/local/bin is on every user's $PATH and is reserved (FHS) for
// software installed by the local administrator, distinct from distro-owned /usr.
func SystemBinDir() string { return "/usr/local/bin" }

// SystemApplicationsDir is the system-wide desktop-entry dir (on $XDG_DATA_DIRS
// via /usr/local/share), auto-discovered by desktop environments.
func SystemApplicationsDir() string { return "/usr/local/share/applications" }

// SystemMimePackagesDir is the system-wide shared-mime-info packages dir;
// update-mime-database /usr/local/share/mime compiles the .xml files here.
func SystemMimePackagesDir() string { return "/usr/local/share/mime/packages" }

// SystemBashCompletionDir is bash-completion's system dir, auto-loaded on demand.
func SystemBashCompletionDir() string { return "/usr/local/share/bash-completion/completions" }

// SystemZshCompletionDir is the system zsh site-functions dir (on the default
// $fpath for a /usr/local install).
func SystemZshCompletionDir() string { return "/usr/local/share/zsh/site-functions" }

// SystemFishCompletionDir is fish's system vendor completions dir, auto-loaded.
func SystemFishCompletionDir() string { return "/usr/local/share/fish/vendor_completions.d" }

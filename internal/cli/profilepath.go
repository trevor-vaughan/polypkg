package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/paths"
)

// profileBasenames is the default-profile search order in a scope's config
// dir. profile.yaml is listed first; it is the canonical name.
var profileBasenames = []string{"profile.yaml", "profile.yml", "profile.jsonc", "profile.json"}

// resolveProfilePath picks the profile a command operates on, by
// precedence: explicit positional arg > POLYPKG_PROFILE > the first
// existing profile.{yaml,yml,jsonc,json} under the scope's config dir
// (user: XDG config home; system: /etc/polypkg — the spec'd fixed
// locations; --prefix is a profile-declared DESTDIR and deliberately does
// not relocate profile discovery).
func resolveProfilePath(cmd *cobra.Command, args []string) (string, error) {
	if len(args) == 1 {
		return args[0], nil
	}
	if p := os.Getenv("POLYPKG_PROFILE"); p != "" {
		return p, nil
	}
	scope, _ := cmd.Flags().GetString("scope")
	var dir string
	if scope == "system" {
		dir = paths.SystemConfigDir()
	} else {
		var err error
		dir, err = paths.UserConfigHome()
		if err != nil {
			return "", &CLIError{Msg: "cannot resolve your config directory", Err: err}
		}
	}
	for _, name := range profileBasenames {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", &CLIError{
		Msg:  fmt.Sprintf("no profile found at %s", filepath.Join(dir, "profile.yaml")),
		Hint: fmt.Sprintf("run `polypkg init` to create a profile, or pass a path: %s <profile-file>", cmd.CommandPath()),
	}
}

// openProfileFile stats profilePath and opens it, returning a shaped CLIError
// if the path is a directory, does not exist, lacks permission, or cannot be
// opened for any other reason. On success the caller is responsible for
// closing the returned file.
//
// This is the preferred call site for profile opens; it detects the directory
// case (os.Open succeeds on directories; the error only surfaces later) via an
// explicit Stat before Open.
func openProfileFile(cmd *cobra.Command, profilePath string) (*os.File, error) {
	clean := filepath.Clean(profilePath)
	fi, serr := os.Stat(clean)
	if serr == nil && fi.IsDir() {
		return nil, openProfileError(cmd, profilePath, syscall.EISDIR)
	}
	f, err := os.Open(clean)
	if err != nil {
		return nil, openProfileError(cmd, profilePath, err)
	}
	return f, nil
}

// openProfileError converts an os.Open error (or a pre-open stat error) into
// a user-facing *CLIError that names the file and suggests a next step.
// Internal context wraps (unlikely from os.Open) are preserved in Err for
// logging; this function is only called for user-caused open failures.
//
// Callers should stat the path before calling os.Open and pass syscall.EISDIR
// when the path is a directory, since os.Open succeeds on directories and the
// is-a-directory condition only surfaces at the read step.
func openProfileError(cmd *cobra.Command, profilePath string, err error) error {
	switch {
	case errors.Is(err, syscall.EISDIR):
		return &CLIError{
			Msg:  fmt.Sprintf("%s is a directory, not a profile file", profilePath),
			Hint: fmt.Sprintf("pass the profile file itself: %s <profile-file>", cmd.CommandPath()),
			Err:  err,
		}
	case errors.Is(err, fs.ErrNotExist):
		return &CLIError{
			Msg:  fmt.Sprintf("profile %s does not exist", profilePath),
			Hint: fmt.Sprintf("run `polypkg init` to create a profile, or pass a path: %s <profile-file>", cmd.CommandPath()),
			Err:  err,
		}
	case errors.Is(err, fs.ErrPermission):
		return &CLIError{
			Msg:  fmt.Sprintf("cannot read profile %s: permission denied", profilePath),
			Hint: "check the file's permissions, or use --scope user with a profile you own",
			Err:  err,
		}
	default:
		return &CLIError{Msg: fmt.Sprintf("cannot open profile %s", profilePath), Err: err}
	}
}

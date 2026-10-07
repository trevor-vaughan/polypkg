package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/lock"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage operator-mutable config files",
		Long: `polypkg tracks every config file a package ships and records its drift policy.
Config-policy files with a preserve policy are operator-mutable: local edits
are kept across applies. Replace-policy files are overwritten on each apply
(the package's canonical content always wins).

The reset subcommand queues a preserve-policy config file for restore to its
package default on the next apply.`,
		Args: cobra.ArbitraryArgs,
		RunE: requireSubcommand(""),
	}
	cmd.AddCommand(newConfigResetCmd())
	return cmd
}

func newConfigResetCmd() *cobra.Command {
	var pkg string
	var yes bool
	cmd := &cobra.Command{
		Use:   "reset [path]",
		Short: "Queue a config file (or all configs of a package) for restore to package default on the next apply",
		Long: "Queues one or more config-policy paths in the state-home pending-resets file. " +
			"The next apply discards local edits and writes the package's canonical content. " +
			"Specify a single <path>, or --package <pkg> to reset every config file the package owns.",
		Example: "  # Reset one config file to the package default on next apply\n" +
			"  polypkg config reset /etc/foo/foo.conf\n\n" +
			"  # Reset every config file owned by a package, no prompt\n" +
			"  polypkg config reset --package foo --yes",
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: completeConfigResetPaths,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "config reset", runConfigReset(cmd, args, pkg, yes, format))
		},
	}
	cmd.Flags().StringVar(&pkg, "package", "", "Reset every config file owned by this package (instead of a single path)")
	cmd.Flags().BoolVar(&yes, "yes", false, "Skip the confirmation prompt (required in non-interactive sessions)")
	_ = cmd.RegisterFlagCompletionFunc("package", completePackages)
	return cmd
}

func runConfigReset(cmd *cobra.Command, args []string, pkg string, yes bool, format Format) error {
	ctx := cmd.Context()
	if len(args) == 0 && pkg == "" {
		return &CLIError{
			Msg:  "config reset needs a target",
			Hint: "pass a file path (polypkg config reset /path/to/file) or --package <pkg> to reset all of a package's config files",
		}
	}
	sub, stateHome, err := openUserStore()
	if err != nil {
		return err
	}
	lockPath := filepath.Join(stateHome, "apply.lock")
	l, err := lock.Acquire(ctx, lockPath,
		lock.Options{TxID: "config-reset", Command: "polypkg config reset"})
	if err != nil {
		return lockError(lockPath, err)
	}
	defer func() { _ = l.Release() }()

	prior, _, _, err := sub.CurrentOwnership()
	if err != nil {
		return &CLIError{
			Msg:  "no generation has been applied yet",
			Hint: "run `polypkg apply` first",
			Err:  err,
		}
	}
	targets, err := resolveResetPaths(prior, args, pkg)
	if err != nil {
		return err
	}

	if !yes {
		if !isInteractive(cmd) {
			return &CLIError{
				Msg:  "config reset needs confirmation but stdin is not a terminal",
				Hint: "re-run with --yes to confirm non-interactively",
			}
		}
		ok, err := confirmReset(cmd.InOrStdin(), cmd.OutOrStdout(), strings.Join(targets, ", "))
		if err != nil {
			return err
		}
		if !ok {
			return &CLIError{Msg: "config reset aborted (answer was not yes)"}
		}
	}

	outPath := filepath.Join(stateHome, "pending-resets.json")
	if err := writePendingResets(outPath, prior.Scope, targets); err != nil {
		return err
	}
	EmitResult(cmd, format, "config reset", map[string]any{"paths_queued": len(targets)},
		func(w *bytes.Buffer, d map[string]any) {
			fmt.Fprintf(w, "queued %d config path(s) for reset on next apply\n", d["paths_queued"])
		})
	return nil
}

// isResettableConfig reports whether an entry is a config file eligible for
// `config reset` (a config action under a preserve policy).
func isResettableConfig(e schema.OwnershipEntry) bool {
	return e.Action == "config" && e.DriftPolicy == "notify_preserve"
}

// resettableConfigPaths returns the sorted paths eligible for `config reset`.
func resettableConfigPaths(entries []schema.OwnershipEntry) []string {
	var out []string
	for i := range entries {
		if isResettableConfig(entries[i]) {
			out = append(out, entries[i].Path)
		}
	}
	sort.Strings(out)
	return out
}

// pkgNames returns the sorted, distinct package names in entries.
func pkgNames(entries []schema.OwnershipEntry) []string {
	set := map[string]bool{}
	for i := range entries {
		if entries[i].Package != "" {
			set[entries[i].Package] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// resolveResetPaths validates the requested paths (or derives all of a package's
// config paths) against the prior ownership index. Each target must be a config
// action with notify_preserve drift policy (preserve / preserve_warn /
// three_way_merge); replace-policy configs are rejected (already overwritten).
func resolveResetPaths(prior *schema.Ownership, args []string, pkg string) ([]string, error) {
	byPath := map[string]schema.OwnershipEntry{}
	for i := range prior.Entries {
		byPath[prior.Entries[i].Path] = prior.Entries[i]
	}
	validate := func(p string) error {
		e, ok := byPath[p]
		if !ok {
			return &CLIError{
				Msg:  fmt.Sprintf("%s not found in current generation ownership", p),
				Hint: "run `polypkg status -vv` to list managed paths",
			}
		}
		if e.Action != "config" {
			return &CLIError{
				Msg:  fmt.Sprintf("%s is not a config action (action=%s)", p, e.Action),
				Hint: "reset only applies to config-policy files",
			}
		}
		if e.DriftPolicy != "notify_preserve" {
			return &CLIError{
				Msg: fmt.Sprintf("%s uses replace policy; user edits are already overwritten on each apply", p),
			}
		}
		if pkg != "" && e.Package != pkg {
			return &CLIError{
				Msg: fmt.Sprintf("%s is owned by %s, not %s", p, e.Package, pkg),
			}
		}
		return nil
	}

	if len(args) == 1 {
		if err := validate(args[0]); err != nil {
			return nil, err
		}
		return []string{args[0]}, nil
	}
	// Bulk by package.
	var out []string
	for i := range prior.Entries {
		e := &prior.Entries[i]
		if e.Package == pkg && isResettableConfig(*e) {
			out = append(out, e.Path)
		}
	}
	if len(out) == 0 {
		return nil, &CLIError{
			Msg:  fmt.Sprintf("no resettable config files owned by %s", pkg),
			Hint: "run `polypkg status -vv` to list managed config files",
		}
	}
	sort.Strings(out)
	return out, nil
}

// writePendingResets merges targets into the queue at path (set semantics),
// keyed to scope, via atomic temp+rename at mode 0o600.
func writePendingResets(path, scope string, targets []string) error {
	set := map[string]bool{}
	if existing, err := readPendingResets(path); err == nil && existing != nil && existing.Scope == scope {
		for _, p := range existing.Paths {
			set[p] = true
		}
	}
	for _, p := range targets {
		set[p] = true
	}
	merged := make([]string, 0, len(set))
	for p := range set {
		merged = append(merged, p)
	}
	sort.Strings(merged)

	rec := &schema.Resets{Schema: "polypkg.resets/v1", Scope: scope, Paths: merged}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal resets: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	return os.Rename(tmp, path)
}

func readPendingResets(path string) (*schema.Resets, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	rs, err := schema.ParseResets(f)
	return rs, schema.WithPath(err, path)
}

// confirmReset prompts on out and reads a y/N answer from in. Only "y"/"Y"
// confirms. Extracted for direct testing (TTY is unavailable under test).
func confirmReset(in io.Reader, out io.Writer, target string) (bool, error) {
	fmt.Fprintf(out, "Reset %s to package default on next apply?\nThis will discard any local edits to the file.\nProceed? [y/N]: ", target)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	line = strings.TrimSpace(line)
	return line == "y" || line == "Y", nil
}

// isInteractive reports whether the command's stdin is a character device (TTY).
func isInteractive(cmd *cobra.Command) bool {
	f, ok := cmd.InOrStdin().(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

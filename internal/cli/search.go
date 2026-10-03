package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"charm.land/huh/v2"
	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/planner"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

func newSearchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "search <term>",
		Short: "Search the configured sources for packages",
		Long: `Fetches the catalog and returns every package whose name contains the search
term (case-insensitive). When run on an interactive terminal, a multi-select
picker lets you install packages directly from the results.`,
		Example: "  # Find all packages whose name contains \"editor\"\n" +
			"  polypkg search editor",
		Args: needsArgs(1, 1, "<term>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "search", runSearch(cmd, args[0], format))
		},
	}
	addScopeFlags(cmd)
	return cmd
}

// searchMatch is one result row from the search command.
type searchMatch struct {
	Name      string
	Versions  []string
	Installed string // empty when the package is not installed
}

// runSearch implements the search command.
func runSearch(cmd *cobra.Command, term string, format Format) error {
	p := bestEffortProfile(cmd)
	scope, dataHome, stateHome, err := resolveListScope(cmd, p)
	if err != nil {
		return err
	}

	// Read the current generation's manifest for installed markers.
	// Missing generation is tolerated — no markers, no error.
	var manifest *schema.Manifest
	sub, serr := substrate.New("store", dataHome)
	if serr == nil {
		_, gen, _, oerr := sub.CurrentOwnership()
		if oerr == nil {
			if m, merr := readGenManifest(dataHome, gen); merr == nil {
				manifest = m
			}
		}
	}

	rows, err := searchRows(cmd, term, scope, stateHome, manifest)
	if err != nil {
		return err
	}

	// Emitting is deliberately outside searchRows: on a TTY it runs the picker,
	// which installs what you tick, and install takes the apply lock searchRows
	// has just released.
	return emitSearchResult(cmd, format, term, rows)
}

// searchRows fetches the catalog under the apply lock and returns the rows
// whose name matches term, each marked with its installed version from
// manifest (nil manifest means no markers). A source serving no catalog
// yields no rows rather than an error.
//
// The apply lock is released before this returns, and that is load-bearing:
// the caller goes on to run the interactive picker, whose install path takes
// the same lock. Folding the picker back inside the withCatalog closure
// deadlocks it against itself.
func searchRows(
	cmd *cobra.Command,
	term, scope, stateHome string,
	manifest *schema.Manifest,
) ([]searchMatch, error) {
	var rows []searchMatch
	err := withCatalog(cmd, scope, stateHome, "search", "polypkg search",
		func(_ *schema.Profile, _ string, fr *planner.FetchResult) error {
			if fr.Catalog == nil {
				return nil
			}
			matched := filterNames(fr.Catalog.Names(), term)

			rows = make([]searchMatch, 0, len(matched))
			for _, name := range matched {
				rows = append(rows, searchMatch{
					Name:      name,
					Versions:  fr.Catalog.Versions(name),
					Installed: installedVersion(manifest, name),
				})
			}
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// interactiveTTY reports whether both stdin and stdout of cmd are TTYs.
// The picker is only shown when this returns true, which requires that both
// cmd.InOrStdin() and cmd.OutOrStdout() are *os.File values backed by
// character devices. In-process tests wiring bytes.Buffer I/O always return
// false, satisfying the non-TTY regression contract.
func interactiveTTY(cmd *cobra.Command) bool {
	outFile, ok := cmd.OutOrStdout().(*os.File)
	if !ok {
		return false
	}
	outInfo, err := outFile.Stat()
	if err != nil || outInfo.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	return isInteractive(cmd)
}

// searchOptionLabel returns the label shown in the multi-select picker for one
// match row. Format is "name (newest-version)"; when there are no versions
// just "name".
func searchOptionLabel(name string, versions []string) string {
	if len(versions) == 0 {
		return name
	}
	return fmt.Sprintf("%s (%s)", name, versions[0])
}

// runSearchPicker presents the interactive multi-select picker after the plain
// table has been emitted. It is called only when interactiveTTY is true,
// format is FormatText, and there is at least one match.
//
// On empty selection it exits cleanly. On a non-empty selection it invokes
// runInstall for the chosen package names (bare-name semantics: each becomes
// ">=newest" under the install path).
//
// This must run after searchRows has released the apply lock. runInstall takes
// that lock itself, so calling this from inside the withCatalog closure fails
// with "another polypkg command is already running (polypkg search)". Install
// re-fetching the catalog searchRows just fetched is accepted redundancy: it
// keeps install's all-or-nothing semantics and its lock/fetch/rollback logic
// in one place.
//
// Ctrl-C (huh.ErrUserAborted) exits cleanly with a CLIError{Msg: "search
// cancelled"} that carries no hint, matching init's cancel handling.
func runSearchPicker(cmd *cobra.Command, rows []searchMatch, format Format) error {
	opts := make([]huh.Option[string], len(rows))
	for i, r := range rows {
		opts[i] = huh.NewOption(searchOptionLabel(r.Name, r.Versions), r.Name)
	}

	var selected []string
	// Height is set explicitly because huh/v2's auto-height subtracts the
	// title's line count from the option viewport, which hides the last row
	// (and shows nothing at all for a single match). huh v1 sized the viewport
	// to the options alone. One title line and no Description on this field
	// means len(opts)+1 reproduces v1's geometry exactly.
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("install selected packages?").
				Options(opts...).
				Height(len(opts) + 1).
				Value(&selected),
		),
	).WithOutput(cmd.OutOrStdout()).WithInput(cmd.InOrStdin())

	if err := form.Run(); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return &CLIError{Msg: "search cancelled"}
		}
		return err
	}

	if len(selected) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "nothing selected")
		return nil
	}

	// Takes the apply lock, which searchRows released before we got here.
	return runInstall(cmd, selected, format)
}

// emitSearchResult writes the search output for the matched rows.
func emitSearchResult(
	cmd *cobra.Command,
	format Format,
	term string,
	rows []searchMatch,
) error {
	matchList := make([]any, len(rows))
	for i, r := range rows {
		matchList[i] = map[string]any{
			"name":      r.Name,
			"versions":  r.Versions,
			"installed": r.Installed,
		}
	}

	EmitResult(cmd, format, "search", map[string]any{
		"matches": matchList,
	}, func(w *bytes.Buffer, _ map[string]any) {
		if len(rows) == 0 {
			writeNoMatchLine(w, term)
			return
		}
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, r := range rows {
			if r.Installed != "" {
				fmt.Fprintf(tw, "%s\t%s\t[installed: %s]\n",
					r.Name, formatVersionList(r.Versions), r.Installed)
			} else {
				fmt.Fprintf(tw, "%s\t%s\n", r.Name, formatVersionList(r.Versions))
			}
		}
		_ = tw.Flush()
	})

	// Interactive picker: only when both stdin and stdout are TTYs, format is
	// text, and there is at least one match. All other paths are no-ops here.
	if format == FormatText && len(rows) > 0 && interactiveTTY(cmd) {
		return runSearchPicker(cmd, rows, format)
	}
	return nil
}

// filterNames returns the elements of names whose lowercased form contains
// the lowercased term. Input order is preserved; callers rely on Names() being
// sorted. Returns a new slice.
func filterNames(names []string, term string) []string {
	lower := strings.ToLower(term)
	out := make([]string, 0, len(names))
	for _, n := range names {
		if strings.Contains(strings.ToLower(n), lower) {
			out = append(out, n)
		}
	}
	return out
}

// formatVersionList formats a version slice for text display: the newest
// three versions joined by ", ", with " (+N more)" appended when there are
// more than three. Returns an empty string for a nil or empty slice.
func formatVersionList(versions []string) string {
	if len(versions) == 0 {
		return ""
	}
	const maxVersions = 3
	if len(versions) <= maxVersions {
		return strings.Join(versions, ", ")
	}
	head := strings.Join(versions[:maxVersions], ", ")
	return fmt.Sprintf("%s (+%d more)", head, len(versions)-maxVersions)
}

// writeNoMatchLine writes the friendly no-match line to w.
func writeNoMatchLine(w io.Writer, term string) {
	fmt.Fprintf(w, "no packages matching %q\n", term)
}

// installedVersion returns the version of name from manifest, or "" when
// manifest is nil or the package is not listed.
func installedVersion(manifest *schema.Manifest, name string) string {
	if manifest == nil {
		return ""
	}
	for i := range manifest.Entries {
		if manifest.Entries[i].Name == name {
			return manifest.Entries[i].Version
		}
	}
	return ""
}

package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/alternatives"
	"github.com/trevor-vaughan/polypkg/internal/lock"
	"github.com/trevor-vaughan/polypkg/internal/paths"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

func newAlternativesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "alternatives",
		Short: "Inspect and override alternatives provider selection",
		Long: "When two or more installed packages provide the same command name (for example, " +
			"two editors that both install a `vi` binary), polypkg picks a winner by priority " +
			"and writes a stable symlink so every other tool sees one consistent path.\n\n" +
			"Use the subcommands to inspect that arbitration and override the winner: `list` " +
			"shows the current winners, `set` pins a provider to a command, and `auto` reverts " +
			"to priority arbitration. Selections take effect immediately; no re-apply is needed.",
		Args: cobra.ArbitraryArgs,
		RunE: requireSubcommand(""),
	}
	cmd.PersistentFlags().String("scope", "user", "Scope to operate on: user or system")
	_ = cmd.RegisterFlagCompletionFunc("scope", completeStatic("user", "system"))
	// Subcommands are grouped so the read-only view is separated from the
	// commands that override arbitration (see AGENTS.md). The table is the
	// single source of truth: each entry registers its group and tags its
	// commands, and slice order drives display order.
	for _, g := range []struct {
		id    string
		title string
		cmds  []*cobra.Command
	}{
		{"inspect", "Inspect:", []*cobra.Command{
			newAlternativesListCmd(),
		}},
		{"override", "Override:", []*cobra.Command{
			newAlternativesSetCmd(), newAlternativesAutoCmd(),
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

// altProvider is one provider of an alternative, for display.
type altProvider struct {
	Package  string `json:"package"`
	Priority int    `json:"priority"`
	Source   string `json:"source"`
}

// altView is one alternative's resolved state.
type altView struct {
	Name      string            `json:"name"`
	Winner    string            `json:"winner"`
	Source    string            `json:"source"`
	Priority  int               `json:"priority"`
	Mode      string            `json:"mode"` // "auto" or "manual"
	Stale     bool              `json:"stale"`
	Providers []altProvider     `json:"providers"`
	Followers map[string]string `json:"followers,omitempty"`
}

// buildAltViews groups alternatives entries by name, resolves the winner
// (selection-aware), and returns a sorted per-name view. Non-alternatives
// entries are ignored.
func buildAltViews(entries []schema.OwnershipEntry, sel alternatives.Selections) []altView {
	byName := map[string][]altProvider{}
	for i := range entries {
		e := &entries[i]
		if e.Action != "alternatives" || e.Expected.Master != "" {
			continue
		}
		name := strings.TrimPrefix(e.Path, "bin/")
		byName[name] = append(byName[name], altProvider{e.Package, e.Expected.Priority, e.Expected.Target})
	}
	winners, staleList := alternatives.Resolve(entries, sel)
	stale := map[string]bool{}
	for _, n := range staleList {
		stale[n] = true
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)

	views := make([]altView, 0, len(names))
	for _, name := range names {
		ps := byName[name]
		sort.Slice(ps, func(i, j int) bool {
			if ps[i].Priority != ps[j].Priority {
				return ps[i].Priority > ps[j].Priority
			}
			return ps[i].Package < ps[j].Package
		})
		w := winners[name]
		prio := 0
		for _, p := range ps {
			if p.Package == w.Package {
				prio = p.Priority
			}
		}
		mode := "auto"
		if selPkg, ok := sel[name]; ok && !stale[name] && selPkg == w.Package {
			mode = "manual"
		}
		views = append(views, altView{
			Name: name, Winner: w.Package, Source: w.Source, Priority: prio,
			Mode: mode, Stale: stale[name], Providers: ps, Followers: w.Followers,
		})
	}
	return views
}

// altScopeSubstrate opens the OwnStore for the --scope flag and returns it with
// the selection-store path. Unknown scopes are an error.
func altScopeSubstrate(cmd *cobra.Command) (*substrate.OwnStore, string, error) {
	scope, _ := cmd.Flags().GetString("scope")
	var dataHome string
	switch scope {
	case "user":
		h, err := paths.UserDataHome()
		if err != nil {
			return nil, "", fmt.Errorf("resolve data home: %w", err)
		}
		dataHome = h
	case "system":
		dataHome = paths.SystemDataDir()
	default:
		return nil, "", &CLIError{Msg: fmt.Sprintf("invalid --scope %q", scope), Hint: "expected user or system"}
	}
	sub, err := substrate.NewOwnStore(dataHome)
	if err != nil {
		return nil, "", fmt.Errorf("open substrate: %w", err)
	}
	return sub, alternatives.SelectionsPath(sub.StateRoot()), nil
}

// altScopeStateHome resolves the XDG/system state home for the --scope flag —
// where the apply lock lives. Mirrors how apply.go derives the lock path.
func altScopeStateHome(cmd *cobra.Command) (string, error) {
	scope, _ := cmd.Flags().GetString("scope")
	switch scope {
	case "user":
		return paths.UserStateHome()
	case "system":
		return paths.SystemStateDir(), nil
	default:
		return "", &CLIError{Msg: fmt.Sprintf("invalid --scope %q", scope), Hint: "expected user or system"}
	}
}

func newAlternativesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list [name]",
		Short: "List arbitrated alternatives and their selection mode",
		Long: "Shows each arbitrated command name, the packages competing to provide it, and " +
			"whether the winner is chosen automatically by priority or pinned by a manual override. " +
			"With a name argument, shows just that one alternative.",
		Example: "  # List every arbitrated command\n" +
			"  polypkg alternatives list\n\n" +
			"  # Inspect a single one\n" +
			"  polypkg alternatives list vi",
		Args:              needsArgs(0, 1, "at most one [name]"),
		ValidArgsFunction: completeAltNames,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "alternatives list", runAlternativesList(cmd, args, format))
		},
	}
}

func runAlternativesList(cmd *cobra.Command, args []string, format Format) error {
	sub, selPath, err := altScopeSubstrate(cmd)
	if err != nil {
		return err
	}
	own, _, _, err := sub.CurrentOwnership()
	if err != nil {
		return &CLIError{Msg: "no generation has been applied yet", Hint: "run `polypkg apply` first", Err: err}
	}
	sel, err := alternatives.LoadSelections(selPath)
	if err != nil {
		return err
	}
	views := buildAltViews(own.Entries, sel)
	if len(args) == 1 {
		filtered := views[:0:0]
		for _, v := range views {
			if v.Name == args[0] {
				filtered = append(filtered, v)
			}
		}
		if len(filtered) == 0 {
			return &CLIError{
				Msg:  fmt.Sprintf("unknown alternative %q", args[0]),
				Hint: fmt.Sprintf("known alternatives: %s", altNameList(views)),
			}
		}
		views = filtered
	}
	EmitResult(cmd, format, "alternatives list",
		map[string]any{"alternatives": views},
		func(w *bytes.Buffer, _ map[string]any) {
			if len(views) == 0 {
				fmt.Fprintln(w, "no alternatives registered")
				return
			}
			for _, v := range views {
				staleNote := ""
				if v.Stale {
					staleNote = " (selection stale; reverted to auto)"
				}
				fmt.Fprintf(w, "%s -> %s [%s, priority %d]%s\n", v.Name, v.Winner, v.Mode, v.Priority, staleNote)
				for _, p := range v.Providers {
					marker := "  "
					if p.Package == v.Winner {
						marker = "* "
					}
					fmt.Fprintf(w, "  %s%s (priority %d) %s\n", marker, p.Package, p.Priority, p.Source)
				}
				if len(v.Followers) > 0 {
					links := make([]string, 0, len(v.Followers))
					for link := range v.Followers {
						links = append(links, link)
					}
					sort.Strings(links)
					fmt.Fprintln(w, "  follows:")
					for _, link := range links {
						fmt.Fprintf(w, "    %s -> %s\n", link, v.Followers[link])
					}
				}
			}
		})
	return nil
}

// validateAltSet checks that name is a known alternative in entries and that
// pkg currently provides it, returning the provider's source. Errors carry the
// known names / actual providers to guide the operator.
func validateAltSet(entries []schema.OwnershipEntry, name, pkg string) (string, error) {
	providers := map[string]string{} // package -> source
	for i := range entries {
		e := &entries[i]
		if e.Action != "alternatives" || e.Expected.Master != "" || strings.TrimPrefix(e.Path, "bin/") != name {
			continue
		}
		providers[e.Package] = e.Expected.Target
	}
	if len(providers) == 0 {
		return "", &CLIError{
			Msg:  fmt.Sprintf("unknown alternative %q", name),
			Hint: fmt.Sprintf("known alternatives: %s", knownAltNames(entries)),
		}
	}
	src, ok := providers[pkg]
	if !ok {
		return "", &CLIError{
			Msg:  fmt.Sprintf("package %q does not provide alternative %q", pkg, name),
			Hint: fmt.Sprintf("providers: %s", sortedKeys(providers)),
		}
	}
	return src, nil
}

// altNames returns the sorted, unique alternative names in entries.
func altNames(entries []schema.OwnershipEntry) []string {
	set := map[string]bool{}
	for i := range entries {
		if entries[i].Action == "alternatives" && entries[i].Expected.Master == "" {
			set[strings.TrimPrefix(entries[i].Path, "bin/")] = true
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// altProviders returns the sorted packages providing the named alternative.
func altProviders(entries []schema.OwnershipEntry, name string) []string {
	set := map[string]bool{}
	for i := range entries {
		e := &entries[i]
		if e.Action == "alternatives" && e.Expected.Master == "" && strings.TrimPrefix(e.Path, "bin/") == name {
			set[e.Package] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// knownAltNames returns the sorted, comma-joined alternative names in entries.
func knownAltNames(entries []schema.OwnershipEntry) string {
	names := altNames(entries)
	if len(names) == 0 {
		return "(none)"
	}
	return strings.Join(names, ", ")
}

func sortedKeys(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

func newAlternativesSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <name> <package>",
		Short: "Manually select the provider for an alternative (overrides priority)",
		Long: "Manually selects which package provides a command, overriding priority arbitration " +
			"until you run `polypkg alternatives auto`. The change takes effect immediately; " +
			"no re-apply is needed.",
		Example: "  # Make neovim win the 'vi' command\n" +
			"  polypkg alternatives set vi neovim",
		Args:              needsArgs(2, 2, "<name> <package>"),
		ValidArgsFunction: positional(completeAltNames, completeAltProviders),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "alternatives set", runAlternativesSet(cmd, args[0], args[1], format))
		},
	}
}

func runAlternativesSet(cmd *cobra.Command, name, pkg string, format Format) error {
	sub, selPath, err := altScopeSubstrate(cmd)
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	stateHome, err := altScopeStateHome(cmd)
	if err != nil {
		return err
	}
	lockPath := filepath.Join(stateHome, "apply.lock")
	l, err := lock.Acquire(ctx, lockPath,
		lock.Options{TxID: "alternatives-set", Command: "polypkg alternatives set"})
	if err != nil {
		return lockError(lockPath, err)
	}
	defer func() { _ = l.Release() }()
	own, _, _, err := sub.CurrentOwnership()
	if err != nil {
		return &CLIError{Msg: "no generation has been applied yet", Hint: "run `polypkg apply` first", Err: err}
	}
	if _, err := validateAltSet(own.Entries, name, pkg); err != nil {
		return err
	}
	sel, err := alternatives.LoadSelections(selPath)
	if err != nil {
		return err
	}
	sel[name] = pkg
	if err := alternatives.SaveSelections(selPath, sel); err != nil {
		return err
	}
	stale, err := alternatives.Reconcile(sub.AltRoot(), selPath, own.Entries)
	if err != nil {
		return fmt.Errorf("apply selection: %w", err)
	}
	for _, s := range stale {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: manual alternatives selection for %q is no longer provided; reverted to auto\n", s)
	}
	if manFollowersPresent(sub) {
		fmt.Fprintln(cmd.ErrOrStderr(), manNudgeLine(sub.ActiveManDir()))
	}
	EmitResult(cmd, format, "alternatives set",
		map[string]any{"name": name, "package": pkg},
		func(w *bytes.Buffer, d map[string]any) {
			fmt.Fprintf(w, "%s now provided by %s (manual)\n", d["name"], d["package"])
		})
	return nil
}

// altNameKnown reports whether name is a registered alternative in entries.
func altNameKnown(entries []schema.OwnershipEntry, name string) bool {
	for i := range entries {
		if entries[i].Action == "alternatives" && entries[i].Expected.Master == "" && strings.TrimPrefix(entries[i].Path, "bin/") == name {
			return true
		}
	}
	return false
}

func newAlternativesAutoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "auto <name>",
		Short: "Revert an alternative to priority arbitration (clears any manual selection)",
		Long: "Clears a manual override so the command reverts to automatic priority-based " +
			"arbitration. If no override was set, this is a no-op. The change takes effect " +
			"immediately; no re-apply is needed.",
		Example: "  # Return 'vi' to priority arbitration\n" +
			"  polypkg alternatives auto vi",
		Args:              needsArgs(1, 1, "<name>"),
		ValidArgsFunction: completeAltNames,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "alternatives auto", runAlternativesAuto(cmd, args[0], format))
		},
	}
}

func runAlternativesAuto(cmd *cobra.Command, name string, format Format) error {
	sub, selPath, err := altScopeSubstrate(cmd)
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	stateHome, err := altScopeStateHome(cmd)
	if err != nil {
		return err
	}
	lockPath := filepath.Join(stateHome, "apply.lock")
	l, err := lock.Acquire(ctx, lockPath,
		lock.Options{TxID: "alternatives-auto", Command: "polypkg alternatives auto"})
	if err != nil {
		return lockError(lockPath, err)
	}
	defer func() { _ = l.Release() }()
	own, _, _, err := sub.CurrentOwnership()
	if err != nil {
		return &CLIError{Msg: "no generation has been applied yet", Hint: "run `polypkg apply` first", Err: err}
	}
	if !altNameKnown(own.Entries, name) {
		return &CLIError{
			Msg:  fmt.Sprintf("unknown alternative %q", name),
			Hint: fmt.Sprintf("known alternatives: %s", knownAltNames(own.Entries)),
		}
	}
	sel, err := alternatives.LoadSelections(selPath)
	if err != nil {
		return err
	}
	if _, ok := sel[name]; !ok {
		EmitResult(cmd, format, "alternatives auto",
			map[string]any{"name": name, "changed": false},
			func(w *bytes.Buffer, d map[string]any) {
				fmt.Fprintf(w, "%s is already in auto mode\n", d["name"])
			})
		return nil
	}
	delete(sel, name)
	if err := alternatives.SaveSelections(selPath, sel); err != nil {
		return err
	}
	stale, err := alternatives.Reconcile(sub.AltRoot(), selPath, own.Entries)
	if err != nil {
		return fmt.Errorf("apply auto: %w", err)
	}
	for _, s := range stale {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: manual alternatives selection for %q is no longer provided; reverted to auto\n", s)
	}
	if manFollowersPresent(sub) {
		fmt.Fprintln(cmd.ErrOrStderr(), manNudgeLine(sub.ActiveManDir()))
	}
	winners, _ := alternatives.Resolve(own.Entries, sel)
	EmitResult(cmd, format, "alternatives auto",
		map[string]any{"name": name, "changed": true, "winner": winners[name].Package},
		func(w *bytes.Buffer, d map[string]any) {
			fmt.Fprintf(w, "%s reverted to auto; now provided by %s\n", d["name"], d["winner"])
		})
	return nil
}

// manNudgeLine is the one-line $MANPATH guidance emitted when the active tree
// has alternatives man followers (manDir is sub.ActiveManDir()). Defined once so
// every surface (apply, rollback, set, auto) prints identical text.
func manNudgeLine(manDir string) string {
	return fmt.Sprintf("note: add %s to your $MANPATH so man pages from alternatives followers are found", manDir)
}

// manFollowersPresent reports whether the active tree has a man follower subtree
// (the $MANPATH nudge condition). Takes the Substrate interface so apply/rollback
// (which hold substrate.Substrate) and set/auto (which hold *OwnStore) can share it.
func manFollowersPresent(sub substrate.Substrate) bool {
	_, err := os.Stat(sub.ActiveManDir())
	return err == nil
}

// altNameList renders the known alternative names for error messages.
func altNameList(views []altView) string {
	names := make([]string, 0, len(views))
	for _, v := range views {
		names = append(names, v.Name)
	}
	if len(names) == 0 {
		return "(none)"
	}
	return strings.Join(names, ", ")
}

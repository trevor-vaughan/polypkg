// Package cli implements polypkg's command-line surface using cobra.
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/starlarkeval"
)

// Version, Commit, and Date are set at build time via -ldflags.
var (
	Version = "0.1.0-dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// NewRootCmd builds the top-level cobra command.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "polypkg",
		Short:         "A *NIX-only declarative package manager",
		Long:          "polypkg is a declarative package manager supporting both system and user-level installs across Linux, macOS, and FreeBSD.",
		SilenceErrors: true,
		SilenceUsage:  true,
		// cobra's default edit distance for "did you mean" suggestions;
		// unknownCommand reads it through SuggestionsFor, which does not
		// apply the default itself.
		SuggestionsMinimumDistance: 2,
		Args:                       unknownCommand,
		RunE: func(cmd *cobra.Command, args []string) error {
			if showVersion, _ := cmd.Flags().GetBool("version"); showVersion {
				if Commit != "unknown" && Date != "unknown" {
					fmt.Fprintf(cmd.OutOrStdout(), "polypkg %s (%s, %s)\n", Version, Commit, Date)
				} else {
					fmt.Fprintln(cmd.OutOrStdout(), "polypkg", Version)
				}
				return nil
			}
			return cmd.Help()
		},
	}
	root.Flags().Bool("version", false, "Print version and exit")
	root.PersistentFlags().StringP("format", "f", "text", "Output format: text or json")
	_ = root.RegisterFlagCompletionFunc("format", completeStatic("text", "json"))

	// Present commands in authored order rather than alphabetically so the
	// curated lifecycle ordering below (and the insertion order of every
	// subcommand's children) is what users see in help.
	cobra.EnableCommandSorting = false

	// Commands are grouped by lifecycle phase so `polypkg --help` reads as a
	// guide rather than a flat list. The table is the single source of truth:
	// each entry registers its group and tags its commands, and the slice order
	// drives both the group display order and the order within each group. Add a
	// new command to the appropriate group here and nowhere else.
	for _, g := range []struct {
		id    string
		title string
		cmds  []*cobra.Command
	}{
		{"getting-started", "Getting started:", []*cobra.Command{
			newInitCmd(),
		}},
		{"packages", "Packages (find & change what's installed):", []*cobra.Command{
			newSearchCmd(), newInfoCmd(), newListCmd(),
			newInstallCmd(), newRemoveCmd(), newUpgradeCmd(),
		}},
		{"profile", "Profile & apply (declarative state):", []*cobra.Command{
			newApplyCmd(), newPlanCmd(), newAcceptDriftCmd(),
		}},
		{"generations", "Generations (history, rollback, cleanup):", []*cobra.Command{
			newStatusCmd(), newRollbackCmd(), newGenerationCmd(), newGCCmd(),
		}},
		{"integration", "Integration (expose & arbitrate commands):", []*cobra.Command{
			newLinkCmd(), newUnlinkCmd(), newAlternativesCmd(),
		}},
		{"sources", "Sources & repositories:", []*cobra.Command{
			newSourceCmd(), newRepoCmd(),
		}},
		{"mirror", "Offline mirrors:", []*cobra.Command{
			newMirrorCmd(),
		}},
		{"audit", "Audit & evidence:", []*cobra.Command{
			newAttestationCmd(),
		}},
		{"authoring", "Author packages:", []*cobra.Command{
			newPkgCmd(),
		}},
		{"maintenance", "Maintenance:", []*cobra.Command{
			newConfigCmd(), newPurgeCmd(),
		}},
	} {
		root.AddGroup(&cobra.Group{ID: g.id, Title: g.title})
		for _, c := range g.cmds {
			c.GroupID = g.id
			root.AddCommand(c)
		}
	}

	// eval-starlark is a hidden re-exec entrypoint, not a user command, so it
	// stays ungrouped (cobra lists ungrouped commands under "Additional Commands").
	root.AddCommand(newEvalStarlarkCmd())

	installFlagErrorFunc(root)
	return root
}

// newEvalStarlarkCmd is the hidden entrypoint the apply runner re-execs to
// evaluate a !starlark snippet in an isolated child process. It reads a request
// from stdin, writes the result to stdout, and exits; it is never invoked by users.
func newEvalStarlarkCmd() *cobra.Command {
	return &cobra.Command{
		Use:    starlarkeval.ChildCommand,
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			starlarkeval.RunChild() // reads stdin, writes stdout, exits
			return nil
		},
	}
}

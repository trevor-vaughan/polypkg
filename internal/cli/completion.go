package cli

import (
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/paths"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

// compFunc is cobra's completion-function shape (positional or flag value).
type compFunc func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective)

// completeStatic returns a compFunc offering a fixed option set, filtered by the
// typed prefix. Used for enum flags (--format, --scope).
func completeStatic(opts ...string) compFunc {
	return func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		out := make([]string, 0, len(opts))
		for _, o := range opts {
			if strings.HasPrefix(o, toComplete) {
				out = append(out, o)
			}
		}
		return out, cobra.ShellCompDirectiveNoFileComp
	}
}

// positional dispatches to the compFunc for the current positional index
// (len(args)); positions past the last fn yield no candidates.
func positional(fns ...compFunc) compFunc {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) < len(fns) {
			return fns[len(args)](cmd, args, toComplete)
		}
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
}

// completionOwnership opens the user-scope substrate read-only and returns the
// current generation's ownership entries. Fail-silent: any error yields
// (nil, false). Completion must never error or block.
func completionOwnership() ([]schema.OwnershipEntry, bool) {
	dataHome, err := paths.UserDataHome()
	if err != nil {
		return nil, false
	}
	sub, err := substrate.NewOwnStore(dataHome)
	if err != nil {
		return nil, false
	}
	own, _, _, err := sub.CurrentOwnership()
	if err != nil || own == nil {
		return nil, false
	}
	return own.Entries, true
}

// genIDStrings renders generation IDs as strings for --to completion.
func genIDStrings(gens []substrate.GenInfo) []string {
	out := make([]string, 0, len(gens))
	for _, g := range gens {
		out = append(out, strconv.Itoa(g.ID))
	}
	return out
}

// completeGenerations completes the rollback --to flag with committed generation IDs.
func completeGenerations(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	dataHome, err := paths.UserDataHome()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	sub, err := substrate.NewOwnStore(dataHome)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	gens, err := sub.ListGenerations()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return genIDStrings(gens), cobra.ShellCompDirectiveNoFileComp
}

// completeAltNames completes an alternative name positional argument.
func completeAltNames(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	entries, ok := completionOwnership()
	if !ok {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return altNames(entries), cobra.ShellCompDirectiveNoFileComp
}

// completeAltProviders completes the provider package for the alternative named in args[0].
func completeAltProviders(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
	if len(args) == 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	entries, ok := completionOwnership()
	if !ok {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return altProviders(entries, args[0]), cobra.ShellCompDirectiveNoFileComp
}

// completeConfigResetPaths completes a `config reset` path argument.
func completeConfigResetPaths(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	entries, ok := completionOwnership()
	if !ok {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return resettableConfigPaths(entries), cobra.ShellCompDirectiveNoFileComp
}

// completePackages completes a package-name flag/argument from the current generation.
func completePackages(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	entries, ok := completionOwnership()
	if !ok {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return pkgNames(entries), cobra.ShellCompDirectiveNoFileComp
}

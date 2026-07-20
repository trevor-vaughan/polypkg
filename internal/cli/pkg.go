package cli

import "github.com/spf13/cobra"

// newPkgCmd is the package-author command group: init → lint → build. It mirrors
// newRepoCmd's subgroup registration (AddGroup + per-command GroupID), so the
// group table below is the single source of truth for both display order and
// group membership.
//
// `pkg init` (getting-started), `pkg lint` + `pkg build` (author loop), and
// `pkg explain` (reference) are registered here via the group table below.
func newPkgCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pkg",
		Short: "Author, validate, and build a polypkg package source",
		Long: `Scaffold a package source, lint it against structure, action, parameter, and
identity rules, and build an unsigned artifact plus an unsigned attestation
preview. No signing key or repository is required.`,
	}
	for _, g := range []struct {
		id    string
		title string
		cmds  []*cobra.Command
	}{
		{"getting-started", "Getting started:", []*cobra.Command{
			newPkgInitCmd(),
		}},
		{"authoring", "Author loop:", []*cobra.Command{
			newPkgLintCmd(),
			newPkgBuildCmd(),
		}},
		{"reference", "Reference:", []*cobra.Command{
			newPkgExplainCmd(),
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

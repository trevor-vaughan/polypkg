package cli

import (
	"bytes"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/cobra"
)

var _ = Describe("root command", func() {
	It("prints the polypkg version with --version", func() {
		cmd := NewRootCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"--version"})
		Expect(cmd.Execute()).To(Succeed())
		Expect(out.String()).To(ContainSubstring("polypkg"))
	})

	It("registers the persistent --format flag with text default", func() {
		root := NewRootCmd()
		flag := root.PersistentFlags().Lookup("format")
		Expect(flag).NotTo(BeNil())
		Expect(flag.DefValue).To(Equal("text"))
		Expect(flag.Shorthand).To(Equal("f"))
	})

	It("propagates --format to subcommands via PersistentFlags", func() {
		root := NewRootCmd()
		for _, sub := range root.Commands() {
			if sub.Hidden {
				continue
			}
			Expect(sub.Flag("format")).NotTo(BeNil(),
				"command %q should inherit --format", sub.Use)
		}
	})

	It("assigns every top-level user command to a registered group", func() {
		root := NewRootCmd()
		// Force cobra to inject built-in commands (help, completion) so the
		// iteration sees the real command tree.
		_ = root.Commands()

		var ungrouped []string
		for _, sub := range root.Commands() {
			switch {
			case sub.Hidden: // starlark-eval and any future hidden commands
				continue
			case sub.Name() == "completion", sub.Name() == "help":
				continue // cobra auto-injects these; they belong in "Additional Commands"
			}
			// A missing or unregistered GroupID drops the command into cobra's
			// "Additional Commands" bucket — the flat-list behavior the lifecycle
			// grouping exists to prevent. Place new commands in the group table
			// in NewRootCmd.
			if sub.GroupID == "" || !root.ContainsGroup(sub.GroupID) {
				ungrouped = append(ungrouped, fmt.Sprintf("%q (GroupID=%q)", sub.Name(), sub.GroupID))
			}
		}
		Expect(ungrouped).To(BeEmpty(),
			"top-level commands not in a registered lifecycle group: %v", ungrouped)
	})

	// walkCommands visits cmd and every non-excluded descendant. It skips:
	//   - hidden commands (cmd.Hidden == true), including the starlark-eval child
	//   - the cobra-auto-injected "completion" command and all its children
	//   - the cobra-auto-injected "help" command
	// All other commands — including the root — must satisfy fn.
	walkCommands := func(root *cobra.Command, fn func(*cobra.Command)) {
		var walk func(*cobra.Command)
		walk = func(cmd *cobra.Command) {
			if cmd.Hidden {
				return // starlark-eval and any future hidden commands
			}
			if cmd.Name() == "completion" {
				return // cobra auto-injects shell-completion; skip it and its children
			}
			if cmd.Name() == "help" {
				return // cobra auto-injects the help command; it carries no Long by design
			}
			fn(cmd)
			for _, child := range cmd.Commands() {
				walk(child)
			}
		}
		walk(root)
	}

	It("every non-hidden, non-completion command has a non-empty Long description", func() {
		root := NewRootCmd()
		// Force cobra to inject built-in commands (help, completion) so the
		// walk sees the real command tree.
		_ = root.Commands()

		var missing []string
		walkCommands(root, func(cmd *cobra.Command) {
			if cmd.Long == "" {
				missing = append(missing, fmt.Sprintf("%q", cmd.CommandPath()))
			}
		})
		Expect(missing).To(BeEmpty(),
			"commands with no Long description (add one or add to the skip list with a comment): %v", missing)
	})

	It("key cold-path commands have non-empty Example strings", func() {
		// Curated guard: these commands had Examples added in UX plan 3.
		// If Example is empty the text is gone and the guard fires.
		root := NewRootCmd()

		find := func(path ...string) *cobra.Command {
			cur := root
			for _, name := range path {
				var found *cobra.Command
				for _, child := range cur.Commands() {
					if child.Name() == name {
						found = child
						break
					}
				}
				Expect(found).NotTo(BeNil(), "command %v not found", append([]string{"polypkg"}, path...))
				cur = found
			}
			return cur
		}

		cases := []struct {
			path []string
		}{
			{[]string{"gc"}},
			{[]string{"rollback"}},
			{[]string{"generation", "pin"}},
			{[]string{"install"}},
			{[]string{"alternatives", "set"}},
		}
		for _, tc := range cases {
			cmd := find(tc.path...)
			Expect(cmd.Example).NotTo(BeEmpty(),
				"command %q should have an Example string", cmd.CommandPath())
		}
	})

	It("never partially groups a command's subcommands", func() {
		// The convention (see AGENTS.md): grouping is opt-in per command, but
		// once a command defines any group, every one of its user subcommands
		// must land in a registered group — otherwise the stragglers fall into
		// cobra's "Additional Commands" bucket and the menu reads worse than a
		// flat list. This invariant holds for the root and any future grouped
		// subcommand tree.
		root := NewRootCmd()
		_ = root.Commands() // force cobra to inject help/completion

		var violations []string
		var walk func(*cobra.Command)
		walk = func(cmd *cobra.Command) {
			if len(cmd.Groups()) > 0 {
				for _, sub := range cmd.Commands() {
					if sub.Hidden || sub.Name() == "completion" || sub.Name() == "help" {
						continue
					}
					if sub.GroupID == "" || !cmd.ContainsGroup(sub.GroupID) {
						violations = append(violations,
							fmt.Sprintf("%q (GroupID=%q)", sub.CommandPath(), sub.GroupID))
					}
				}
			}
			for _, sub := range cmd.Commands() {
				walk(sub)
			}
		}
		walk(root)
		Expect(violations).To(BeEmpty(),
			"a command that defines groups must place every subcommand in a registered group: %v", violations)
	})
})

var _ = Describe("subcommand grouping", func() {
	// Parents whose subcommands are grouped, with the group title expected for
	// each child. Flat menus (generation, config) are intentionally absent — the
	// partial-grouping invariant above is the completeness guard for whatever is
	// grouped here; this table pins the specific taxonomy.
	groupedMenus := map[string]map[string]string{
		"repo": {
			"init":          "Getting started:",
			"add":           "Repository contents:",
			"remove":        "Repository contents:",
			"build":         "Build & status:",
			"export-bundle": "Build & status:",
			"status":        "Build & status:",
			"key":           "Signing keys:",
			"revoke":        "Revocation:",
		},
		"source": {
			"list":   "Inspect:",
			"add":    "Modify:",
			"remove": "Modify:",
		},
		"alternatives": {
			"list": "Inspect:",
			"set":  "Override:",
			"auto": "Override:",
		},
	}

	for parentName, wantTitle := range groupedMenus {
		It("assigns "+parentName+" subcommands to the expected groups", func() {
			root := NewRootCmd()
			var parent *cobra.Command
			for _, c := range root.Commands() {
				if c.Name() == parentName {
					parent = c
					break
				}
			}
			Expect(parent).NotTo(BeNil(), "%q command not registered", parentName)

			titleByID := map[string]string{}
			for _, g := range parent.Groups() {
				titleByID[g.ID] = g.Title
			}
			for _, sub := range parent.Commands() {
				if sub.Hidden || sub.Name() == "completion" || sub.Name() == "help" {
					continue
				}
				want, known := wantTitle[sub.Name()]
				Expect(known).To(BeTrue(),
					"unexpected %s subcommand %q — place it in the grouping table", parentName, sub.Name())
				Expect(sub.GroupID).NotTo(BeEmpty(), "%s %q has no GroupID", parentName, sub.Name())
				Expect(titleByID).To(HaveKey(sub.GroupID),
					"%s %q references unregistered group %q", parentName, sub.Name(), sub.GroupID)
				Expect(titleByID[sub.GroupID]).To(Equal(want),
					"%s %q is in the wrong group", parentName, sub.Name())
			}
		})
	}
})

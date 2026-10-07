package cli

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/action"
)

// phaseDoc pairs a lifecycle Phase constant with a one-line meaning. The slice
// order below is the canonical apply-lifecycle order; there is no exported
// ordered list in the action package, so this local table is the reference's
// source of order. The constants are referenced (not re-typed) so a rename in
// action.go is a compile error here rather than silent drift.
type phaseDoc struct {
	phase action.Phase
	desc  string
}

// lifecyclePhases lists every apply phase in lifecycle order with its meaning.
// place = files enter the generation store; activate = the generation becomes
// active; deactivate = the prior generation is retired.
var lifecyclePhases = []phaseDoc{
	{action.PhasePrePlace, "before this package's files are placed into the generation store"},
	{action.PhasePostPlace, "after this package's files are placed into the generation store"},
	{action.PhasePreActivate, "before the new generation is promoted to active"},
	{action.PhasePostActivate, "after the new generation is promoted to active"},
	{action.PhasePreDeactivate, "before the prior active generation is retired"},
	{action.PhasePostDeactivate, "after the prior active generation is retired"},
}

// platformExample is the recipe key that makes an artifact per-platform: each
// host downloads only the artifact published for its own <os>/<arch>. A test
// validates the value with the producer grammar, so the reference never shows
// a platform pkg lint would refuse.
const platformExample = "platform: linux/amd64"

// starlarkExample is the fat-artifact portability hint: one artifact carries
// every platform's files, and a computed !starlark param value reads host
// facts (the predeclared `host` struct exposes `os` and `arch`; `package.name`
// is also available) to select the OS/arch-specific file at apply time.
const starlarkExample = `src: !starlark "return '$PKG/content/bin/' + host.os + '/' + host.arch + '/hello'"`

// newPkgExplainCmd prints an orientation reference for package authors: the
// build-outside model, the apply lifecycle phases, the discovered action
// catalogue with each action's parameters, the $PKG/$ACTIVE path vars, and the
// two portability mechanisms (per-platform artifacts and !starlark fat
// artifacts). The action list is discovered from action.Registry so it cannot
// drift from the code.
func newPkgExplainCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "explain",
		Short: "Print a reference for phases, actions, and path vars",
		Long: `Print an orientation reference for authoring a polypkg package: the
build-outside model, the apply lifecycle phases, every registered action with
its parameters, the $PKG and $ACTIVE path vars, and the two ways to ship an
OS/arch-aware package: one artifact per platform (the platform: key) or one fat
artifact that selects files with !starlark host facts. The action catalogue is
discovered from the runtime registry, so it always matches the installed
polypkg.`,
		Example: "  polypkg pkg explain\n  polypkg pkg explain --format json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			EmitResult(cmd, format, "pkg explain", explainData(), renderExplainText)
			return nil
		},
	}
}

// actionParam is one action parameter rendered for the reference.
type actionParam struct {
	Name     string   `json:"name"`
	Required bool     `json:"required"`
	Kind     string   `json:"kind"`
	Enum     []string `json:"enum,omitempty"`
}

// explainData builds the structured reference payload consumed by both the
// json envelope and the text renderer. Actions are sorted by name for stable
// output; phases follow the canonical lifecycle order.
func explainData() map[string]any {
	phases := make([]any, 0, len(lifecyclePhases))
	for _, p := range lifecyclePhases {
		phases = append(phases, map[string]any{
			"name":        string(p.phase),
			"description": p.desc,
		})
	}

	names := make([]string, 0, len(action.Registry))
	for name := range action.Registry {
		names = append(names, name)
	}
	sort.Strings(names)

	actions := make([]any, 0, len(names))
	for _, name := range names {
		spec := action.Registry[name]
		params := make([]actionParam, 0, len(spec.Params))
		for _, p := range spec.Params {
			params = append(params, actionParam{
				Name:     p.Name,
				Required: p.Required,
				Kind:     paramKindName(p.Kind),
				Enum:     p.Enum,
			})
		}
		actions = append(actions, map[string]any{
			"name":   name,
			"params": params,
		})
	}

	return map[string]any{
		"phases":  phases,
		"actions": actions,
		"vars": []any{
			map[string]any{"name": "$PKG", "meaning": "this package's own shipped files (content/ ...)"},
			map[string]any{"name": "$ACTIVE", "meaning": "the install root the package's files land under (e.g. ~/.local/share/polypkg/active/...)"},
		},
		"notes": []any{
			"polypkg does not build software: you build your program externally and drop the result into the package's content/ directory; polypkg packs and installs it.",
			"actions run at lifecycle phases during `polypkg apply`.",
			"a param value may be computed with !starlark, which can read host facts (host.os, host.arch) and package.name to select OS/arch-specific files.",
			"a package may instead publish one artifact per platform: set platform: <os>/<arch> (Go GOOS/GOARCH names) in polypkg.yaml and publish one repository entry per platform; each host downloads only its own artifact. Omitting platform: publishes a platform-agnostic (any) artifact.",
		},
		"platform_example": platformExample,
		"starlark_example": starlarkExample,
	}
}

// paramKindName maps a ParamKind to its author-facing label.
func paramKindName(k action.ParamKind) string {
	switch k {
	case action.KindString:
		return "string"
	case action.KindPath:
		return "path"
	case action.KindMode:
		return "mode"
	case action.KindInt:
		return "int"
	case action.KindEnum:
		return "enum"
	case action.KindStringList:
		return "list"
	default:
		return "string"
	}
}

// renderExplainText writes the human-readable reference. It re-derives the
// ordering directly from the same tables explainData uses, so text and json
// stay in lockstep.
func renderExplainText(w *bytes.Buffer, _ map[string]any) {
	fmt.Fprintln(w, "polypkg package reference")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "The model: polypkg does not build your software. You build your program")
	fmt.Fprintln(w, "externally and drop the result into the package's content/ directory; polypkg")
	fmt.Fprintln(w, "packs it and, at `polypkg apply`, runs the actions you declare under 'actions:'")
	fmt.Fprintln(w, "at their lifecycle phases.")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Phases (in lifecycle order):")
	pw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, p := range lifecyclePhases {
		fmt.Fprintf(pw, "  %s\t%s\n", string(p.phase), p.desc)
	}
	_ = pw.Flush()
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Actions (name and parameters; required params are marked *):")
	names := make([]string, 0, len(action.Registry))
	for name := range action.Registry {
		names = append(names, name)
	}
	sort.Strings(names)
	aw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, name := range names {
		spec := action.Registry[name]
		fmt.Fprintf(aw, "  %s\t%s\n", name, formatParams(spec.Params))
	}
	_ = aw.Flush()
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Path vars (expand at apply time):")
	fmt.Fprintln(w, "  $PKG     this package's own shipped files (content/ ...)")
	fmt.Fprintln(w, "  $ACTIVE  the install root the package's files land under")
	fmt.Fprintln(w, "           (e.g. ~/.local/share/polypkg/active/...)")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Portability: a package whose files differ per OS/arch ships one of two ways.")
	fmt.Fprintln(w, "  Per-platform artifacts: set a top-level platform: key in polypkg.yaml to the")
	fmt.Fprintln(w, "  <os>/<arch> the artifact is for (Go GOOS/GOARCH names) and publish one")
	fmt.Fprintln(w, "  artifact per platform; each host downloads only its own. Omit the key for a")
	fmt.Fprintln(w, `  platform-agnostic ("any") artifact. Example:`)
	fmt.Fprintf(w, "    %s\n", platformExample)
	fmt.Fprintln(w, "  Fat artifact: ship every platform's files in one artifact and compute a param")
	fmt.Fprintln(w, "  value with !starlark, which can read host facts (host.os, host.arch) and")
	fmt.Fprintln(w, "  package.name. Every host downloads every platform's files. Example:")
	fmt.Fprintf(w, "    %s\n", starlarkExample)
}

// formatParams renders an action's parameters as a single readable line:
// "src* (path), dest* (path), policy (enum: symlink|copy|hardlink)". Required
// params carry a trailing '*'. Enum kinds list their allowed values.
func formatParams(params []action.ParamSpec) string {
	if len(params) == 0 {
		return "(no parameters)"
	}
	parts := make([]string, 0, len(params))
	for _, p := range params {
		star := ""
		if p.Required {
			star = "*"
		}
		kind := paramKindName(p.Kind)
		if p.Kind == action.KindEnum && len(p.Enum) > 0 {
			kind = "enum: " + strings.Join(p.Enum, "|")
		}
		parts = append(parts, fmt.Sprintf("%s%s (%s)", p.Name, star, kind))
	}
	return strings.Join(parts, ", ")
}

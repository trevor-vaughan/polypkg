package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

// reInitName mirrors the package-name pattern the JSON schema enforces at parse
// time. Validating up front keeps the round-trip invariant intact: a name that
// would fail 'pkg lint' (PKG000) is rejected before anything is written.
var reInitName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// newPkgInitCmd scaffolds a lint-clean, runnable package source. The emitted
// polypkg.yaml plus content/bin/<name> stub satisfy every pkglint layer, so
// `pkg init X && pkg lint X` reports zero findings — the round-trip invariant.
func newPkgInitCmd() *cobra.Command {
	var name, version string
	var force bool
	cmd := &cobra.Command{
		Use:   "init <dir>",
		Short: "Scaffold a lint-clean package source",
		Long: `Scaffold <dir>/polypkg.yaml plus a content/bin/<name> stub for a new package
source. The emitted source passes 'pkg lint' with zero findings and is ready to
edit. --name defaults to the directory basename; --version defaults to 0.1.0.
Refuses to overwrite an existing polypkg.yaml unless --force is given.`,
		Example: "  polypkg pkg init ./hello\n  polypkg pkg init --name hello --version 1.0.0 ./src",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPkgInit(cmd, args[0], name, version, force)
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "Package name (default: dir basename)")
	cmd.Flags().StringVar(&version, "version", "0.1.0", "Initial version")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite an existing polypkg.yaml")
	return cmd
}

func runPkgInit(cmd *cobra.Command, dir, name, version string, force bool) error {
	if name == "" {
		name = filepath.Base(dir)
	}
	if !reInitName.MatchString(name) {
		return &CLIError{
			Msg:  fmt.Sprintf("package name %q is not a valid slug", name),
			Hint: "names must match ^[a-zA-Z0-9_-]+$; pass --name with a valid slug (e.g. --name mytool)",
		}
	}
	manifest := filepath.Join(dir, "polypkg.yaml")
	if _, err := os.Stat(manifest); err == nil && !force {
		return &CLIError{
			Msg:  fmt.Sprintf("%s already exists", manifest),
			Hint: "pass --force to overwrite, or choose a new directory",
		}
	}
	contentDir := filepath.Join(dir, "content", "bin")
	if err := os.MkdirAll(contentDir, 0o755); err != nil { //nolint:gosec // G301: scaffolded package source tree the author owns and shares; 0755 is intentional
		return &CLIError{Msg: "create content dir", Err: err}
	}
	stub := filepath.Join(contentDir, name)
	if err := os.WriteFile(stub, []byte("#!/bin/sh\necho \"Hello, world!\"\n"), 0o755); err != nil { //nolint:gosec // G306: the stub ships in content/bin and must be executable; 0755 is intentional
		return &CLIError{Msg: "write stub", Err: err}
	}

	raw := []byte(fillPkgTemplate(name, version))
	tmp := manifest + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil { //nolint:gosec // G306: scaffolded polypkg.yaml is author-owned source, not secret material; 0644 is intentional
		return &CLIError{Msg: "write manifest", Err: err}
	}
	if err := os.Rename(tmp, manifest); err != nil {
		return &CLIError{Msg: "commit manifest", Err: err}
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Scaffolded %s (%s) in %s\n", name, version, dir)
	return nil
}

// pkgTemplate is the hand-authored polypkg.yaml written by `polypkg pkg init`.
// It leads with the package identity, annotates each action inline, and points
// at `polypkg pkg explain` instead of an inline lifecycle primer. Marshaling
// cannot control param order or emit per-action comments, so the scaffold is a
// literal template rather than a serialized schema.Package. YAML comments are
// lint-invisible, so the round-trip invariant — `pkg init X && pkg lint X`
// reports zero findings, and the scaffold parses via ParsePackage — holds.
//
// Placeholders: {NAME}, {VERSION}.
const pkgTemplate = `# polypkg.yaml — how to install the "{NAME}" package.
#
# To ship your tool: set name/version below and put your built program in
# content/bin/. Then check and install:
#   polypkg pkg lint .      validate this file
#   polypkg apply .         install it
# New here?  Run  polypkg pkg explain  for phases, actions, and portability.
schema: polypkg.package/v1
name: {NAME}
version: {VERSION}
# title: {NAME}   # optional human-friendly display name (name stays the ASCII id)

# 'actions' run in order at a lifecycle phase of 'polypkg apply'. This template
# does the common thing — put one binary on your PATH — all at post-place
# (right after your files are copied in).
actions:
  # 1) Copy your program into place. install creates parent dirs and preserves
  #    the file mode, so an executable stays executable.
  - phase: post-place
    action: install
    params:
      src: $PKG/content/bin/{NAME}   # your file, shipped in this package
      dest: $ACTIVE/{NAME}/bin/{NAME}   # where it installs ($ACTIVE ≈ ~/.local/share/polypkg/active)
  # 2) Expose it as the ` + "`" + `{NAME}` + "`" + ` command on your PATH — this makes it runnable.
  - phase: post-place
    action: path
    params:
      name: {NAME}   # the command you type
      source: $ACTIVE/{NAME}/bin/{NAME}   # the file installed above
`

// fillPkgTemplate substitutes name and version into pkgTemplate in a single
// simultaneous pass, mirroring fillProfileTemplate. name is validated upstream
// (reInitName) before it reaches this function.
func fillPkgTemplate(name, version string) string {
	return strings.NewReplacer(
		"{NAME}", name,
		"{VERSION}", version,
	).Replace(pkgTemplate)
}

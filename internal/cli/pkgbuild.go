package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/trevor-vaughan/polypkg/internal/attest"
	"github.com/trevor-vaughan/polypkg/internal/pkglint"
	"github.com/trevor-vaughan/polypkg/internal/repo"
)

func newPkgBuildCmd() *cobra.Command {
	var outDir string
	cmd := &cobra.Command{
		Use:   "build <dir>",
		Short: "Lint, pack, and preview the attestation for a package source",
		Long: `Runs pkg lint (aborting on any error-severity finding), packs a deterministic
unsigned <name>-<version>.tar.zst, prints its BLAKE3 digest, and writes the
unsigned in-toto attestation preview <name>-<version>.att.json — the exact
statement the publisher will sign.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPkgBuild(cmd, args[0], outDir)
		},
	}
	cmd.Flags().StringVarP(&outDir, "output", "o", ".", "Directory to write the artifact and attestation preview")
	return cmd
}

func runPkgBuild(cmd *cobra.Command, dir, outDir string) error {
	// Create the output directory before linting so an unwritable destination
	// fails fast instead of after the full lint+pack run.
	if err := os.MkdirAll(outDir, 0o755); err != nil { //nolint:gosec // G301: author-chosen output dir for distributable build products; 0755 is intentional
		return &CLIError{Msg: fmt.Sprintf("pkg build: create output dir %q", outDir), Err: err}
	}

	res, err := pkglint.Lint(dir)
	if err != nil {
		return &CLIError{Msg: fmt.Sprintf("cannot lint %q", dir), Err: err}
	}
	if res.HasErrors() {
		pkglint.WriteHuman(cmd.OutOrStdout(), res)
		return &CLIError{Msg: "pkg build: lint found error-severity issues; not packing"}
	}

	artifact, pkg, err := repo.PackArtifact(dir)
	if err != nil {
		return &CLIError{Msg: "pkg build: pack", Err: err}
	}
	base := fmt.Sprintf("%s-%s", pkg.Name, pkg.Version)
	artifactPath := filepath.Join(outDir, base+".tar.zst")
	if err := os.WriteFile(artifactPath, artifact, 0o644); err != nil { //nolint:gosec // G306: the artifact is public distribution material; 0644 is intentional
		return &CLIError{Msg: "pkg build: write artifact", Err: err}
	}

	ch := repo.ContentHash(artifact) // "blake3:<hex>"
	sarifBytes, err := pkglint.SARIF(res)
	if err != nil {
		return &CLIError{Msg: "pkg build: render SARIF", Err: err}
	}
	st := attest.AssembleStatement(base+".tar.zst", strings.TrimPrefix(ch, "blake3:"), json.RawMessage(sarifBytes))
	attBytes, err := st.CanonicalJSON()
	if err != nil {
		return &CLIError{Msg: "pkg build: canonicalize attestation", Err: err}
	}
	attPath := filepath.Join(outDir, base+".att.json")
	if err := os.WriteFile(attPath, attBytes, 0o644); err != nil { //nolint:gosec // G306: the attestation preview is public metadata a publisher signs; 0644 is intentional
		return &CLIError{Msg: "pkg build: write attestation preview", Err: err}
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Built %s\n  artifact:    %s\n  digest:      %s\n  attestation: %s\n",
		base, artifactPath, ch, attPath)
	return nil
}

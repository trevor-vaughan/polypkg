package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

func newAttestationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attestation",
		Short: "Inspect recorded provenance evidence",
		Long: `Provenance audit surface. Aggregates the attestation evidence polypkg
recorded when each installed package was verified at install time.

Subcommands: report.`,
		Args: cobra.ArbitraryArgs,
		RunE: requireSubcommand("the only subcommand is `attestation report`"),
	}
	cmd.AddCommand(newAttestationReportCmd())
	return cmd
}

func newAttestationReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Emit a deterministic provenance-evidence report",
		Long: `Aggregate every installed package's recorded provenance evidence
(tier, predicate types, verifying key / builder identity / certificate identity,
policy at install) across all retained generations into a deterministic
polypkg.attestation-report/v1 JSON document.

The report is a faithful aggregation of already-recorded, individually anchored
evidence — it is NOT signed by polypkg. Trust derives from the upstream
signatures each recorded hash verifies against.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "attestation report", runAttestationReport(cmd, format))
		},
	}
	addScopeFlags(cmd)
	return cmd
}

func runAttestationReport(cmd *cobra.Command, format Format) error {
	p := bestEffortProfile(cmd)
	scope, dataHome, _, err := resolveListScope(cmd, p)
	if err != nil {
		return err
	}
	sub, err := substrate.New("store", dataHome)
	if err != nil {
		return fmt.Errorf("open substrate: %w", err)
	}
	rep, err := buildAttestationReport(sub, scope, dataHome)
	if err != nil {
		return err
	}
	if format == FormatJSON {
		data, merr := json.Marshal(rep)
		if merr != nil {
			return fmt.Errorf("marshal attestation report: %w", merr)
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(data))
		return nil
	}
	emitAttestationReportText(cmd.OutOrStdout(), rep)
	if skipped := rep.GeneratedFrom.SkippedIncomplete; len(skipped) > 0 {
		ids := make([]string, len(skipped))
		for i, id := range skipped {
			ids[i] = strconv.Itoa(id)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: skipped incomplete generation(s) %s: an interrupted apply left them without a manifest, so they hold no evidence; run `polypkg gc` to remove them\n",
			strings.Join(ids, ", "))
	}
	return nil
}

// buildAttestationReport aggregates the recorded provenance of every installed
// package across all retained generations into a deterministic report. A
// generation with no manifest (an interrupted apply) holds no recorded
// evidence: it is skipped and listed in GeneratedFrom.SkippedIncomplete. Any
// other manifest failure is a hard error naming the generation (dataHome
// locates it): a damaged manifest means corruption or tampering, and an audit
// must not let either hide a generation's evidence. Ordering: generation ids ascending; packages by
// (name, version, generation, content_hash) — content_hash is the final
// tiebreaker so a tampered manifest with duplicate name@version entries in one
// generation still yields a provable total order. Per-package installed_at is the persisted
// manifest timestamp, so the output is reproducible with no wall-clock input.
func buildAttestationReport(sub substrate.Substrate, scope, dataHome string) (*schema.AttestationReport, error) {
	ids, err := sub.GenerationIDs()
	if err != nil {
		return nil, fmt.Errorf("list generations: %w", err)
	}
	sort.Ints(ids)

	pkgs := make([]schema.PackageEvidence, 0)
	included := make([]int, 0, len(ids))
	var skipped []int
	for _, id := range ids {
		m, rerr := sub.ReadManifest(id)
		if errors.Is(rerr, substrate.ErrIncompleteGeneration) {
			skipped = append(skipped, id)
			continue
		}
		if rerr != nil {
			return nil, generationManifestError(id, filepath.Join(dataHome, "generations", strconv.Itoa(id)), "audited", rerr)
		}
		included = append(included, id)
		for i := range m.Entries {
			e := &m.Entries[i]
			ev := schema.PackageEvidence{
				Name:        e.Name,
				Version:     e.Version,
				Generation:  id,
				ContentHash: e.ContentHash,
				InstalledAt: m.ProducedBy.Timestamp,
			}
			if e.Attestation != nil {
				ev.Status = e.Attestation.Status
				ev.PredicateTypes = e.Attestation.PredicateTypes
				ev.AttestationHash = e.Attestation.AttestationHash
				ev.PolicyAtInstall = e.Attestation.PolicyAtInstall
				ev.GateDisabled = e.Attestation.GateDisabled
				ev.CarriedBindings = e.Attestation.CarriedBindings
			}
			pkgs = append(pkgs, ev)
		}
	}
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		if pkgs[i].Version != pkgs[j].Version {
			return pkgs[i].Version < pkgs[j].Version
		}
		if pkgs[i].Generation != pkgs[j].Generation {
			return pkgs[i].Generation < pkgs[j].Generation
		}
		return pkgs[i].ContentHash < pkgs[j].ContentHash
	})

	return &schema.AttestationReport{
		Schema:        schema.AttestationReportSchemaV1,
		GeneratedFrom: schema.ReportSource{Scope: scope, Generations: included, SkippedIncomplete: skipped},
		Packages:      pkgs,
	}, nil
}

func emitAttestationReportText(w io.Writer, rep *schema.AttestationReport) {
	fmt.Fprintf(w, "attestation report (scope %s, %d generation(s), %d package record(s))\n",
		rep.GeneratedFrom.Scope, len(rep.GeneratedFrom.Generations), len(rep.Packages))
	for i := range rep.Packages {
		p := &rep.Packages[i]
		tier := "no record" // pre-v2 generation: entry has no attestation record at all
		switch {
		case len(p.CarriedBindings) > 0:
			tier = p.CarriedBindings[0].Tier
		case p.Status != "":
			tier = p.Status
		}
		fmt.Fprintf(w, "  gen %d  %s %s  [%s]\n", p.Generation, p.Name, p.Version, tier)
	}
}

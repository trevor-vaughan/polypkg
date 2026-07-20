// Command provenancegen mints the carried-provenance fixture trees the e2e
// venom matrix reads over its read-only provenance-fixtures mount. It is a
// host-side pre-step (wired into .taskfiles/integration.yml, task
// provenance:fixtures) run before the compose services start: each variant
// gets its own signed served-repo tree under <out>/<variant>/public, and this
// command prints one "variant=<name> allow_key=<base64>" line per variant so
// venom suites can copy the builder's allow-list key literal.
//
// Usage:
//
//	go run ./tests/e2e/provenancegen -o <out-dir>
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/trevor-vaughan/polypkg/tests/e2e/provenancegen/gen"
)

// variants lists every fixture tree this command builds. Adding a new
// tampered variant (G1, G2, ...) is a one-line addition here: {name, builder}.
var variants = []struct {
	name  string
	build func(dir string) (gen.Tree, error)
}{
	{"genuine", gen.BuildGenuine},
	{"g4-multialgo", gen.BuildG4MultiAlgo},
	{"g4-mismatch", gen.BuildG4MismatchAlgo},
	{"g4-sha1only", gen.BuildG4Sha1Only},
	{"g4-nooverlap", gen.BuildG4NoOverlap},
	{"g1-rogue", gen.BuildG1Rogue},
	{"g2-strip", gen.BuildG2StripSLSA},
	{"g5-relabel", gen.BuildG5Relabel},
	{"g5-mismatch", gen.BuildG5Mismatch},
	{"g6-sigstore-genuine", gen.BuildG6SigstoreGenuine},
	{"g6-no-inclusion-proof", gen.BuildG6NoInclusionProof},
	{"g7-install-refused", gen.BuildG7InstallRefused},
	{"g9-predicate", gen.BuildG9PredicateMismatch},
	{"g10-dupkeys", gen.BuildG10DupKeys},
}

func run(outDir string) error {
	for _, v := range variants {
		tree, err := v.build(filepath.Join(outDir, v.name))
		if err != nil {
			return fmt.Errorf("build variant %s: %w", v.name, err)
		}
		fmt.Printf("variant=%s allow_key=%s\n", v.name, tree.AllowKeyB64)
	}
	return nil
}

func main() {
	outDir := flag.String("o", "", "output directory to build fixture trees into (required)")
	flag.Parse()

	if *outDir == "" {
		fmt.Fprintln(os.Stderr, "provenancegen: -o <out-dir> is required")
		os.Exit(1)
	}

	if err := run(*outDir); err != nil {
		fmt.Fprintln(os.Stderr, "provenancegen:", err)
		os.Exit(1)
	}
}

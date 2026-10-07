package pkglint

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// reYAMLLine extracts the line from a gopkg.in/yaml.v3 error (mirrors
// internal/schema/profile.go's reYAMLLineN).
var reYAMLLine = regexp.MustCompile(`yaml: line (\d+):`)

// Lint validates the package source rooted at dir (expects dir/polypkg.yaml and
// an optional dir/content tree) and returns all findings. It never aborts on
// the first finding — authors fix in batches — but a structural (PKG000)
// failure that prevents a typed parse stops the deeper layers for that file.
func Lint(dir string) (Result, error) {
	var res Result
	path := filepath.Join(dir, "polypkg.yaml")
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path is <dir>/polypkg.yaml where dir is the author-supplied package source
	if err != nil {
		return res, err // I/O error (missing dir) is a real error, not a finding
	}

	// Structural layer: ParsePackage validates against the JSON Schema.
	pkg, perr := schema.ParsePackage(bytesReader(raw), "polypkg.yaml")
	if perr != nil {
		res.Findings = append(res.Findings, structuralFinding(perr))
		return res, nil // cannot run typed layers without a valid struct
	}

	idx, ierr := newDocIndex(raw)
	if ierr != nil {
		// YAML parsed for the struct but not the node tree — locations degrade
		// to none, but we can still run typed layers. Continue with a nil idx.
		idx = &docIndex{}
	}

	res.Findings = append(res.Findings, checkIdentity(pkg, idx)...)
	res.Findings = append(res.Findings, checkActionsAndParams(pkg, idx)...)
	res.Findings = append(res.Findings, checkContent(pkg, idx, dir)...)
	res.Findings = append(res.Findings, checkExtract(pkg, idx, dir)...)

	// Sort deterministically by (line, ruleID, message) so human output and the
	// later canonical SARIF are stable across runs.
	sort.Slice(res.Findings, func(a, b int) bool {
		fa, fb := res.Findings[a], res.Findings[b]
		if fa.Loc.Line != fb.Loc.Line {
			return fa.Loc.Line < fb.Loc.Line
		}
		if fa.RuleID != fb.RuleID {
			return fa.RuleID < fb.RuleID
		}
		return fa.Message < fb.Message
	})
	return res, nil
}

func structuralFinding(err error) Finding {
	f := Finding{RuleID: "PKG000", Severity: SeverityError, Message: err.Error(), File: "polypkg.yaml"}
	if m := reYAMLLine.FindStringSubmatch(err.Error()); m != nil {
		f.Loc = Loc{Line: atoi(m[1])}
	}
	return f
}

// bytesReader adapts a byte slice to the io.Reader ParsePackage expects.
func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// atoi parses a decimal integer, returning 0 on failure (used only on regex
// captures already known to be digits).
func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

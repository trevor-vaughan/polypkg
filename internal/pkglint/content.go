package pkglint

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// checkContent enforces PKG006: every literal param value that references the
// package tree via the "$PKG/" prefix must resolve to a real file under dir.
// $ACTIVE/… (install targets) and !starlark values (non-string) are not content
// refs and are skipped.
func checkContent(pkg *schema.Package, idx *docIndex, dir string) []Finding {
	var out []Finding
	for i, v := range pkg.Actions {
		for name, raw := range v.Params {
			s, ok := raw.(string)
			if !ok || !strings.HasPrefix(s, "$PKG/") {
				continue
			}
			rel := strings.TrimPrefix(s, "$PKG/")
			abs := filepath.Join(dir, filepath.FromSlash(rel))
			if _, err := os.Stat(abs); err != nil {
				out = append(out, Finding{
					RuleID: "PKG006", Severity: SeverityError, File: "polypkg.yaml",
					Loc:     loc(idx.paramNode(i, name)),
					Message: fmt.Sprintf("action %q parameter %q references %q, which does not exist in the package", v.Action, name, rel),
				})
			}
		}
	}
	return out
}

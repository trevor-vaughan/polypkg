package trust

import (
	"fmt"
	"strings"
)

// parseComment splits a polypkg trusted comment into its key=value fields.
// Fields are space-separated; each must be "<key>=<value>" with a non-empty
// key (the value may be empty). Duplicate keys are an error. Unknown keys are
// preserved so callers decide which are required — keeping the format
// forward-compatible.
func parseComment(comment string) (map[string]string, error) {
	out := map[string]string{}
	for _, tok := range strings.Fields(comment) {
		k, v, ok := strings.Cut(tok, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("malformed trusted-comment field %q", tok)
		}
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("duplicate trusted-comment key %q", k)
		}
		out[k] = v
	}
	return out, nil
}

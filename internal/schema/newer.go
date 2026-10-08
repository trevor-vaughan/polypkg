package schema

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// NewerSchemaError reports a polypkg document whose "schema" names the kind
// this binary parses at a higher version: a newer polypkg wrote it. It is
// returned instead of the strict-validation error such a document would
// otherwise produce, which never says why it failed.
type NewerSchemaError struct {
	// Path is the file the document was read from, attached by the caller
	// via WithPath; empty when unknown.
	Path string
	// Found is the document's schema identifier, e.g. "polypkg.ownership/v2".
	Found string
	// Supported is the highest version of that kind this binary reads.
	Supported int
}

func (e *NewerSchemaError) Error() string {
	subject := "this document"
	if e.Path != "" {
		subject = e.Path
	}
	return fmt.Sprintf("%s was written by a newer polypkg (%s; this version reads v%d); upgrade polypkg",
		subject, e.Found, e.Supported)
}

// WithPath attaches path to the first *NewerSchemaError in err's chain that
// has none, and returns err itself. Any other error, and nil, pass through
// unchanged. Callers that read a document from a file wrap their Parse* call
// with it so the message names the file.
func WithPath(err error, path string) error {
	var ne *NewerSchemaError
	if errors.As(err, &ne) && ne.Path == "" {
		ne.Path = path
	}
	return err
}

// checkNotNewer returns a *NewerSchemaError when instanceJSON declares the
// kind schemaJSON's "schema" const names, at a higher version. It runs before
// strict validation because a newer document fails that in ways (an unknown
// field, a const mismatch) that do not say why. Anything it cannot interpret —
// malformed JSON, a missing or non-string schema field, another kind, an equal
// or older version — returns nil and is left to validation, which still
// rejects it: this check never accepts a document.
func checkNotNewer(instanceJSON, schemaJSON []byte) error {
	var doc struct {
		Schema any `json:"schema"`
	}
	if json.Unmarshal(instanceJSON, &doc) != nil {
		return nil
	}
	found, ok := doc.Schema.(string)
	if !ok {
		return nil
	}
	var sch struct {
		Properties struct {
			Schema struct {
				Const string `json:"const"`
			} `json:"schema"`
		} `json:"properties"`
	}
	if json.Unmarshal(schemaJSON, &sch) != nil {
		return nil
	}
	wantKind, wantVersion, ok := parseSchemaID(sch.Properties.Schema.Const)
	if !ok {
		return nil
	}
	gotKind, gotVersion, ok := parseSchemaID(found)
	if !ok || gotKind != wantKind || gotVersion <= wantVersion {
		return nil
	}
	return &NewerSchemaError{Found: found, Supported: wantVersion}
}

// parseSchemaID splits a "polypkg.<kind>/v<N>" identifier into its kind
// ("polypkg.<kind>", non-empty) and its version N (decimal digits only, >= 1).
// A version too large for an int is reported as math.MaxInt.
func parseSchemaID(id string) (kind string, version int, ok bool) {
	const prefix = "polypkg."
	i := strings.LastIndex(id, "/v")
	if !strings.HasPrefix(id, prefix) || i <= len(prefix) {
		return "", 0, false
	}
	digits := id[i+2:]
	if digits == "" || strings.Trim(digits, "0123456789") != "" {
		return "", 0, false
	}
	v, err := strconv.Atoi(digits)
	if errors.Is(err, strconv.ErrRange) {
		// Only digits, so too large to represent: newer than any version
		// this binary knows.
		return id[:i], math.MaxInt, true
	}
	if err != nil || v < 1 {
		return "", 0, false
	}
	return id[:i], v, true
}

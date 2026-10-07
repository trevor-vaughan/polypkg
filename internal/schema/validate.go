package schema

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/text/message"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// schemaBaseURL is the absolute base every embedded schema is registered
// under. The jsonschema compiler resolves a bare file name against the process
// working directory, which leaked the CWD into every validation error as a
// file:// URL. It matches the $id most embedded schemas declare; nothing is
// fetched, because each schema is supplied in-process via AddResource.
const schemaBaseURL = "https://polypkg.dev/schemas/"

// validateAgainstSchema validates instanceJSON against the given embedded JSON
// Schema, with format assertion enabled (so "format" keywords like uri and
// date-time are enforced, not merely annotated). schemaName is the embedded
// file's base name, e.g. "ownership-v1.json".
func validateAgainstSchema(instanceJSON, schemaJSON []byte, schemaName string) error {
	if err := checkNotNewer(instanceJSON, schemaJSON); err != nil {
		return err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(instanceJSON))
	if err != nil {
		return fmt.Errorf("unmarshal for validation: %w", err)
	}
	url := schemaBaseURL + schemaName
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource(url, mustParseSchemaJSON(schemaJSON)); err != nil {
		return fmt.Errorf("add schema resource: %w", err)
	}
	sch, err := compiler.Compile(url)
	if err != nil {
		return fmt.Errorf("compile schema: %w", err)
	}
	if err := sch.Validate(doc); err != nil {
		return fmt.Errorf("schema validation: %w", err)
	}
	return nil
}

// mustParseSchemaJSON parses the embedded JSON Schema bytes. It panics on
// malformed JSON because a broken embedded asset is always a programmer error
// caught in tests or on first use, not a runtime condition.
func mustParseSchemaJSON(data []byte) any {
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		panic(fmt.Sprintf("invalid embedded JSON Schema: %v", err))
	}
	return v
}

// profileFriendlyError converts a jsonschema ValidationError into:
//
//	profile <name> is invalid:
//	  - /path/to/field: human-readable message
//
// one line per leaf cause (nodes with no child Causes). Causes are sorted for
// stable output. SchemaURL and file:// paths are never included.
func profileFriendlyError(name string, ve *jsonschema.ValidationError) error {
	type finding struct {
		pointer string
		message string
	}

	var collect func(e *jsonschema.ValidationError, findings *[]finding)
	collect = func(e *jsonschema.ValidationError, findings *[]finding) {
		if len(e.Causes) == 0 {
			// Leaf: emit one line. Build instance pointer from InstanceLocation.
			pointer := "/" + strings.Join(e.InstanceLocation, "/")
			if pointer == "/" {
				pointer = ""
			}
			msg := e.ErrorKind.LocalizedString(message.NewPrinter(message.MatchLanguage("en")))
			*findings = append(*findings, finding{pointer: pointer, message: msg})
			return
		}
		for _, c := range e.Causes {
			collect(c, findings)
		}
	}

	var findings []finding
	collect(ve, &findings)

	// Stable order: by pointer then message.
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].pointer != findings[j].pointer {
			return findings[i].pointer < findings[j].pointer
		}
		return findings[i].message < findings[j].message
	})

	if len(findings) == 0 {
		return fmt.Errorf("profile %s is invalid: %w", name, ve)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "profile %s is invalid:", name)
	for _, f := range findings {
		if f.pointer != "" {
			fmt.Fprintf(&sb, "\n  - %s: %s", f.pointer, f.message)
		} else {
			fmt.Fprintf(&sb, "\n  - %s", f.message)
		}
	}
	return errors.New(sb.String())
}

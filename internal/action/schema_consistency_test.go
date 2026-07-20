package action

// These guards live in the action package (not schema) because internal/action
// imports internal/schema, so internal/schema must NOT import internal/action.
// The Registry — the single source of truth for actions — is therefore only
// directly reachable from here. Two JSON schemas hardcode a parallel action
// enum that no other test ties back to the Registry, so they can silently
// drift. These tests bind them:
//
//   - package-v1.json lists every dispatchable action the author may declare, so
//     its action enum must equal ALL Registry keys.
//   - ownership-v1.json records entries produced only by FILE-PLACING actions, so
//     its action enum must equal the Registry keys whose FilePlacing == true.
//
// The two assertions coincide today (all 12 actions are file-placing) but are
// semantically distinct, and are written distinctly so the guard stays correct
// when a future non-file-placing action is added.

import (
	"encoding/json"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// schemaActionEnum reads a schema JSON file and extracts the action enum found at
// properties.<arrayProp>.items.properties.action.enum, returning it as []string.
// It fails the running spec (with a clear message) if any node in that path is
// missing or the wrong type, so an absent path can never masquerade as an empty
// enum that accidentally satisfies a ConsistOf against an empty key set.
func schemaActionEnum(path, arrayProp string) []string {
	raw, err := os.ReadFile(path)
	Expect(err).ToNot(HaveOccurred(), "reading schema file %s", path)

	var doc map[string]any
	Expect(json.Unmarshal(raw, &doc)).To(Succeed(), "unmarshalling schema file %s", path)

	node := doc
	for _, step := range []string{"properties", arrayProp, "items", "properties", "action"} {
		next, ok := node[step].(map[string]any)
		Expect(ok).To(BeTrue(), "schema %s missing object at %q", path, step)
		node = next
	}

	enumRaw, ok := node["enum"].([]any)
	Expect(ok).To(BeTrue(), "schema %s missing action enum array", path)
	Expect(enumRaw).ToNot(BeEmpty(), "schema %s action enum must not be empty", path)

	enum := make([]string, 0, len(enumRaw))
	for i, v := range enumRaw {
		s, ok := v.(string)
		Expect(ok).To(BeTrue(), "schema %s action enum index %d is not a string", path, i)
		enum = append(enum, s)
	}
	return enum
}

var _ = Describe("schema action enums", func() {
	var allKeys, filePlacingKeys []string

	BeforeEach(func() {
		allKeys = make([]string, 0, len(Registry))
		filePlacingKeys = filePlacingKeys[:0]
		for name, spec := range Registry {
			allKeys = append(allKeys, name)
			if spec.FilePlacing {
				filePlacingKeys = append(filePlacingKeys, name)
			}
		}
	})

	It("package-v1.json action enum equals every registry action", func() {
		enum := schemaActionEnum("../schema/jsonschema/package-v1.json", "actions")
		Expect(enum).To(ConsistOf(allKeys),
			"package-v1.json action enum must list exactly the Registry keys")
	})

	It("ownership-v1.json action enum equals the file-placing registry actions", func() {
		enum := schemaActionEnum("../schema/jsonschema/ownership-v1.json", "entries")
		Expect(enum).To(ConsistOf(filePlacingKeys),
			"ownership-v1.json action enum must list exactly the file-placing Registry keys")
	})
})

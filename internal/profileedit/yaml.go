package profileedit

import (
	"bytes"
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// applyEdits decodes data to a yaml.Node document, applies each edit to the
// packages section in order, re-validates the encoded result against the
// profile schema, and returns the new file bytes. The input bytes are never
// mutated; on any error (including a validation failure) the returned bytes
// are nil and the caller leaves the file on disk untouched.
//
// path is used only for the schema parser's format dispatch and error
// messages; the YAML extension is guaranteed by the caller.
func applyEdits(data []byte, path string, edits []Edit) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse profile: %w", err)
	}
	root := documentRoot(&doc)
	if root == nil || root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("profile is not a YAML mapping")
	}

	for _, e := range edits {
		if err := applyOne(root, e); err != nil {
			return nil, err
		}
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, fmt.Errorf("encode profile: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("encode profile: %w", err)
	}
	out := buf.Bytes()

	// Validation gate: reject any edit that yields a profile the schema
	// would not accept. The on-disk file stays untouched.
	if _, err := schema.ParseProfile(bytes.NewReader(out), path); err != nil {
		return nil, fmt.Errorf("edit would make the profile invalid: %w", err)
	}
	return out, nil
}

// documentRoot returns the mapping node at the root of a decoded document,
// unwrapping the DocumentNode wrapper.
func documentRoot(doc *yaml.Node) *yaml.Node {
	if doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 {
		return doc.Content[0]
	}
	return doc
}

// applyOne applies a single edit. An empty Version means remove; otherwise
// add or update.
func applyOne(root *yaml.Node, e Edit) error {
	if e.Version == "" {
		return removePackage(root, e)
	}
	return upsertPackage(root, e)
}

// upsertPackage adds or updates package e.Name in scope e.Scope, creating the
// packages map and the scope map if absent. Returns an error if the existing
// packages or scope node is present but not a mapping.
func upsertPackage(root *yaml.Node, e Edit) error {
	pkgs, err := getOrCreateMap(root, "packages")
	if err != nil {
		return err
	}
	scope, err := getOrCreateMap(pkgs, e.Scope)
	if err != nil {
		return fmt.Errorf("packages.%s: %w", e.Scope, err)
	}

	if entry := mapValue(scope, e.Name); entry != nil {
		setVersion(entry, e.Version)
		return nil
	}

	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: e.Name}
	valNode := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	setVersion(valNode, e.Version)
	scope.Content = append(scope.Content, keyNode, valNode)
	return nil
}

// removePackage deletes package e.Name from scope e.Scope. Removing a package
// the scope does not have returns *NotInProfileError with the scope's package
// names sorted. Removing the last package leaves an empty scope mapping, which
// the schema permits (packages.<scope> has no minProperties).
func removePackage(root *yaml.Node, e Edit) error {
	pkgs := mapValue(root, "packages")
	var scope *yaml.Node
	if pkgs != nil {
		scope = mapValue(pkgs, e.Scope)
	}
	if scope == nil {
		return &NotInProfileError{Name: e.Name, Scope: e.Scope}
	}

	idx := mapKeyIndex(scope, e.Name)
	if idx < 0 {
		return &NotInProfileError{Name: e.Name, Scope: e.Scope, Known: mapKeys(scope)}
	}
	// Drop the key/value pair (two consecutive Content entries).
	scope.Content = append(scope.Content[:idx], scope.Content[idx+2:]...)
	return nil
}

// setVersion sets the "version" entry of a package-ref mapping node, forcing
// the value to a double-quoted string so operator-prefixed constraints such
// as ">=1.0.0" round-trip unambiguously as strings.
func setVersion(entry *yaml.Node, version string) {
	if v := mapValue(entry, "version"); v != nil {
		v.Kind = yaml.ScalarNode
		v.Tag = "!!str"
		v.Value = version
		v.Style = yaml.DoubleQuotedStyle
		return
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "version"}
	valNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!str",
		Value: version,
		Style: yaml.DoubleQuotedStyle,
	}
	entry.Content = append(entry.Content, keyNode, valNode)
}

// getOrCreateMap returns the mapping value for key in the mapping node m,
// creating an empty mapping (and the key scalar) if the key is absent.
// Returns an error if the key exists but its value is not a MappingNode —
// appending into a non-mapping node produces a corrupt document.
func getOrCreateMap(m *yaml.Node, key string) (*yaml.Node, error) {
	if v := mapValue(m, key); v != nil {
		if v.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("profile structure is malformed: %s is not a map", key)
		}
		return v, nil
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	valNode := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	m.Content = append(m.Content, keyNode, valNode)
	return valNode, nil
}

// mapValue returns the value node paired with key in mapping node m, or nil.
// Mapping nodes store keys and values as alternating Content entries.
func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// mapKeyIndex returns the Content index of the key scalar for key in mapping
// node m, or -1 if absent.
func mapKeyIndex(m *yaml.Node, key string) int {
	if m.Kind != yaml.MappingNode {
		return -1
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return i
		}
	}
	return -1
}

// mapKeys returns the sorted key names of mapping node m.
func mapKeys(m *yaml.Node) []string {
	if m.Kind != yaml.MappingNode {
		return nil
	}
	keys := make([]string, 0, len(m.Content)/2)
	for i := 0; i+1 < len(m.Content); i += 2 {
		keys = append(keys, m.Content[i].Value)
	}
	sort.Strings(keys)
	return keys
}

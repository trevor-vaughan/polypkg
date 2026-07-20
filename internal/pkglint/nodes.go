package pkglint

import "gopkg.in/yaml.v3"

// docIndex maps package fields to yaml.Node positions for accurate locations.
// It is built from the same bytes ParsePackage consumed. All lookups return a
// zero Loc when the node is absent (location omitted, never fabricated).
type docIndex struct {
	root *yaml.Node // the mapping node of the document
}

// newDocIndex parses raw YAML into a node tree. A parse error here is the
// caller's PKG000 signal (returned error), not a panic.
func newDocIndex(raw []byte) (*docIndex, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	root := &doc
	if doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 {
		root = doc.Content[0]
	}
	return &docIndex{root: root}, nil
}

// mapValue returns the value node for key in a mapping node, or nil.
func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// mapKey returns the KEY node for key in a mapping node (for pointing at the
// key rather than the value), or nil.
func mapKey(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i]
		}
	}
	return nil
}

// actionNode returns the mapping node of the i-th action, or nil.
func (d *docIndex) actionNode(i int) *yaml.Node {
	seq := mapValue(d.root, "actions")
	if seq == nil || seq.Kind != yaml.SequenceNode || i < 0 || i >= len(seq.Content) {
		return nil
	}
	return seq.Content[i]
}

// paramNode returns the KEY node of param `name` inside the i-th action's
// params mapping, or nil.
func (d *docIndex) paramNode(i int, name string) *yaml.Node {
	return mapKey(mapValue(d.actionNode(i), "params"), name)
}

// relationNode returns the value node of the `name` field of the j-th relation
// in the top-level sequence `field` (e.g. "depends"), or nil.
func (d *docIndex) relationNode(field string, j int) *yaml.Node {
	seq := mapValue(d.root, field)
	if seq == nil || seq.Kind != yaml.SequenceNode || j < 0 || j >= len(seq.Content) {
		return nil
	}
	return mapValue(seq.Content[j], "name")
}

// loc converts a node to a Loc (zero when node is nil).
func loc(n *yaml.Node) Loc {
	if n == nil {
		return Loc{}
	}
	return Loc{Line: n.Line, Column: n.Column}
}

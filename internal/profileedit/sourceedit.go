package profileedit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/tailscale/hujson"
	"gopkg.in/yaml.v3"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// ReservedSourceName is the one key under the profile's `sources` map that is
// not a source: it holds the preference-order array. A SourceEdit must never
// add a source with this name — doing so collides with the order array and, on
// a YAML profile, silently corrupts it (scalar fields get written into the
// sequence) while the result still passes schema validation.
const ReservedSourceName = "order"

// ErrReservedSourceName is returned by ApplySourceEdits when a non-remove edit
// targets ReservedSourceName.
var ErrReservedSourceName = errors.New(`source name "order" is reserved for the preference order`)

// SourceEdit is one mutation of the sources section. When Remove is true the
// named source (and its order entry) are deleted; otherwise the source is
// added or updated in place. An update rewrites type, url and trust_root only:
// the source keeps its sources.order position, and a source that is not in
// sources.order is not added to it.
type SourceEdit struct {
	Name       string
	Remove     bool
	Type       string // e.g. "polypkg-native" (add/update only)
	URL        string // must be a valid URI; the schema backstop catches violations
	TrustRoot  string
	OrderFirst bool // prepend to sources.order instead of append (add only)
	// CreateOnly refuses an edit whose source already exists, returning
	// *SourceExistsError. The check runs on the same parse that is written
	// back, so a source added concurrently after a caller's own pre-check is
	// still never overwritten.
	CreateOnly bool
}

// SourceExistsError reports a CreateOnly edit of a source the profile already
// has.
type SourceExistsError struct {
	Name string
}

func (e *SourceExistsError) Error() string {
	return fmt.Sprintf("source %q already exists", e.Name)
}

// SourceNotInProfileError reports a remove of a source the profile doesn't have.
type SourceNotInProfileError struct {
	Name  string
	Known []string // source names present, sorted
}

func (e *SourceNotInProfileError) Error() string {
	if len(e.Known) == 0 {
		return fmt.Sprintf("source %q is not in the profile", e.Name)
	}
	return fmt.Sprintf("source %q is not in the profile (present: %v)", e.Name, e.Known)
}

// ensure SourceNotInProfileError satisfies the error interface at compile time.
var _ error = (*SourceNotInProfileError)(nil)

// ApplySourceEdits loads the profile at path, applies source edits,
// re-validates against the profile schema, and atomically rewrites the file
// (comment-preserving). Returns the original bytes for rollback.
//
// Mirrors the structure of Apply exactly: symlinks are followed, temp+rename
// writes are used, and any schema violation aborts the write.
func ApplySourceEdits(path string, edits []SourceEdit) (original []byte, err error) {
	path = filepath.Clean(path)

	// Refuse to add a source under the reserved order key before any file I/O,
	// so a corrupting edit can never reach the YAML/JSONC writers regardless of
	// caller. Removing it is left to the normal path (the schema's required
	// "order" backstop rejects that safely).
	for _, e := range edits {
		if !e.Remove && e.Name == ReservedSourceName {
			return nil, fmt.Errorf("cannot add source %q: %w", e.Name, ErrReservedSourceName)
		}
	}

	original, err = os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}

	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("resolve profile path: %w", err)
	}

	var out []byte
	if isYAMLPath(path) {
		out, err = applySourceEditsYAML(original, resolved, edits)
	} else {
		out, err = applySourceEditsJSONC(original, resolved, edits)
	}
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(resolved)
	if err != nil {
		return nil, fmt.Errorf("stat profile: %w", err)
	}

	if err := atomicWrite(resolved, out, info.Mode().Perm()); err != nil {
		return nil, err
	}
	return original, nil
}

// ---------------------------------------------------------------------------
// YAML path
// ---------------------------------------------------------------------------

// applySourceEditsYAML decodes data to a yaml.Node document, applies each
// source edit in order, re-validates the encoded result, and returns the new
// file bytes. Mirrors applyEdits for the sources section.
func applySourceEditsYAML(data []byte, path string, edits []SourceEdit) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse profile: %w", err)
	}
	root := documentRoot(&doc)
	if root == nil || root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("profile is not a YAML mapping")
	}

	for _, e := range edits {
		if err := applyOneSourceYAML(root, e); err != nil {
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

	if _, err := schema.ParseProfile(bytes.NewReader(out), path); err != nil {
		return nil, fmt.Errorf("edit would make the profile invalid: %w", err)
	}
	return out, nil
}

func applyOneSourceYAML(root *yaml.Node, e SourceEdit) error {
	if e.Remove {
		return removeSourceYAML(root, e)
	}
	return upsertSourceYAML(root, e)
}

// upsertSourceYAML adds or updates the named source under sources:<name>. A
// new source joins sources.order (appended, or prepended per OrderFirst); an
// update never touches sources.order.
func upsertSourceYAML(root *yaml.Node, e SourceEdit) error {
	sources, err := getOrCreateMap(root, "sources")
	if err != nil {
		return err
	}

	// Update an existing source in place, touching only type/url/trust_root so
	// unmanaged keys (e.g. trust_doc) survive. Its place in sources.order is
	// the operator's choice, including leaving it out to make it reachable
	// only through a per-package source pin, so an update leaves order alone.
	if entry := mapValue(sources, e.Name); entry != nil {
		if e.CreateOnly {
			return &SourceExistsError{Name: e.Name}
		}
		setStringField(entry, "type", e.Type)
		setStringField(entry, "url", e.URL)
		setStringField(entry, "trust_root", e.TrustRoot)
		return nil
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: e.Name}
	valNode := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	setStringField(valNode, "type", e.Type)
	setStringField(valNode, "url", e.URL)
	setStringField(valNode, "trust_root", e.TrustRoot)
	sources.Content = append(sources.Content, keyNode, valNode)

	// A new source joins sources.order.
	orderNode, err := getOrCreateSeq(sources, "order")
	if err != nil {
		return fmt.Errorf("sources.order: %w", err)
	}
	if !seqContains(orderNode, e.Name) {
		if e.OrderFirst {
			prependSeqItem(orderNode, e.Name)
		} else {
			appendSeqItem(orderNode, e.Name)
		}
	}
	return nil
}

// removeSourceYAML deletes sources.<name> and removes it from sources.order.
// Returns *SourceNotInProfileError when the source is absent.
func removeSourceYAML(root *yaml.Node, e SourceEdit) error {
	sources := mapValue(root, "sources")
	if sources == nil || mapKeyIndex(sources, e.Name) < 0 {
		var known []string
		if sources != nil {
			for _, k := range mapKeys(sources) {
				if k != "order" {
					known = append(known, k)
				}
			}
			sort.Strings(known)
		}
		return &SourceNotInProfileError{Name: e.Name, Known: known}
	}

	idx := mapKeyIndex(sources, e.Name)
	sources.Content = append(sources.Content[:idx], sources.Content[idx+2:]...)

	// Remove from order sequence if present.
	if orderNode := mapValue(sources, "order"); orderNode != nil && orderNode.Kind == yaml.SequenceNode {
		removeSeqItem(orderNode, e.Name)
	}
	return nil
}

// ---------------------------------------------------------------------------
// YAML sequence helpers
// ---------------------------------------------------------------------------

// getOrCreateSeq returns the sequence node for key in mapping node m, creating
// an empty sequence if absent. Returns an error if the node exists but is not a
// sequence.
func getOrCreateSeq(m *yaml.Node, key string) (*yaml.Node, error) {
	if v := mapValue(m, key); v != nil {
		if v.Kind != yaml.SequenceNode {
			return nil, fmt.Errorf("profile structure is malformed: %s is not a sequence", key)
		}
		return v, nil
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	valNode := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	// Prepend the order key so it comes before the source name keys for
	// readability: sources: { order: [...], name: {...} }.
	m.Content = append([]*yaml.Node{keyNode, valNode}, m.Content...)
	return valNode, nil
}

// seqContains reports whether the sequence node contains a scalar with value v.
func seqContains(seq *yaml.Node, v string) bool {
	for _, item := range seq.Content {
		if item.Kind == yaml.ScalarNode && item.Value == v {
			return true
		}
	}
	return false
}

// appendSeqItem appends a new scalar item to the sequence node.
func appendSeqItem(seq *yaml.Node, v string) {
	seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v})
}

// prependSeqItem inserts a new scalar item at the front of the sequence node.
func prependSeqItem(seq *yaml.Node, v string) {
	node := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v}
	seq.Content = append([]*yaml.Node{node}, seq.Content...)
}

// removeSeqItem removes the first scalar item with value v from the sequence.
func removeSeqItem(seq *yaml.Node, v string) {
	for i, item := range seq.Content {
		if item.Kind == yaml.ScalarNode && item.Value == v {
			seq.Content = append(seq.Content[:i], seq.Content[i+1:]...)
			return
		}
	}
}

// setStringField sets the scalar value for key in the mapping node m. If the
// key already exists its value is updated in place; otherwise a new key/value
// pair is appended. Values are written as plain scalars (no quoting) because
// source fields (type, url, trust_root) are not operator-prefixed constraint
// strings and round-trip cleanly as plain scalars in YAML.
func setStringField(m *yaml.Node, key, value string) {
	if v := mapValue(m, key); v != nil {
		v.Kind = yaml.ScalarNode
		v.Tag = "!!str"
		v.Value = value
		v.Style = 0
		return
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	valNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
	m.Content = append(m.Content, keyNode, valNode)
}

// ---------------------------------------------------------------------------
// JSONC path
// ---------------------------------------------------------------------------

// applySourceEditsJSONC applies source edits to a JSONC/JSON profile. The
// strategy mirrors applyEditsJSONC: build RFC 6902 patches, apply them to the
// hujson AST (preserving comments byte-for-byte on untouched regions), then
// re-validate.
//
// Source names must match the same ^[a-zA-Z0-9_-]+$ pattern the schema enforces
// on source property names, so they never contain '/' or '~' and need no RFC
// 6901 pointer escaping.
func applySourceEditsJSONC(data []byte, path string, edits []SourceEdit) ([]byte, error) {
	v, err := hujson.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse profile: %w", err)
	}

	for _, e := range edits {
		if err := applyOneSourceJSONC(&v, e); err != nil {
			return nil, err
		}
	}

	out := v.Pack()

	if _, err := schema.ParseProfile(bytes.NewReader(out), path); err != nil {
		return nil, fmt.Errorf("edit would make the profile invalid: %w", err)
	}
	return out, nil
}

func applyOneSourceJSONC(v *hujson.Value, e SourceEdit) error {
	if e.Remove {
		return removeSourceJSONC(v, e)
	}
	return upsertSourceJSONC(v, e)
}

// upsertSourceJSONC adds or updates /sources/<name>. A new source joins the
// /sources/order array; an update leaves that array alone. It creates /sources
// if absent (mirroring the package path's parent-creation pattern).
//
// When the source already exists, only the managed fields (type, url,
// trust_root) are patched individually so that unmanaged keys such as
// trust_doc are left untouched. When the source is new, the whole object is
// added in one operation.
func upsertSourceJSONC(v *hujson.Value, e SourceEdit) error {
	var ops []map[string]any

	sourcesPtr := "/sources"
	leafPtr := "/sources/" + e.Name
	orderPtr := "/sources/order"

	sourcesVal := v.Find(sourcesPtr)
	if sourcesVal == nil {
		// Create the sources object; will include order + name below.
		ops = append(ops, map[string]any{"op": "add", "path": sourcesPtr, "value": json.RawMessage("{}")})
	} else if _, ok := sourcesVal.Value.(*hujson.Object); !ok {
		return fmt.Errorf("profile structure is malformed: sources is not a map")
	}

	sourceExists := v.Find(leafPtr) != nil
	if sourceExists && e.CreateOnly {
		return &SourceExistsError{Name: e.Name}
	}

	if sourceExists {
		// Update in place: issue per-field RFC 6902 "add" ops so that unmanaged
		// keys (e.g. trust_doc) on the existing source object are preserved.
		// RFC 6902 §4.1: "add" on an existing object member replaces its value.
		for _, kv := range []struct{ key, val string }{
			{"type", e.Type},
			{"url", e.URL},
			{"trust_root", e.TrustRoot},
		} {
			encoded, err := json.Marshal(kv.val)
			if err != nil {
				return fmt.Errorf("marshal source field %s: %w", kv.key, err)
			}
			ops = append(ops, map[string]any{
				"op":    "add",
				"path":  leafPtr + "/" + kv.key,
				"value": json.RawMessage(encoded),
			})
		}
	} else {
		// New source: add the whole object in one operation.
		srcVal, err := json.Marshal(map[string]string{
			"type":       e.Type,
			"url":        e.URL,
			"trust_root": e.TrustRoot,
		})
		if err != nil {
			return fmt.Errorf("marshal source value: %w", err)
		}
		ops = append(ops, map[string]any{"op": "add", "path": leafPtr, "value": json.RawMessage(srcVal)})
	}

	patch, err := json.Marshal(ops)
	if err != nil {
		return fmt.Errorf("marshal patch: %w", err)
	}
	if err := v.Patch(patch); err != nil {
		return err
	}
	if sourceExists {
		// As on the YAML path, an update leaves /sources/order alone.
		return nil
	}

	// A new source joins the order array. This runs after the source patch so
	// the sources object exists.
	return ensureInOrderJSONC(v, orderPtr, e.Name, e.OrderFirst)
}

// ensureInOrderJSONC ensures that name appears in the JSON array at arrayPtr.
// If the array is absent it is created (empty) first. If name is already
// present no change is made. Otherwise it is prepended or appended per first.
func ensureInOrderJSONC(v *hujson.Value, arrayPtr, name string, first bool) error {
	orderVal := v.Find(arrayPtr)

	// If order array doesn't exist yet, create it.
	if orderVal == nil {
		emptyArr := json.RawMessage("[]")
		createPatch, err := json.Marshal([]map[string]any{
			{"op": "add", "path": arrayPtr, "value": emptyArr},
		})
		if err != nil {
			return fmt.Errorf("marshal order-create patch: %w", err)
		}
		if err := v.Patch(createPatch); err != nil {
			return fmt.Errorf("create order array: %w", err)
		}
		orderVal = v.Find(arrayPtr)
	}

	// Check whether name is already in the array.
	if orderVal != nil {
		if arr, ok := orderVal.Value.(*hujson.Array); ok {
			for i := range arr.Elements {
				lit, ok := arr.Elements[i].Value.(hujson.Literal)
				if !ok {
					continue
				}
				var s string
				if err := json.Unmarshal([]byte(lit), &s); err != nil {
					continue
				}
				if s == name {
					return nil // already present
				}
			}
		}
	}

	// Append or prepend.
	nameJSON, err := json.Marshal(name)
	if err != nil {
		return fmt.Errorf("marshal source name: %w", err)
	}
	var insertPath string
	if first {
		insertPath = arrayPtr + "/0"
	} else {
		insertPath = arrayPtr + "/-"
	}
	insertPatch, err := json.Marshal([]map[string]any{
		{"op": "add", "path": insertPath, "value": json.RawMessage(nameJSON)},
	})
	if err != nil {
		return fmt.Errorf("marshal order-insert patch: %w", err)
	}
	return v.Patch(insertPatch)
}

// removeSourceJSONC removes /sources/<name> and its entry from /sources/order.
// Returns *SourceNotInProfileError when the source is absent.
func removeSourceJSONC(v *hujson.Value, e SourceEdit) error {
	leafPtr := "/sources/" + e.Name

	if v.Find(leafPtr) == nil {
		return &SourceNotInProfileError{
			Name:  e.Name,
			Known: jsoncSourceKeys(v),
		}
	}

	// Remove the source entry.
	removePatch, err := json.Marshal([]map[string]any{
		{"op": "remove", "path": leafPtr},
	})
	if err != nil {
		return fmt.Errorf("marshal patch: %w", err)
	}
	if err := v.Patch(removePatch); err != nil {
		return err
	}

	// Remove from order array if present.
	return removeFromOrderJSONC(v, "/sources/order", e.Name)
}

// removeFromOrderJSONC removes the first occurrence of name from the JSON array
// at arrayPtr. A no-op if the array is absent or name is not in it.
func removeFromOrderJSONC(v *hujson.Value, arrayPtr, name string) error {
	orderVal := v.Find(arrayPtr)
	if orderVal == nil {
		return nil
	}
	arr, ok := orderVal.Value.(*hujson.Array)
	if !ok {
		return nil
	}
	for i := range arr.Elements {
		lit, ok := arr.Elements[i].Value.(hujson.Literal)
		if !ok {
			continue
		}
		var s string
		if err := json.Unmarshal([]byte(lit), &s); err != nil {
			continue
		}
		if s == name {
			removePatch, err := json.Marshal([]map[string]any{
				{"op": "remove", "path": fmt.Sprintf("%s/%d", arrayPtr, i)},
			})
			if err != nil {
				return fmt.Errorf("marshal order-remove patch: %w", err)
			}
			return v.Patch(removePatch)
		}
	}
	return nil
}

// jsoncSourceKeys returns the sorted source names from /sources (excluding the
// "order" key), or nil if /sources is absent or not an object.
func jsoncSourceKeys(v *hujson.Value) []string {
	sourcesVal := v.Find("/sources")
	if sourcesVal == nil {
		return nil
	}
	obj, ok := sourcesVal.Value.(*hujson.Object)
	if !ok {
		return nil
	}
	var keys []string
	for i := range obj.Members {
		lit, ok := obj.Members[i].Name.Value.(hujson.Literal)
		if !ok {
			continue
		}
		var s string
		if err := json.Unmarshal([]byte(lit), &s); err != nil {
			continue
		}
		if s != "order" {
			keys = append(keys, s)
		}
	}
	sort.Strings(keys)
	return keys
}

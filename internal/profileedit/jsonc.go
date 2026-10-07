package profileedit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/tailscale/hujson"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// applyEditsJSONC applies edits to a JSONC/JSON profile byte slice.
//
// Strategy: parse the file with hujson.Parse (builds a comment-preserving AST),
// build an RFC 6902 patch document for the requested edits, apply it with
// v.Patch, then emit with v.Pack() which is byte-for-byte identical to the
// input on untouched parts (hujson's documented guarantee).
//
// Package names match ^[a-zA-Z0-9_-]+$ per profile-v1.json schema propertyNames,
// so they never contain '/' or '~' and require no RFC 6901 pointer escaping.
func applyEditsJSONC(data []byte, path string, edits []Edit) ([]byte, error) {
	v, err := hujson.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse profile: %w", err)
	}

	for _, e := range edits {
		// On patch failure v may be partially mutated but is discarded here.
		// That is harmless: Pack and atomicWrite are never reached on this path.
		if err := applyOneJSONC(&v, e); err != nil {
			return nil, err
		}
	}

	out := v.Pack()

	// Validation gate: reject any edit that yields a profile the schema
	// would not accept. The on-disk file stays untouched.
	if _, err := schema.ParseProfile(bytes.NewReader(out), path); err != nil {
		return nil, fmt.Errorf("edit would make the profile invalid: %w", err)
	}
	return out, nil
}

// applyOneJSONC applies a single edit to the hujson AST.
func applyOneJSONC(v *hujson.Value, e Edit) error {
	if e.Version == "" {
		return removePackageJSONC(v, e)
	}
	return upsertPackageJSONC(v, e)
}

// upsertPackageJSONC adds or updates /packages/<scope>/<name> in the AST.
// If the /packages or /packages/<scope> containers are absent, they are
// created with "add" ops before the leaf op is emitted. RFC 6902 "add" on
// a deep path fails if intermediate nodes are missing (section 4), so we
// detect and create parents explicitly.
//
// Pre-checks gate the path before hujson.Patch is called: if "packages" or
// "packages/<scope>" is present but is not an object (e.g. it is an array),
// hujson would return an opaque internal message like "invalid array index:
// user". We mirror the YAML path's wording instead.
func upsertPackageJSONC(v *hujson.Value, e Edit) error {
	// Build the patches needed to guarantee intermediate containers exist.
	var ops []map[string]any

	pkgsPtr := "/packages"
	scopePtr := "/packages/" + e.Scope
	leafPtr := "/packages/" + e.Scope + "/" + e.Name

	pkgsVal := v.Find(pkgsPtr)
	if pkgsVal == nil {
		ops = append(ops, map[string]any{"op": "add", "path": pkgsPtr, "value": json.RawMessage("{}")})
	} else if _, ok := pkgsVal.Value.(*hujson.Object); !ok {
		return fmt.Errorf("profile structure is malformed: packages is not a map")
	}

	scopeVal := v.Find(scopePtr)
	if scopeVal == nil {
		ops = append(ops, map[string]any{"op": "add", "path": scopePtr, "value": json.RawMessage("{}")})
	} else if _, ok := scopeVal.Value.(*hujson.Object); !ok {
		return fmt.Errorf("profile structure is malformed: packages.%s is not a map", e.Scope)
	}

	// "add" on an existing member replaces it (RFC 6902 §4.1), so a single op
	// covers both the add-new and update-existing cases.
	pkgVal, err := json.Marshal(map[string]string{"version": e.Version})
	if err != nil {
		return fmt.Errorf("marshal package value: %w", err)
	}
	ops = append(ops, map[string]any{"op": "add", "path": leafPtr, "value": json.RawMessage(pkgVal)})

	patch, err := json.Marshal(ops)
	if err != nil {
		return fmt.Errorf("marshal patch: %w", err)
	}
	return v.Patch(patch)
}

// removePackageJSONC removes /packages/<scope>/<name> from the AST.
// Removing a non-existent member is an RFC 6902 error; we pre-check and
// return *NotInProfileError with the sorted known names in that scope.
func removePackageJSONC(v *hujson.Value, e Edit) error {
	scopePtr := "/packages/" + e.Scope
	leafPtr := "/packages/" + e.Scope + "/" + e.Name

	// If the leaf is present we can remove it directly.
	if v.Find(leafPtr) != nil {
		patch, err := json.Marshal([]map[string]any{
			{"op": "remove", "path": leafPtr},
		})
		if err != nil {
			return fmt.Errorf("marshal patch: %w", err)
		}
		return v.Patch(patch)
	}

	// Package is absent — collect known names from the scope for the error.
	scopeVal := v.Find(scopePtr)
	return &NotInProfileError{
		Name:  e.Name,
		Scope: e.Scope,
		Known: jsoncObjectKeys(scopeVal),
	}
}

// jsoncObjectKeys returns the sorted member names of the hujson Value if it is
// an object, or nil otherwise.
func jsoncObjectKeys(v *hujson.Value) []string {
	if v == nil {
		return nil
	}
	obj, ok := v.Value.(*hujson.Object)
	if !ok {
		return nil
	}
	keys := make([]string, 0, len(obj.Members))
	for i := range obj.Members {
		lit, ok := obj.Members[i].Name.Value.(hujson.Literal)
		if !ok {
			continue
		}
		var s string
		if err := json.Unmarshal([]byte(lit), &s); err != nil {
			continue
		}
		keys = append(keys, s)
	}
	sort.Strings(keys)
	return keys
}

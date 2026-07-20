package alternatives

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// SelectionsFile is the basename of the per-scope manual-selection store. It
// lives directly under the substrate's state area (Substrate.StateRoot()),
// beside — never inside — the alternatives middle-link area (Reconcile's
// prune loop would delete a control file placed in AltRoot).
const SelectionsFile = "alternatives-selections.json"

// SelectionsPath returns the selection-store path for a substrate state root.
func SelectionsPath(stateRoot string) string {
	return filepath.Join(stateRoot, SelectionsFile)
}

// Selections maps an alternative name to the operator-chosen providing package.
// Absence of a key means auto mode for that name.
type Selections map[string]string

// LoadSelections reads the selection store at path. A missing file yields an
// empty (non-nil) Selections and no error; a present but malformed file is an
// error so operator intent is never silently discarded.
func LoadSelections(path string) (Selections, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return Selections{}, nil
		}
		return nil, fmt.Errorf("read selections: %w", err)
	}
	sel := Selections{}
	if err := json.Unmarshal(data, &sel); err != nil {
		return nil, fmt.Errorf("parse selections %q: %w", path, err)
	}
	return sel, nil
}

// SaveSelections writes sel to path atomically (temp + rename) at mode 0o600,
// creating the parent directory if absent. JSON object marshaling sorts keys,
// so the file is reproducible.
func SaveSelections(path string, sel Selections) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	data, err := json.MarshalIndent(sel, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal selections: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	return os.Rename(tmp, path)
}

package cli

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

// generationManifestError turns a failure to read generation id's manifest
// into the user-facing error for a command that would have done verb ("activated",
// "pinned") with it. genDir is the generation's directory, named in hints so
// the user can inspect it. The three cases need different next steps:
//   - incomplete (no manifest): an interrupted apply; gc removes it.
//   - damaged (present but unusable): corruption or tampering; gc keeps it as
//     evidence, so the hint is to inspect it, never to run gc.
//   - written by a newer polypkg: not damage; the fix is to upgrade.
//   - any other read error (EACCES, EIO): nothing is known about the
//     generation; the hint is about permissions and the filesystem.
func generationManifestError(id int, genDir, verb string, err error) *CLIError {
	var ne *schema.NewerSchemaError
	switch {
	case errors.As(err, &ne):
		return newerStateError(err, ne)
	case errors.Is(err, substrate.ErrIncompleteGeneration):
		return &CLIError{
			Msg:  fmt.Sprintf("generation %d is incomplete: an interrupted apply left it without a manifest, so it cannot be %s", id, verb),
			Hint: "run `polypkg gc` to remove it, and `polypkg status -v` to list the other generations",
			Err:  err,
		}
	case errors.Is(err, substrate.ErrDamagedGeneration):
		return &CLIError{
			Msg:  fmt.Sprintf("generation %d's manifest is damaged: it does not parse or names another generation, so it cannot be %s", id, verb),
			Hint: fmt.Sprintf("inspect %s for corruption or tampering, and delete it by hand only if it is not needed as evidence", genDir),
			Err:  err,
		}
	default:
		return &CLIError{
			Msg:  fmt.Sprintf("cannot read generation %d's manifest", id),
			Hint: fmt.Sprintf("check the permissions of %s and the health of its filesystem", filepath.Join(genDir, "manifest.json")),
			Err:  err,
		}
	}
}

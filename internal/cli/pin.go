package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/trevor-vaughan/polypkg/internal/audit"
	"github.com/trevor-vaughan/polypkg/internal/lock"
	"github.com/trevor-vaughan/polypkg/internal/paths"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

// newGenerationCmd is the parent of pin/unpin so the surface reads
// `polypkg generation pin <id>` (mirrors the apply-semantics spec wording).
func newGenerationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generation",
		Short: "Manage retained generations (pin/unpin)",
		Long: `Each apply creates a new generation: an immutable snapshot of the package
set that was active at that point. Generations are retained according to the
garbage-collection policy and pruned automatically once that limit is reached.

Pinning exempts a generation from automatic GC. A pinned generation is kept
indefinitely regardless of how many newer generations have been applied.

Subcommands: pin, unpin.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			return WrapError(cmd, format, "generation", &CLIError{
				Msg:  fmt.Sprintf("unknown generation subcommand %q", args[0]),
				Hint: "run `polypkg status -v` to list generations",
			})
		},
	}
	cmd.AddCommand(newGenerationPinCmd())
	cmd.AddCommand(newGenerationUnpinCmd())
	return cmd
}

func newGenerationPinCmd() *cobra.Command {
	var reason string
	cmd := &cobra.Command{
		Use:   "pin <generation-id>",
		Short: "Pin a generation so it is exempt from automatic GC",
		Long: `Marks a generation so that GC never removes it, regardless of how many newer
generations accumulate. Pinning is useful before a risky change (so there is a
known-good generation to roll back to) or to preserve a baseline for auditing.

Find the generation id in the output of ` + "`polypkg status -v`" + `.

The optional --reason flag records a free-form annotation alongside the pin
so that the purpose is visible when reviewing pinned generations later.`,
		Example: "  # Pin the current generation before a risky change\n" +
			"  polypkg status -v\n" +
			"  polypkg generation pin 4 --reason \"known-good before kernel bump\"",
		Args: needsArgs(1, 1, "<generation-id>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			id, err := strconv.Atoi(args[0])
			if err != nil {
				return WrapError(cmd, format, "pin", &CLIError{
					Msg:  fmt.Sprintf("invalid generation id %q (expected a number)", args[0]),
					Hint: "run `polypkg status -v` to list generation ids",
					Err:  err,
				})
			}
			return WrapError(cmd, format, "pin", runPin(cmd, id, reason, format))
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "Free-form reason recorded with the pin")
	return cmd
}

func newGenerationUnpinCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unpin <generation-id>",
		Short: "Remove a generation pin",
		Long: `Removes the pin from a generation so it is eligible for garbage collection
again. Once unpinned, the generation will be pruned by the next GC pass if it
falls outside the retention policy.`,
		Example: "  polypkg generation unpin 4",
		Args:    needsArgs(1, 1, "<generation-id>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, ferr := resolveFormat(cmd)
			if ferr != nil {
				return ferr
			}
			id, err := strconv.Atoi(args[0])
			if err != nil {
				return WrapError(cmd, format, "unpin", &CLIError{
					Msg:  fmt.Sprintf("invalid generation id %q (expected a number)", args[0]),
					Hint: "run `polypkg status -v` to list generation ids",
					Err:  err,
				})
			}
			return WrapError(cmd, format, "unpin", runUnpin(cmd, id, format))
		},
	}
}

func runPin(cmd *cobra.Command, id int, reason string, format Format) error {
	ctx := cmd.Context()
	dataHome, err := paths.UserDataHome()
	if err != nil {
		return err
	}
	stateHome, err := paths.UserStateHome()
	if err != nil {
		return err
	}
	sub, err := substrate.New("store", dataHome)
	if err != nil {
		return fmt.Errorf("open substrate: %w", err)
	}
	lockPath := filepath.Join(stateHome, "apply.lock")
	l, err := lock.Acquire(ctx, lockPath,
		lock.Options{TxID: "pin", Command: "polypkg generation pin"})
	if err != nil {
		return lockError(lockPath, err)
	}
	defer func() { _ = l.Release() }()

	w, err := audit.NewFileWriter(filepath.Join(stateHome, "audit.log"))
	if err != nil {
		return fmt.Errorf("open audit writer: %w", err)
	}
	defer func() { _ = w.Close() }()

	if err := sub.PinGeneration(id, reason); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &CLIError{
				Msg:  fmt.Sprintf("generation %d does not exist", id),
				Hint: "run `polypkg status -v` to list retained generations",
				Err:  err,
			}
		}
		return err
	}

	_ = w.Write(audit.Event{
		Scope: "user", TxID: "pin", Event: "pin.add",
		Fields: map[string]any{"gen_id": id, "reason": reason, "pinned_by": osUserOrUnknown()},
	})
	EmitResult(cmd, format, "pin", map[string]any{
		"gen_id": id,
		"reason": reason,
	}, func(w *bytes.Buffer, d map[string]any) {
		fmt.Fprintf(w, "pinned generation %d\n", d["gen_id"])
	})
	return nil
}

func runUnpin(cmd *cobra.Command, id int, format Format) error {
	ctx := cmd.Context()
	dataHome, err := paths.UserDataHome()
	if err != nil {
		return err
	}
	stateHome, err := paths.UserStateHome()
	if err != nil {
		return err
	}
	sub, err := substrate.New("store", dataHome)
	if err != nil {
		return fmt.Errorf("open substrate: %w", err)
	}
	lockPath := filepath.Join(stateHome, "apply.lock")
	l, err := lock.Acquire(ctx, lockPath,
		lock.Options{TxID: "unpin", Command: "polypkg generation unpin"})
	if err != nil {
		return lockError(lockPath, err)
	}
	defer func() { _ = l.Release() }()

	w, err := audit.NewFileWriter(filepath.Join(stateHome, "audit.log"))
	if err != nil {
		return fmt.Errorf("open audit writer: %w", err)
	}
	defer func() { _ = w.Close() }()

	if err := sub.UnpinGeneration(id); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &CLIError{
				Msg:  fmt.Sprintf("generation %d does not exist", id),
				Hint: "run `polypkg status -v` to list retained generations",
				Err:  err,
			}
		}
		return err
	}
	_ = w.Write(audit.Event{
		Scope: "user", TxID: "unpin", Event: "pin.remove",
		Fields: map[string]any{"gen_id": id},
	})
	EmitResult(cmd, format, "unpin", map[string]any{
		"gen_id": id,
	}, func(w *bytes.Buffer, d map[string]any) {
		fmt.Fprintf(w, "unpinned generation %d\n", d["gen_id"])
	})
	return nil
}

// osUserOrUnknown returns $USER or "unknown" — mirrors the substrate's
// PinGeneration behaviour so audit and persisted pin metadata agree.
func osUserOrUnknown() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "unknown"
}

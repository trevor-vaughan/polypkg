# AGENTS.md

Guidance for AI agents and contributors working on polypkg. This file covers
conventions that aren't obvious from the code alone. For build/test/architecture
details, see `CONTRIBUTING.md` and `docs/dev/`.

## Terminology: verbs vs. actions

Two distinct concepts share overlapping spellings. Keep them straight — they are
named, tested, and renamed independently, and conflating them is an easy mistake.

- **verb** — a **CLI subcommand** the user types: `install`, `remove`, `upgrade`,
  `search`, `list`. This is the cobra command tree in `internal/cli`. Phrases
  like "the imperative verbs" and the per-subcommand e2e suites
  (`tests/integration/e2e_verbs_test.go`) use this sense.
- **action** — a **declarative install-time operation** a package declares in its
  `polypkg.yaml`, run at a lifecycle `phase` (`pre-place` … `post-deactivate`).
  Manifests list them under `actions:`, each entry naming a `phase` and an
  `action`. The set lives in `internal/action` (registry + one handler per
  action: `install`, `dir`, `path`, `symlink`, `alternatives`, …) and is
  validated by `internal/pkglint` (`actionphase_test.go`).

The spellings overlap — `install` is both a CLI verb and a manifest action — but
the layers are separate. Never rename one sense into the other: CLI-subcommand
"verbs" stay "verb"; manifest/lint "actions" stay "action". (The concept was
renamed from "verb" to "action" on the manifest side in 2026-07; the CLI side
was intentionally left as "verb".)

## CLI command grouping

polypkg's cobra commands are organized by **lifecycle phase**, not as a flat
alphabetical list, so that `--help` reads as a guide to the workflow. This
applies to the root command and to any subcommand tree large enough to benefit.

### The pattern

Each command that groups its children declares the grouping with a single
table that is the only place a child's group is set. The slice order drives
both the group display order and the order within each group:

```go
for _, g := range []struct {
    id    string
    title string
    cmds  []*cobra.Command
}{
    {"getting-started", "Getting started:", []*cobra.Command{newInitCmd()}},
    // ...one entry per group...
} {
    parent.AddGroup(&cobra.Group{ID: g.id, Title: g.title})
    for _, c := range g.cmds {
        c.GroupID = g.id
        parent.AddCommand(c)
    }
}
```

See `internal/cli/root.go` (top-level commands) and `internal/cli/repo.go`
(`repo` subcommands) for the live examples.

### Rules

- **Register the group before adding its commands.** cobra panics at startup if
  a command's `GroupID` names a group the parent hasn't registered. The table
  above does both in one pass, so keep using it.
- **Group titles end with a colon** (`"Build & status:"`) to match cobra's
  built-in `"Available Commands:"` / `"Additional Commands:"` headers.
- **Leave auto-injected and hidden commands ungrouped.** `help` and `completion`
  carry no `GroupID` and fall under cobra's "Additional Commands" by design; the
  hidden `eval-starlark` re-exec entrypoint stays ungrouped too.
- **Insertion order is the contract.** The root sets
  `cobra.EnableCommandSorting = false` (a package-level global) so commands list
  in authored order rather than alphabetically. When you add a subcommand
  anywhere, place it where you want it to appear in help.

### When to group a subcommand tree

Grouping is opt-in per command — it pays off as soon as the children fall into
distinct roles, even in a short menu. Apply it the way the root, `repo`,
`source`, and `alternatives` do.

- **Group** when the subcommands span distinct lifecycle phases (`repo`) or
  split cleanly along read-vs-write lines (`source` and `alternatives` each set
  a safe `list` apart from the verbs that mutate state). A single command alone
  in its own group is fine when it sits alongside other groups in a grouped menu
  (e.g. `repo key`).
- **Stay flat** when the children don't differentiate: a two-command pair that
  reads as one unit (`generation`'s pin/unpin) or a single-subcommand menu
  (`config`). Headers there are noise.

The invariant in `internal/cli/root_test.go` ("never partially groups a
command's subcommands") enforces *completeness*: once a command defines any
group, every user-facing subcommand must land in a registered group. It does
not force a command to group — that judgment is yours, per the guidance above.

## CLI output and errors

Every command supports `--format text|json` (a persistent flag on the root,
default `text`). A new command must honor both modes — never write straight to
`os.Stdout`/`os.Stderr`, and never `fmt.Println` a result directly. Use the
helpers in `internal/cli/format.go` and the error types in
`internal/cli/clierr.go`:

```go
RunE: func(cmd *cobra.Command, args []string) error {
    format, ferr := resolveFormat(cmd)
    if ferr != nil {
        return ferr
    }
    return WrapError(cmd, format, "repo init", runRepoInit(cmd, args, format))
},
```

- **Success output** goes through `EmitResult(cmd, format, command, data, textRenderer)`.
  Under `--format json` it marshals a stable `polypkg.cli-result/v2` envelope from
  `data`; under text it runs `textRenderer` (which writes into a `*bytes.Buffer`).
  Both paths write to `cmd.OutOrStdout()`.
- **The JSON shape is a public contract.** A new envelope command, or a new key
  under `data`, gets a row in `docs/json-output.md` in the same commit. Within
  `polypkg.cli-result/v2` a key may be added but never removed, renamed, or
  given a new type or meaning; that needs a new schema version (see the
  stability policy in that file).
- **Errors** return `WrapError(cmd, format, command, err)` from `RunE` so the JSON
  error envelope is emitted in JSON mode and cobra prints normally in text mode.
  `WrapError` returns its input error unchanged, so `return WrapError(...)` both
  emits and propagates the non-zero exit.
- **User-facing errors** are `*CLIError{Msg, Hint, Err}`. `Msg` is the complete
  user-facing sentence — never put Go internals (syscall text, type names) in it;
  `Hint` names the next command to run; `Err` carries the wrapped cause for `%w`
  and logs. To control the process exit code (e.g. `plan`'s changes-pending
  signal), return a `*StatusError{Code, Quiet, Msg}`.

Use cobra's `RunE` (never `Run`) and declare positional-arg rules with `Args`
validators (`cobra.ExactArgs(1)`, etc.) rather than checking `len(args)` inside
the handler. Make a flag mandatory with `requireFlags(cmd, "name", …)` after
setting `RunE`, never cobra's `MarkFlagRequired`: cobra raises that error
outside the flag-error handler, so it would carry no JSON envelope and no hint.

## Testing

`internal/cli` mixes two styles in one package: Ginkgo/Gomega specs (bootstrapped
by `RunSpecs` in `suite_test.go`) and plain `func TestXxx(t *testing.T)`. Both
run under `go test ./...` — match whichever style the neighboring tests in the
file use.

Build a fresh command tree with `NewRootCmd()` inside each test. cobra
accumulates flag state across `Execute()` calls, so a shared root leaks parsed
flags between cases. Drive commands in-process with `root.SetArgs(...)` plus
`root.SetOut`/`root.SetErr` to capture output (see `runRepo` in
`internal/cli/repo_test.go`).

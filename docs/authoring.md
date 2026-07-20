# Authoring a package

> Package author's guide to the `polypkg pkg` inner loop. To publish what you build, see [Publishing a repository](publishing.md).

`polypkg pkg` is the package author's inner loop: scaffold a source, lint it,
and build an unsigned artifact. You author with `pkg`; you publish the result
with `repo` (`repo add` registers it into a repository and signs it).

```
polypkg pkg init ./hello                   # scaffold a lint-clean, runnable source
polypkg pkg explain                        # reference: phases, actions, portability
polypkg pkg lint ./hello                   # validate structure, actions, params, identity, content
polypkg pkg build ./hello                  # lint, pack the artifact, preview the attestation
```

**`polypkg pkg init <dir>`**: scaffolds `<dir>/polypkg.yaml` plus a
`content/bin/<name>` stub. The scaffolded manifest leads with the package
identity, annotates each action inline, and points to `polypkg pkg explain`
for the phase/action reference. The emitted source passes `pkg lint` with zero
findings and is runnable end-to-end: the scaffold includes a `path` action, so
once the package is published and installed, its command is linked onto the
consumer's `$PATH`. `--name` defaults to the directory basename (it must be an
ASCII slug) and `--version` defaults to `0.1.0`. `pkg init` refuses to
overwrite an existing `polypkg.yaml` unless you pass `--force`.

**`polypkg pkg explain`**: prints an authoring reference — the lifecycle
phases, every available action with its parameters (discovered from the action
registry, so it never drifts), the `$PKG`/`$ACTIVE` path variables, and how to
make a package OS/arch-aware with a computed `!starlark` parameter. Honors
`--format text|json`.

**`polypkg pkg lint <dir>`**: validates `<dir>/polypkg.yaml` and its content
tree against structure, action, parameter, identity, and content-reference
rules, reporting each finding with a `PKGxxx` rule ID and a source location. Human
output is the default; `--sarif` emits canonical SARIF 2.1.0 instead, and
`-o <file>` writes that SARIF to a file rather than stdout. `pkg lint` exits
non-zero if any error-severity finding fires.

**`polypkg pkg build <dir>`**: runs the same lint (aborting before it packs
anything if any error-severity finding fires), packs a deterministic unsigned
`<name>-<version>.tar.zst`, prints its BLAKE3 digest, and writes an unsigned
in-toto attestation preview `<name>-<version>.att.json` — the exact statement a
publisher will sign. `-o <dir>` chooses the output directory (default the
current directory).

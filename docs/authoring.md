# Authoring a package

> Package author's guide to the `polypkg pkg` inner loop. To publish what you build, see [Publishing a repository](publishing.md).

`polypkg pkg` is the package author's inner loop: scaffold a source, lint it,
and build an unsigned artifact.

```
polypkg pkg init ./hello                   # scaffold a lint-clean, runnable source
polypkg pkg explain                        # reference: phases, actions, portability
polypkg pkg lint ./hello                   # validate structure, actions, params, identity, content
polypkg pkg build ./hello                  # lint, pack the artifact, preview the attestation
```

`pkg build` exists so you can check your own work. Publishing does not consume
its output — `polypkg repo add <package-source-dir>` takes the **source
directory**, not the `.tar.zst`, and re-lints and re-packs from it. Do not hand
a publisher the tarball; hand them the source tree (or a URL for it). See
[Publishing a repository](publishing.md).

## polypkg does not build your software

Build your program with whatever toolchain it already uses, then drop the
result into the package's `content/` tree. polypkg packs that tree and, at
`polypkg apply`, replays the `actions:` you declared against it.

`pkg init` writes a placeholder so the scaffold is runnable before you have
written anything: `content/bin/<name>` is a two-line `#!/bin/sh` script that
echoes `Hello, world!`. **Overwrite it with your real binary.** Follow the
scaffold literally and you will publish the placeholder.

## Source layout

A package source directory holds up to three things:

| Path | Required | Who reads it |
| --- | --- | --- |
| `polypkg.yaml` | yes | `pkg lint`, `pkg build`, `repo build` |
| `content/**` | in practice | packed into the artifact verbatim; referenced as `$PKG/content/...` |
| `attestations/*.json` | no | `repo build` at publish time |

`attestations/` is where a pre-existing provenance document goes — an SBOM, a
SLSA provenance statement, an upstream signature bundle. Rules:

- Top-level `*.json` only. Subdirectories and other extensions are skipped.
- The directory is optional; absent means "no carried attestations".
- It is **not** packed into the artifact. `polypkg repo build` discovers each
  blob at publish time and binds it to the built artifact alongside the lint
  attestation polypkg mints itself.

`pkg build` packs `polypkg.yaml` plus `content/**` and nothing else, so adding
`attestations/` does not change your artifact's digest.

`content/` may hold only regular files and directories: `pkg build` refuses a
symlink or any other special file there. If you assemble an artifact by hand
instead, polypkg refuses at install time any archive with an entry that passes
through, or replaces, a symlink earlier in the same archive. When polypkg
unpacks an artifact, every file stays readable by its owner and every
directory stays readable, writable and searchable by its owner, whatever mode
the archive records.

## Scaffold: `polypkg pkg init <dir>`

```
$ polypkg pkg init ./hello
Scaffolded hello (0.1.0) in ./hello
```

It writes `<dir>/polypkg.yaml` and the `content/bin/<name>` placeholder. The
emitted manifest is commented inline, passes `pkg lint` with zero findings, and
declares a `path` action — so once the package is published and installed, its
command lands on the consumer's `$PATH`.

- `--name` defaults to the directory basename and must be an ASCII slug
  (`^[a-zA-Z0-9_-]+$`).
- `--version` defaults to `0.1.0`.
- `pkg init` refuses to overwrite an existing `polypkg.yaml` unless you pass
  `--force`.

## The recipe: `polypkg.yaml`

Four top-level keys are required:

| Key | Value |
| --- | --- |
| `schema` | the literal string `polypkg.package/v1` |
| `name` | the package's ASCII-slug identifier, `^[a-zA-Z0-9_-]+$` |
| `version` | the version string |
| `actions` | a list of what to do at install time (see [Actions](#actions)) |

The smallest recipe that lints — the whole file, no ellipses:

```yaml
schema: polypkg.package/v1
name: jot
version: 1.4.2
actions:
  - phase: post-place
    action: install
    params:
      src: $PKG/content/bin/jot
      dest: $ACTIVE/jot/bin/jot
  - phase: post-place
    action: path
    params:
      name: jot
      source: $ACTIVE/jot/bin/jot
```

Paired with an executable at `content/bin/jot`, that is a complete package
source.

**Unknown keys are fatal, not advisory.** The parser rejects any key it does
not know, at both the YAML and JSON Schema layers, so a plausible guess stops
the build rather than being silently dropped:

```
$ polypkg pkg lint ./jot
error PKG000: yaml decode: yaml: unmarshal errors:
  line 4: field dependencies not found in type schema.Package
error: lint found error-severity issues
```

(The key is `depends`, not `dependencies`.) Use the tables below rather than
guessing. `polypkg pkg explain` covers phases, actions, and parameters — it
does not list top-level recipe keys. The authoritative enumeration is the
schema itself: [`internal/schema/jsonschema/package-v1.json`](../internal/schema/jsonschema/package-v1.json).

### Optional top-level keys

Two are descriptive:

| Key | Value |
| --- | --- |
| `title` | human-friendly display name; `name` stays the ASCII id |
| `description` | one-line summary |

Six declare relations to other packages. Each takes a list of `{name, version}`
mappings — `name` is required and must be an ASCII slug; `version` is an
optional constraint, and omitting it means "any version":

| Key | Meaning |
| --- | --- |
| `depends` | hard dependency; the solve fails if it cannot be satisfied |
| `recommends` | installed automatically when satisfiable, dropped and reported when not |
| `suggests` | advertised in `plan`/`apply` output, never installed automatically |
| `provides` | a virtual name this package satisfies |
| `conflicts` | cannot be installed alongside this package |
| `obsoletes` | this package supersedes the named one |

Consumer-side behaviour and policy for `recommends`/`suggests` — including
`--no-recommends` and the profile block that disables them — is documented
under [Weak dependencies](../README.md#weak-dependencies) in the README.

A recipe using them:

```yaml
schema: polypkg.package/v1
name: jot
version: 1.4.2
title: Jot
description: Append-only note capture for the terminal.

depends:
  - name: ripgrep
    version: ">=13.0.0"
provides:
  - name: notes-cli
obsoletes:
  - name: jot-legacy

actions:
  - phase: post-place
    action: install
    drift: refuse
    params:
      src: $PKG/content/bin/jot
      dest: $ACTIVE/jot/bin/jot
  - phase: post-place
    action: install
    params:
      src: $PKG/content/share/bash-completion/completions/jot
      dest: $ACTIVE/jot/share/bash-completion/completions/jot
  - phase: post-place
    action: path
    params:
      name: jot
      source: $ACTIVE/jot/bin/jot
  - phase: post-place
    action: completion
    params:
      shell: bash
      name: jot
      source: $ACTIVE/jot/share/bash-completion/completions/jot
```

### Actions

Every entry under `actions:` requires `phase`, `action`, and `params`, and may
carry an optional `drift`. Run `polypkg pkg explain` for the phase list, the
action catalogue, and each action's parameters.

`drift` decides what `polypkg apply` does when a file this action placed has
been modified on disk since it was installed:

| Value | Effect on the next `apply` |
| --- | --- |
| `notify_heal` | **Default when `drift` is omitted.** The drift is audited and the packaged file is put back. |
| `silent_heal` | Same overwrite, but the routine per-path `drift.detected` audit event is suppressed. A `silent_heal` path that is refused, preserved, or accepted is still audited. |
| `refuse` | `apply` aborts and names the drifted paths. Override with `--heal-drift`, or adopt the on-disk state as the new baseline with `polypkg accept-drift <path>`. |
| `notify_preserve` | The drift is audited and the apply is not refused. This is what the `config` action selects for itself unless its `policy` is `replace`. |

The `config`, `state`, and `unmanaged` actions choose their own drift policy, so
a `drift:` you declare on one of those is ignored. On the other nine actions it
takes effect as written.

For `config` the split is one-sided: `policy: replace` gets `notify_heal`, and
every other value — `preserve`, `preserve_warn`, `three_way_merge`, and the
omitted default, which is `preserve` — gets `notify_preserve`.

#### File modes

The `dir` and `perms` actions take an octal `mode` such as `"0o755"` or
`"0644"`. Quote it: YAML reads an unquoted `0o755` as a number. A mode may use
only the bits in `0755`: read, write and execute for the owner, read and
execute for group and other. polypkg refuses, in every scope, a mode that sets
any of these:

| Bit | Name | Why it is refused |
| --- | --- | --- |
| `0o002` | other-write | Any local user could replace the file, and in system scope `/usr/local/bin` links to it. |
| `0o020` | group-write | Same exposure for every member of the file's group. On systems without per-user groups, that is often every user. |
| `0o4000` / `0o2000` | setuid / setgid | Turns a package file into a privilege boundary. |
| `0o1000` | sticky | Has no use on a path the package owns. |

`polypkg pkg lint` reports such a mode as `PKG010`. `polypkg apply` refuses
it before touching the filesystem, and the error names the path and the mode.
Lint cannot check a `mode` computed by `!starlark`, so `apply` is where that
case is caught.

`install` with `policy: copy` creates the copy with the source file's read,
write and execute bits, less the umask (`apply` uses `0022` in system scope),
and never its setuid, setgid or sticky bits.

#### How `install` places a file

`install`'s optional `policy` decides what lands in the generation:

| `policy` | What lands in the generation | What drift detection checks |
| --- | --- | --- |
| `copy` | **Default when `policy` is omitted.** A regular file with the source's permission bits, less the umask. Setuid, setgid, and sticky bits are never copied. | File type and content hash. |
| `symlink` | A symlink to the file in polypkg's extract cache (`$XDG_STATE_HOME/polypkg/pkg-extract/`). It saves disk, but the generation depends on the cache. | File type, plus the content hash of the link's target, re-hashed on every check. |
| `hardlink` | A hard link to the file in the extract cache. It is the same inode, so an edit through either name changes both. Fails if the cache and the generation are on different filesystems. | File type and content hash. |

Every `plan` and `apply` also checks each package's extract cache against its
signed artifact and re-extracts a cache that was modified, so no policy lets an
edit to the cache reach a new generation. Prefer `copy`. With `hardlink`, a
`perms` action on the installed file also changes the cache's copy, and if it
adds permission bits, every `apply` re-extracts the cache.

## Reference: `polypkg pkg explain`

Prints an authoring reference — the lifecycle phases, every available action
with its parameters, the `$PKG`/`$ACTIVE` path variables, and how to make a
package OS/arch-aware with a computed `!starlark` parameter. Honors
`--format text|json`.

The action catalogue and its parameters are discovered from the action
registry, so that part of the output always matches the installed binary. The
recipe's own top-level keys are not registry-derived and do not appear here;
they are in the [schema](../internal/schema/jsonschema/package-v1.json) and in
the tables above.

## Validate: `polypkg pkg lint <dir>`

Validates `<dir>/polypkg.yaml` and its content tree in five layers, reporting
each finding with a `PKGxxx` rule ID and a source location:

- **structure** — the file parses and satisfies the JSON Schema (`PKG000`).
- **action** — the phase and action names are real and legal together.
- **parameter** — required params are present, typed, and within their enums,
  and every `mode` stays within `0755` (`PKG010`; see [File modes](#file-modes)).
- **identity** — every relation name is an ASCII slug (`PKG007`), and no two
  identifiers in the recipe collide when case-folded (`PKG008`).
- **content-reference** — every literal `$PKG/...` param resolves to a file
  that actually exists in the source (`PKG006`).

A clean source says so, and exits `0`:

```
$ polypkg pkg lint ./jot
clean: no findings
```

`pkg lint` exits non-zero if any error-severity finding fires. Human output is
the default; `--sarif` emits canonical SARIF 2.1.0 instead. `-o <file>` writes
that SARIF to a file rather than stdout — it applies **only** with `--sarif`,
and is ignored in human mode.

## Pack: `polypkg pkg build <dir>`

```
$ polypkg pkg build ./jot -o ./out
Built jot-1.4.2
  artifact:    out/jot-1.4.2.tar.zst
  digest:      blake3:7fff6617aeb0e7e4119473d769208126050bbf92cf7e906bfffdba4b2539e7be
  attestation: out/jot-1.4.2.att.json
```

That digest is illustrative. It hashes the archive, which covers your
`content/` bytes, so the recipe above will print a different one for whatever
executable you dropped at `content/bin/jot`.

`pkg build` runs the same lint first and aborts before packing anything if an
error-severity finding fires. The `.tar.zst` is deterministic: sorted paths,
zeroed mtime/uid/gid, so an unchanged source rebuilds to the same digest.
`-o <dir>` chooses the output directory (default: the current directory).

`<name>-<version>.att.json` is a **preview, not a build input.** Nothing
consumes it — `polypkg repo build` re-lints the source and re-assembles the
statement itself. Both paths feed the same assembler the same three inputs (the
artifact filename, its BLAKE3 digest, and the lint SARIF), so for an unchanged
source the preview is byte-identical to what the publisher signs. Read it to
see what you are about to have signed; do not ship it.

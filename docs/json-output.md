# JSON output for scripts

> Reference for reading `polypkg --format json` from scripts and CI: what each
> command prints, which fields you can rely on, and how the format may change.
> The README's [Scripting](../README.md#scripting) section has the short
> version.

## Reading a result

`--format json` is a persistent flag on the root command, so every command
accepts it. Under it a command prints one JSON document, followed by a
newline, on stdout. Messages meant for a person still go to stderr: a failed
command prints the same `error:` and `hint:` lines it prints in text mode,
`source add` prints its `warning:` line when it could not check the source,
and `mirror verify` prints its `SECURITY:` grace warning there.

Read a result in this order:

1. **The exit code.** 0 is success and 1 is an error. `plan`, `repo status`
   and `status` use other codes to report a state rather than a failure; see
   [Exit codes](../README.md#exit-codes). A state code still comes with a
   success document.
2. **`.schema`.** It names the document and its version. Most commands print
   the `polypkg.cli-result/v2` envelope; `plan`, `status` and
   `attestation report` print their own document on success. A failed
   command prints the envelope with `"status": "error"` (the exceptions are in
   [Commands that print text](#commands-that-print-text)), so check
   `.schema` before reading other fields.
3. **The payload.** For the envelope that is `.data`; for the other three it
   is the document itself.

## The envelope: `polypkg.cli-result/v2`

```json
{"schema":"polypkg.cli-result/v2","command":"repo status","status":"ok","data":{"pending":false,"reason":""}}
{"schema":"polypkg.cli-result/v2","command":"pin","status":"error","error":"generation 7 does not exist","hint":"run `polypkg status -v` to list retained generations"}
```

| Field | Type | Present | Meaning |
|---|---|---|---|
| `schema` | string | always | `polypkg.cli-result/v2` |
| `command` | string | always | Which command produced it: the command path without `polypkg` (`repo status`). `generation pin` and `generation unpin` report `pin` and `unpin`. An error envelope reports the same value as the command's successful result, including for a wrong number of arguments, a missing required flag, or an unknown or malformed flag (`pkg lint` for `polypkg pkg lint --bogus`). An unknown command (`polypkg bogus`) reports `polypkg`: no command ran, so the envelope names the root that rejected the word. |
| `status` | string | always | `ok` or `error`. |
| `data` | object | on success | The command's result. Every command listed below includes it. The schema marks it optional so that a future command with nothing to report may leave it out; treat a missing `data` as `{}`. |
| `error` | string | on error | A sentence for a person. |
| `hint` | string | on error, when there is one | The next command to run, for a person. |

`error` and `hint` are prose. Their wording changes whenever it can be made
clearer, so never match on it; branch on the exit code and `status`.

## Stability policy

The `schema` value names a format and its version. Within one version,
polypkg:

- may add fields, and may add envelope commands;
- does not remove or rename a field, or change its type or meaning;
- does not stop emitting a field this page lists as always present;
- does not change the `command` value of a command's result, success or
  error.

A change that breaks any of these ships under a new version (for example
`polypkg.cli-result/v3`), and the [CHANGELOG](../CHANGELOG.md) records it.
This holds before 1.0.0 as well.

So a consumer should ignore fields it does not recognise, and should check
`.schema` before it reads anything else.

Not covered by this policy:

- text output, which is for people and changes freely;
- the wording of `error` and `hint`;
- `pkg lint --sarif`, which follows the SARIF 2.1.0 standard rather than a
  polypkg schema.

Two serialization details apply to every document:

- A list with no entries may be printed as `[]` or as `null`. Treat both as
  empty.
- An optional object that is absent is `null` (for example `info`'s
  `attestation` for a package that is not installed).

## Schemas

These are JSON Schema (draft 2020-12) files. polypkg embeds the same files and
validates documents against them when it parses them. A schema's `$id`, where
it has one, is an identifier, not a URL you can download from.

| Document | Printed by | Schema |
|---|---|---|
| `polypkg.cli-result/v2` | every envelope command, and every failed command | [`cli-result-v2.json`](../internal/schema/jsonschema/cli-result-v2.json) |
| `polypkg.plan/v1` | `plan` | [`plan-v1.json`](../internal/schema/jsonschema/plan-v1.json) |
| `polypkg.status/v1` | `status` | [`status-v1.json`](../internal/schema/jsonschema/status-v1.json) |
| `polypkg.attestation-report/v1` | `attestation report` | [`attestation-report-v1.json`](../internal/schema/jsonschema/attestation-report-v1.json) |

The envelope schema covers the envelope only: it requires `data` to be an
object and says nothing about its keys. The keys are the per-command tables
below.

`plan` exits 2 when changes are pending and `status` exits 3, 4 or 5 to report
revocation state; both still print their own document. `plan`'s `current`
object, present once a generation exists, names that `generation` and its
`committed_at` time, the same value `status` reports as `applied_at`.
`status -v`, `-vv` and `-vvv` do not change the JSON: the full `status/v1`
document is always printed.

## Commands that print text

`pkg init`, `pkg lint` and `pkg build` print text on success; `--format json`
does not turn their success output into a document. When one of them fails,
it prints the error envelope on stdout like any other command. Under
`--format json` the human lint report of `pkg lint` and `pkg build` goes to
stderr, so stdout holds only the envelope. `pkg lint --sarif` prints SARIF
2.1.0 instead, and `-o <file>` writes it to a file; when the SARIF document is
on stdout, a lint that finds error-severity issues exits 1 without an
envelope, so stdout stays one document. `help` and `completion` print text
and shell scripts.

One failure can print no envelope: an unknown flag. Flags are read left to
right and reading stops at the first unknown one, so a `--format json` placed
after it is never seen and the error is printed as text only.
`polypkg --format json status --bogus` prints the envelope;
`polypkg status --bogus --format json` does not. Put `--format` first in
scripts.

## Per-command `data`

Each table lists the keys of `data` for one envelope command. "Always" means
present on every success.

`generation pin` and `generation unpin` are the two commands whose `command`
value is not their path: they print `"command": "pin"` and
`"command": "unpin"`.

### Apply results: `apply`, `install`, `remove`, `upgrade`

These four run an apply and share its keys. `install`, `remove` and `upgrade`
add their own keys, listed after this table.

| Key | Type | Present | Meaning |
|---|---|---|---|
| `gen_id` | integer | when an apply ran | The generation the apply committed. `install` and `upgrade` can finish without an apply (see below); then it is absent. |
| `skipped_recommends` | array | when a recommended package was skipped | Each item: `name`, `version_range`, `reason`, `recommended_by` (array of package names). Same shape as in `plan/v1`. |
| `suggests` | array | when a package suggests another | Each item: `name`, `version_range`, `suggested_by`. Same shape as in `plan/v1`. |
| `bridge` | object | when the command bridge is enabled | `linked`, `pruned`, `skipped`: arrays of command names. |
| `completion` | object | when shell completion integration ran | Keyed by shell name; each value has `linked` and `pruned` arrays. |
| `desktop` | object | when desktop integration ran | `linked`, `pruned`, `skipped`: arrays of entry names. |
| `mime` | object | when MIME integration ran | `linked`, `pruned`, `skipped`: arrays of entry names. |
| `manpath` | string | when an installed package ships man pages | The directory to add to `MANPATH`. |

`install` adds:

| Key | Type | Present | Meaning |
|---|---|---|---|
| `edits` | array | always | One item per requested package: `name`, `constraint` (the constraint now in the profile), `action` (`add`, `update` or `kept`). When every item is `kept`, no apply runs and `edits` is the only key. |

`remove` adds:

| Key | Type | Present | Meaning |
|---|---|---|---|
| `edits` | array | always | One item per removed package: `name`, `action` (always `remove`). |

`upgrade` adds one of:

| Key | Type | Present | Meaning |
|---|---|---|---|
| `held_back` | array | bare `upgrade` | Exact pins with a newer version available. Each item: `name`, `pinned` (the pinned version), `available` (the newest version). |
| `edits` | array | `upgrade <package>...` | One item per named package: `name`, `action` (`bump`, `at-newest` or `range`), `constraint` (only for `bump`: the new pin), `available` (when a newer version exists). When no pin was bumped and no range was named, no apply runs and `edits` is the only key. |

### Getting started

**`init`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `path` | string | always | The profile file written. |

### Packages

**`search`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `matches` | array | always | One item per matching package: `name`; `versions` (installable on this machine); `unavailable_versions` (published only for other platforms); `installed` (the installed version, `""` when not installed). `versions` can be empty when `unavailable_versions` is not, for a package published only for other platforms, so check it before installing. |

**`info`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `name` | string | always | The package. |
| `installed` | string | always | Installed version; `""` when not installed. |
| `installed_platform` | string | always | The installed package's platform (`any` when platform-agnostic); `""` when not installed. |
| `generation` | integer | always | Generation holding the installed version; `0` when not installed. |
| `available` | array | always | Versions installable on this machine, newest first. |
| `source` | string | always | The source the package resolves from. |
| `scope` | string | always | `user` or `system`. |
| `note` | string | always | Why `available` may be incomplete: an offline source, or a package published only for other platforms (`<name> <version> is published for <platforms>; this host is <os>/<arch>`). `""` otherwise. |
| `artifact` | string | always | The artifact the newest available version would install. |
| `platform` | string | always | That artifact's platform (`any` when platform-agnostic); `""` for a package published only for other platforms. |
| `other_platforms` | array | always | The other platforms that version is published for. |
| `recommends` | array | always | Weak dependencies the newest version recommends. |
| `suggests` | array | always | Packages the newest version suggests. |
| `attestation` | object or null | always | The installed package's install-time attestation record: `status` (`verified` or `unattested`), `predicate_types`, `attestation_hash`, and further detail. `null` when not installed or installed before attestations were recorded. |

**`list`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `packages` | array | always | One item per installed package: `name`, `version`, `scope`, `pinned` (the exact pin, e.g. `=1.2.3`, or `""`), `platform` (`any` when platform-agnostic). Empty when nothing is installed. |
| `generation` | integer | when a generation exists | The current generation. |
| `scope` | string | when a generation exists | `user` or `system`. |

### Profile & apply

**`apply`**: the [apply keys](#apply-results-apply-install-remove-upgrade).

**`accept-drift`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `paths_accepted` | integer | always | Number of paths adopted. |
| `gen_id` | integer | always | The generation whose baseline was updated. |

### Generations

**`rollback`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `target` | integer | always | The generation now active. |
| `bridge`, `completion`, `desktop`, `mime`, `manpath` | | as for apply | Same shapes as the [apply keys](#apply-results-apply-install-remove-upgrade). |

**`generation pin`** (`"command": "pin"`)

| Key | Type | Present | Meaning |
|---|---|---|---|
| `gen_id` | integer | always | The pinned generation. |
| `reason` | string | always | The `--reason` text; `""` when none was given. |

**`generation unpin`** (`"command": "unpin"`)

| Key | Type | Present | Meaning |
|---|---|---|---|
| `gen_id` | integer | always | The unpinned generation. |

**`gc`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `removed` | integer | always | Generations removed. |
| `failed` | integer | always | Generations that could not be removed. |
| `bytes_reclaimed` | integer | always | Bytes freed by removing generations. |
| `extract_dirs_removed` | integer | always | Extracted package trees pruned. |
| `extract_dirs_pruned` | array | always | Their paths, all of them (text output shows the first 20). |
| `cache_artifacts_removed` | integer | always | Cached downloads pruned. |
| `cache_artifacts_pruned` | array | always | Their paths, all of them. |
| `kept_by_age` | integer | always | Generations past `--count` that `--age` kept. |
| `damaged` | array | always | Generation numbers whose manifest is damaged; `gc` keeps them for inspection. |

### Integration

**`link`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `linked` | array | always | Command names linked into the bridge directory. |
| `pruned` | array | always | Stale links removed. |
| `skipped` | array | always | Command names not linked because something else owns the path. |

**`unlink`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `pruned` | array | always | Command links removed from the bridge directory. |

**`alternatives list`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `alternatives` | array | always | One item per alternative name: `name`, `winner` (providing package), `source`, `priority`, `mode` (`auto` or `manual`), `stale` (a manual selection that no longer applies), `providers` (each: `package`, `priority`, `source`), `followers` (object, when the winner has followers). |

**`alternatives set`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `name` | string | always | The alternative. |
| `package` | string | always | The package now providing it (manual mode). |

**`alternatives auto`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `name` | string | always | The alternative. |
| `changed` | boolean | always | `false` when it was already in auto mode. |
| `winner` | string | when `changed` is true | The package now providing it. |

### Sources & repositories

**`source list`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `sources` | array | always | One item per source, in preference order: `name`, `type`, `url`, `trust_root`. |
| `order` | array | always | The profile's `sources.order`. |

**`source add`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `name` | string | always | The source added. |
| `type` | string | always | Its type. |
| `url` | string | always | Its URL, normalised. |
| `trust_root` | string | always | The managed copy of its trust root. |
| `order_first` | boolean | always | Whether it was put first in the preference order (`--order-first`). |
| `verified` | boolean | always | Whether `source add` fetched the source's signed trust document and checked it against the trust root. `false` when the check could not complete (the source was unreachable, served no trust document, or its trust document has expired); the source is added anyway. A source that fails the check outright (its trust document is not signed by the trust root, or names another source) is refused with an error envelope instead. |
| `warning` | string | when `verified` is false | Why the check could not complete: the stderr `warning:` line without its `warning: ` prefix. |

**`source remove`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `name` | string | always | The source removed. |

**`source set-trust-root`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `name` | string | always | The source. |
| `old_fingerprint` | string or null | always | Key id of the key previously pinned; `null` when that key file could not be read. |
| `new_fingerprint` | string | always | Key id of the key now pinned. |
| `trust_root` | string | always | The managed copy of the new trust root. |
| `changed` | boolean | always | Whether the pinned key changed. |
| `state_reset` | boolean | always | Whether the source's anti-rollback memory was cleared. |

**`repo init`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `manifest` | string | always | The `polypkg-repo.yaml` written. |
| `key` | string | always | The encrypted signing key written. |
| `trust_root` | string | always | The public trust root to give clients. |

**`repo add`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `package` | string | always | The first source's package name. |
| `version` | string | always | The first source's version. |
| `serial` | integer | always | The repository serial after the rebuild. |
| `added` | array | always | One item per source directory: `package`, `version`, `platform` (`any` when platform-agnostic), `source`. |
| `trust_bundle` | object | when the rebuild changed the trust bundle | Same shape as in `repo build`, below. |

**`repo remove`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `package` | string | always | The package removed. |
| `serial` | integer | always | The repository serial after the rebuild. |
| `version` | string | when a version was given | The version removed. |
| `removed` | array | when a version was given | One item per withdrawn entry: `entry`, `platform`. |
| `trust_bundle` | object | when the rebuild changed the trust bundle | Same shape as in `repo build`, below. |

**`repo build`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `changed` | boolean | always | Whether anything was re-signed. |
| `serial` | integer | always | The repository serial after the build. |
| `trust_bundle` | object | when the build changed the published `trust-bundle.json` | What the new bundle vouches for, so whoever reviews a `sigstore_roots` or `trust_bundle` edit sees the trust it adds. `withdrawn` (boolean): `true` when the build removed the bundle, and then the two lists are absent. `sigstore_roots` (array): each item has `fulcio_root_sha256` (hex SHA-256 of the root's self-signed Fulcio certificate), `valid_from`, and `valid_until` (absent when open-ended). `builder_keys` (array): each item has `key_id`, `valid_from`, and `valid_until` (absent when open-ended). Times are RFC 3339, as the bundle records them. |

**`repo status`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `pending` | boolean | always | Whether a `repo build` is needed. The command also exits 2 when it is. |
| `reason` | string | always | Why a build is needed; `""` when none is. |
| `trust_bundle` | object | when a build is pending and would change the trust bundle | What the bundle would vouch for after that build; same shape as in `repo build`, above. |

**`repo export-bundle`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `bundle` | string | always | The tarball written. |
| `entries` | integer | always | Files in the bundle. |
| `serial` | integer | always | The bundle manifest's serial. |
| `expires` | string | always | When the bundle manifest expires (RFC 3339). |

**`repo key show`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `key_id` | string | always | The signing key's id, as clients pass to `--trust-root-fingerprint`. |
| `pubkey` | string | always | The public key, base64. |

**`repo revoke`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `revocations` | string | always | The revocation list written. |
| `signature` | string | always | Its signature file. |
| `serial` | integer | always | The revocation list's serial. |
| `revoked_attestations` | array | always | Attestation hashes now revoked. |
| `revoked_builder_keys` | array | always | Builder key ids now revoked. |

### Offline mirrors

**`mirror pull`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `packages` | integer | always | Packages pulled. |
| `output` | string | always | The mirror repository directory. |
| `manifest` | string | always | The mirror's `polypkg-repo.yaml`. |
| `bundle` | string | always | The bundle written with `-o`; `""` without it. |
| `fresh` | boolean | always | Whether `--fresh` re-anchored the mirror. |

**`mirror verify`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `source` | string | always | The source the bundle was signed for. |
| `serial` | integer | always | The bundle manifest's serial. |
| `expires` | string | always | When the bundle manifest expires. |
| `entries` | integer | always | Files checked. |
| `graced` | boolean | always | Whether an expired manifest was accepted under `--accept-expiry-until`. |
| `pinned` | boolean | always | Whether the bundle was checked against a trust root you gave with `--trust-root`. `false` means self-consistency only: the signature was checked against the trust root inside the bundle, which says nothing about who signed it. |

### Author packages

**`pkg explain`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `phases` | array | always | Lifecycle phases in run order: `name`, `description`. |
| `actions` | array | always | Every action, sorted by name: `name`, `params` (each: `name`, `required`, `kind`, `enum` when restricted). |
| `vars` | array | always | Path variables: `name`, `meaning`. |
| `notes` | array | always | Strings. |
| `platform_example` | string | always | A per-platform `polypkg.yaml` example. |
| `starlark_example` | string | always | A computed-parameter example. |

**`pkg import`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `release` | string | always | The release reference as given on the command line (`github:OWNER/REPO` or `github:OWNER/REPO@TAG`); `version` holds the version it resolved to. |
| `name` | string | always | The package name. |
| `version` | string | always | The package version. |
| `trusted_root` | string | always | Absolute path of the sigstore `trusted_root.json` written beside the sources. |
| `platforms` | array | always | One item per source written: `platform`, `asset`, `integrity`, `attestations` (integer), `dir`, `warnings`, `notes`. |
| `skipped` | array | always | Release assets not imported: `name`, `reason`. |
| `next` | array | always | The commands that publish the result. |

### Maintenance

**`config reset`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `paths_queued` | integer | always | Config paths queued for reset on the next apply. |

**`purge`**

| Key | Type | Present | Meaning |
|---|---|---|---|
| `package` | string | always | The package whose state was deleted. |

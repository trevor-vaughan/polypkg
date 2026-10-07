# Authoring a package

> Package author's guide to the `polypkg pkg` inner loop. To publish what you build, see [Publishing a repository](publishing.md).

`polypkg pkg` is the package author's inner loop: scaffold a source, lint it,
and build an unsigned artifact.

```
polypkg pkg init ./hello                   # scaffold a lint-clean, runnable source
polypkg pkg import github:cli/cli ./imports  # or: one source per platform from a GitHub release
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

## Import a GitHub release: `polypkg pkg import`

Most command-line tools already publish prebuilt binaries per platform as
GitHub release assets. `pkg import` turns one release into publish-ready
package sources, one per platform, each shipping the upstream asset byte for
byte:

```
polypkg pkg import github:OWNER/REPO[@TAG] <out-dir> [flags]
```

Without `@TAG` it imports the repository's latest release that is not a
prerelease. A failed import leaves `<out-dir>` as it was, and an import into a
directory that already holds a target `<os>-<arch>` directory is refused
before anything is downloaded.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--name` | the repository name, lower-cased | the package name |
| `--version` | the tag, less a leading `v` or `V` before a digit | the package version, when the tag is not a semantic version |
| `--bin NAME` (repeatable) | the package name | an executable to expose on `PATH` |
| `--platform OS/ARCH=GLOB` (repeatable) | — | force a platform's asset: resolves an ambiguity, or adds a platform the matching missed |
| `--require-attestation` | off | refuse a platform whose asset has no verified attestation |
| `--insecure-skip-digest` | off | import an asset that has neither a GitHub digest nor a checksums entry, marked `UNVERIFIED` |
| `--api-url` | `https://api.github.com` | the REST API root (GitHub Enterprise Server: `https://HOST/api/v3`) |
| `--trusted-root FILE` | fetched over TUF | the sigstore `trusted_root.json` to verify attestations against, instead of the Sigstore public-good root |

`GITHUB_TOKEN`, else `GH_TOKEN`, raises GitHub's rate limit (60 anonymous
requests an hour; an import makes two, plus one per page of attestations for
each matched asset). It is sent only to the `--api-url` host, never to asset
or attestation downloads, and never over plain http except to a loopback host.

Attestations verify only against the Sigstore public-good root and only for
`https://github.com/OWNER/REPO` builds, so a private repository's or a GitHub
Enterprise Server's attestations, which GitHub signs on its own Sigstore
instance, are not supported: such a provenance bundle refuses the import.

### What it writes

```
<out-dir>/
  sigstore-trusted-root.json          # the Sigstore root the import verified against
  <name>/<version>/<os>-<arch>/
    polypkg.yaml
    content/<asset-file-name>         # upstream bytes, verbatim
    attestations/<n>.json             # verified sigstore bundles, if any
```

For an archive asset, the recipe unpacks it with
[`extract`](#unpacking-an-archive-extract) and exposes each `--bin` with
`path`. For example, the GitHub CLI on linux/amd64
(`pkg import github:cli/cli ./imports --name gh --bin gh`):

```yaml
# Generated by `polypkg pkg import` from github:cli/cli, version 2.102.0.
schema: polypkg.package/v1
name: gh
version: 2.102.0
platform: linux/amd64
title: cli
description: GitHub’s official command line tool
actions:
  - phase: post-place
    action: extract
    params:
      dest: $ACTIVE/gh/dist
      src: $PKG/content/gh_2.102.0_linux_amd64.tar.gz
      strip_components: 1
  - phase: post-place
    action: path
    params:
      name: gh
      source: $ACTIVE/gh/dist/bin/gh
```

`title` is the repository name and `description` the repository's GitHub
description. `strip_components` is 1 when every member of the archive lies
below one top-level directory (2 when member names start with `./`), else it
is omitted. Each `--bin` must be exactly one executable regular file in the
archive with that base name; zero or several matches refuse that platform and
list the executables found. A bare executable asset (an ELF or Mach-O file,
not an archive) is copied to `$ACTIVE/<name>/bin/<bin>` with an `install`
action (`policy: copy`) and takes exactly one `--bin`. Every generated source
passes `pkg lint`; the import lints each one and refuses on any finding.

A platform that cannot be imported safely (an asset over 2 GiB, an unknown
asset kind, an executable built for another architecture, a missing `--bin`,
no attestation under `--require-attestation`) is dropped and listed with the
skipped assets; the import fails only when no platform remains. Each asset is
downloaded into memory and checked there before it is written, so the host
needs free memory for the largest asset it imports.

On success the text output is a table — platform, asset, integrity source,
attestations carried, directory — then any `warning:` and `note:` lines, the
skipped assets, and the commands that publish the result:

```
polypkg repo add <out-dir>/gh/2.102.0/linux-amd64 <out-dir>/gh/2.102.0/darwin-arm64 …
# add once to ./polypkg-repo.yaml (relative to that file):  sigstore_roots: ["<out-dir>/sigstore-trusted-root.json"]
polypkg repo build
```

The commands use `./polypkg-repo.yaml`, and a manifest's `sigstore_roots`
resolve against its own directory, so the root's path is printed relative
to the current directory. Run them from where the manifest is, or adjust the
path.

Under `--format json`, `data` holds `release`, `name`, `version`,
`trusted_root`, `platforms` (each `platform`, `asset`, `integrity`,
`attestations`, `dir`, `warnings`, `notes`), `skipped` (each `name`,
`reason`), and `next` (the `repo add` and `repo build` commands). See
[Publishing a repository](publishing.md) for `sigstore_roots`.

### How assets are matched to platforms

Matching reads the lower-cased asset file name. A token counts only at a
separator boundary (start, end, `-`, `_`, `.`); `x86_64` and `x86-64` match
as whole strings.

| Platform part | Tokens |
| --- | --- |
| `darwin` | `darwin`, `macos`, `apple`, `osx`, `mac` |
| any other Go OS (`linux`, `freebsd`, …) | its name |
| `amd64` | `amd64`, `x86_64`, `x86-64`, `x64` |
| `arm64` | `arm64`, `aarch64` |
| `386` | `386`, `i386`, `i686` |
| any other Go architecture | its name (`riscv64`, `ppc64le`, `s390x`, …) |

A darwin asset named `universal` or `all` serves both `darwin/amd64` and
`darwin/arm64`, each only when no asset is specific to that architecture.

These assets are skipped and listed in the output, not treated as errors:
Windows assets (`windows`, `win32`, `win64`, `.exe`); OS packages (`.deb`,
`.rpm`, `.apk`, `.msi`, `.pkg`, `.dmg`, `.snap`, `.AppImage`); signature,
checksum and metadata files (`.sha256`, `.sha512`, `.sha512sum`, `.sha1`,
`.md5`, `.sig`, `.asc`, `.pem`, `.crt`, `.cert`, `.pub`, `.minisig`,
`.sigstore`, `.sbom`, `.spdx`, `.cdx.xml`, `.json`, `.jsonl`,
`.intoto.jsonl`, `.txt`, `.bundle`, and checksums files such as `SHA256SUMS`);
32-bit ARM (`armv6`, `armv7`, `armhf`, `arm` alone), which needs variant
support polypkg does not have yet; and any name with an OS token but no
architecture, or the reverse. A matched asset must turn out, once downloaded,
to be an archive `extract` can read (judged by its bytes, not its name) or a
bare executable; anything else refuses that platform.

When several assets match one platform, the first of these rules that leaves
one candidate wins:

1. a `--platform OS/ARCH=GLOB` for that platform;
2. a name containing `musl` over one containing `gnu` (static binaries run on
   any distribution);
3. by kind: `.tar.zst`/`.tzst`, then `.tar.xz`/`.txz`, `.tar.gz`/`.tgz`,
   `.zip`, `.tar`, then a bare executable, then a name with any other
   extension after its platform tokens.

If more than one still remains, the import is refused, listing the candidates;
re-run with, for example,
`--platform linux/amd64='*x86_64-unknown-linux-musl.tar.gz'`.

### What the integrity check does and does not prove

Each matched asset is downloaded and its sha256 compared with the digest
GitHub's API reports for it. A mismatch refuses the whole import. When GitHub
reports no digest, the release's checksums file (`SHA256SUMS`,
`checksums.txt`, `<asset>.sha256`, and similar) must list the asset with a
matching sha256: a mismatch refuses the whole import, and a missing entry
refuses that platform. With neither, the platform is refused unless
`--insecure-skip-digest` is set, and the summary marks it `UNVERIFIED`.

These checks protect against a corrupted or swapped download. They are **not
upstream signatures**: GitHub computes the digest of whatever was uploaded,
and a checksums file is uploaded by the same hand as the assets. What
establishes that the project's own build produced the bytes is the
attestation check.

### Attestations

For each asset the import asks GitHub for its
[artifact attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations).
Only SLSA provenance is carried. Any other kind, such as GitHub's release
attestation (signed by GitHub's own internal CA, which the public-good root
does not hold), is skipped unverified and reported as a `note:`.

Each provenance bundle is verified offline against the Sigstore public-good
root (or `--trusted-root`). It is kept only if its Fulcio certificate was
issued to GitHub Actions (`https://token.actions.githubusercontent.com`) and
its source-repository extension names `https://github.com/OWNER/REPO`, the
repository whose code was built. A bundle that verifies but names another
issuer or repository is dropped with a `warning:`. A provenance bundle that
fails verification, or does not name the asset's digest, refuses the import,
because a broken signature on an attestation is a tamper signal.
`--require-attestation` refuses a platform for which no bundle was kept.

Kept bundles go in `attestations/`, where `repo build` binds them to the
asset by digest. Publish the root with `sigstore_roots` and an install records
the binding as `verified-offline`. This check is defence in depth: what
decides whether a consumer installs is that consumer's
[trust policy](trust-policy.md#pinning-a-github-actions-identity).

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

### Platforms: per-platform or fat artifacts

A package that is the same on every machine, such as a shell script or data
files, needs nothing more. An artifact with no `platform:` key is
platform-agnostic and installs on any host. A package whose content differs
per OS or CPU architecture, such as a compiled binary, can ship in one of two
ways.

**Per-platform artifacts (`platform:`).** Keep one package source per
platform. Each source has the same `name` and `version` and declares the
platform its `content/` was built for:

```yaml
schema: polypkg.package/v1
name: jot
version: 1.4.2
platform: linux/amd64
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

To publish the macOS build of the same version, add a second source that
differs only in `platform: darwin/arm64` and the binary in `content/bin/jot`.
The publisher lists both sources (see
[Publishing a repository](publishing.md)). Each client downloads only the
artifact for its own host.

The value is `<os>/<arch>` in Go's `GOOS`/`GOARCH` names: one of the pairs
`go tool dist list` prints, such as `linux/amd64`, `linux/arm64`, or
`darwin/arm64`. `pkg lint` refuses a pair Go does not know, so a typo such
as `linux/amd46` fails before it is published. Matching is exact. A
`linux/arm64` host does not install a `linux/amd64` artifact, and there is no
fallback to a nearby platform. A third segment for an architecture variant
(`linux/arm/v7`) is not accepted.

**Fat artifacts (`!starlark`).** Leave `platform:` out, put every platform's
files in one `content/` tree, and pick the right file at install time with a
computed parameter. The parameter reads `host.os` and `host.arch`, which use
the same `GOOS` and `GOARCH` names:

```yaml
  - phase: post-place
    action: install
    params:
      src: !starlark "return '$PKG/content/bin/' + host.os + '/' + host.arch + '/jot'"
      dest: $ACTIVE/jot/bin/jot
```

**Which to choose.** Prefer per-platform artifacts for compiled binaries:

- Each download carries one platform's files.
- `install` on a host the package was not built for is refused before
  anything is downloaded, with a message that names the platforms it is
  published for.

A fat artifact makes every client download every platform's files. In
exchange it is one source, one artifact, and one signature, so it suits
packages where the per-platform part is small. On a host it has no files
for, a fat artifact fails at install time, when the computed path does not
exist.

A version is one or the other. The publisher refuses a version that has
both an entry without a platform and entries with one.

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
a `drift:` you declare on one of those is ignored. On the other ten actions it
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

A `perms` action can change the mode of a path an earlier action of the same
package created, such as a `dir` or a file `extract` unpacked. Drift detection
then checks that path against the mode of the last action that set it, and
checks the earlier action only for the path's type and content.

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

#### Unpacking an archive: `extract`

`extract` unpacks an archive shipped in `content/` into the package's
directory when `polypkg apply` runs:

```yaml
actions:
  - phase: post-place
    action: extract
    params:
      src: $PKG/content/ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz
      dest: $ACTIVE/ripgrep/rg
      strip_components: 1
      include:
        - rg
        - doc/rg.1
        - complete/*
  - phase: post-place
    action: path
    params:
      name: rg
      source: $ACTIVE/ripgrep/rg/rg
```

| Param | Required | Meaning |
| --- | --- | --- |
| `src` | yes | The archive, under `$PKG/`. It must be a regular file, not a symlink and not under a symlinked directory: `repo build` refuses any symlink in `content/`, and `pkg lint` reports one (`PKG012`). It may be at most 1 GiB: every file in a package is limited to 1 GiB, so a larger archive could never install. |
| `dest` | yes | The directory to unpack into, strictly below `$ACTIVE/<name>/`. It must not exist yet: `extract` creates it, along with any missing parent directories, and fails if an earlier action already placed something there. |
| `strip_components` | no | An integer from `0` to `64` (the deepest member path an archive may hold), default `0`. Removes that many leading path segments from every member name, as `tar --strip-components` does. A member with too few segments is skipped; if that leaves no member at all, the apply fails. |
| `include` | no | A list of `path.Match` patterns, default every member. A member is unpacked if a pattern matches its path after `strip_components`, or matches one of its parent directories. As in `path.Match`, `*` does not cross a `/`. A pattern that matches no member fails the apply, so a typo or a changed upstream layout is caught. It must be a literal list: `!starlark` computes a string, so `pkg lint` reports a computed `include` (`PKG010`). |

polypkg recognizes the format from the file's first bytes, not from its
name: `.tar.gz`, `.tar.zst`, `.tar.xz`, `.zip`, or an uncompressed `.tar`.
A compressed file that does not hold a tar archive, such as a single
gzip-compressed binary, is refused.

Every unpacked file, directory and symlink is a real path in the
generation, owned by the package and checked for drift: a file by its
content hash and mode, a directory by its mode, a symlink by its target. A
`drift:` on the action applies to each of them, and `status -vv` names the
exact path that changed. Only what the archive placed is tracked: a file
you add under `dest` later is not reported as drift, the same as a file
added under a `dir`.

An archive is untrusted input. `apply` refuses it, and places nothing from
it, if:

- any member name is empty, absolute, contains a `..` segment, a backslash,
  a control character (C0, C1 or DEL, including NUL, tab and newline) or a
  Unicode format character (such as a bidi override), has a `:` in its
  first segment, is longer than 4096 bytes, or has more than 64 segments;
- a member it would unpack is a hard link, a device, a FIFO, a socket, or an
  entry type polypkg does not know;
- a symlink's target is empty, absolute, leads outside `dest`, or climbs
  back out of a directory with `..` (`sub/../x`);
- a member would be written through a symlink the archive placed;
- two members have the same path after `strip_components`;
- a file is larger than 1 GiB, the unpacked files total more than 2 GiB, or
  the archive has more than 100 000 entries (members, plus the directories
  created to hold them). Sizes are counted from the data actually unpacked,
  not from the sizes the archive declares;
- it is a `.tar.zst` that needs a decompression window larger than 64 MiB.

File modes are normalized: a file with any execute bit becomes `0755`, every
other file `0644`. Setuid, setgid, sticky, and group or other write bits are
never applied. Directories get the mode polypkg uses for every directory it
creates in that scope. Owners and modification times recorded in the archive
are ignored.

Like every action that places files, `extract` runs in `pre-place`,
`post-place`, or `pre-activate`.

**`extract` or `install`?** Use `install` for files you put in `content/`
yourself: a binary you built, a script, a config file. Use `extract` when you
ship an upstream release archive unchanged. The file in `content/` then stays
byte-for-byte what upstream published, so a checksum or provenance statement
upstream made about that archive still describes what your package carries.
You could unpack the archive into `content/` yourself and `install` the
pieces, but the package would then carry a tree you assembled rather than
upstream's file. The cost of `extract` is disk: the archive sits packed in the
extract cache and unpacked in the generation.

`polypkg pkg lint` checks the parameter values and that no earlier action
creates `dest` (`PKG010`), and that a `src` present in the source is a
regular file of at most 1 GiB, not a symlink, that starts like an archive
`apply` can unpack (`PKG012`). It does not decompress the archive,
so a damaged or non-tar payload inside a valid compressed stream is caught by
`apply`.

## Reference: `polypkg pkg explain`

Prints an authoring reference — the lifecycle phases, every available action
with its parameters, the `$PKG`/`$ACTIVE` path variables, and the two ways to
ship OS/arch-specific content: one artifact per platform with the `platform:`
key, or one fat artifact that selects its files with a computed `!starlark`
parameter (see [Platforms](#platforms-per-platform-or-fat-artifacts)). Honors
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
  every `mode` stays within `0755` (`PKG010`; see [File modes](#file-modes)),
  and an `extract` action's `src`, `dest`, `strip_components`, and `include`
  hold values `apply` accepts (`PKG010`; see
  [Unpacking an archive](#unpacking-an-archive-extract)).
- **identity** — every relation name is an ASCII slug (`PKG007`), no two
  identifiers in the recipe collide when case-folded (`PKG008`), and a
  declared `platform:` is an `<os>/<arch>` pair the toolchain that built
  polypkg can publish, as listed by `go tool dist list` (`PKG011`; see
  [Platforms](#platforms-per-platform-or-fat-artifacts)).
- **content-reference** — every literal `$PKG/...` param resolves to a file
  that actually exists in the source (`PKG006`), and an `extract` action's
  `src` is a regular file of at most 1 GiB, not a symlink, that starts like
  an archive `apply` can unpack (`PKG012`).

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

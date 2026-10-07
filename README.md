# polypkg

[![test](https://github.com/trevor-vaughan/polypkg/actions/workflows/test.yml/badge.svg)](https://github.com/trevor-vaughan/polypkg/actions/workflows/test.yml)
[![lint](https://github.com/trevor-vaughan/polypkg/actions/workflows/lint.yml/badge.svg)](https://github.com/trevor-vaughan/polypkg/actions/workflows/lint.yml)
[![security](https://github.com/trevor-vaughan/polypkg/actions/workflows/security.yml/badge.svg)](https://github.com/trevor-vaughan/polypkg/actions/workflows/security.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/trevor-vaughan/polypkg.svg)](https://pkg.go.dev/github.com/trevor-vaughan/polypkg)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

`polypkg` is a declarative package manager for Linux, macOS, and FreeBSD. You describe what should be installed in a profile file; `polypkg apply` makes the system match it. Each apply creates an immutable generation, so if something breaks you can return to the previous state with a single command.

## Demo

Point `polypkg` at a repository, install a package, then undo it — every step against a throwaway `file://` repository. Watch for `[verified]`: that is the signature and attestation check polypkg recorded when the package was installed.

![polypkg quickstart: init against a signed file:// repository, apply an empty baseline, install hello, see attestation report print gen 2 hello 1.0.0 [verified], then roll back to generation 1 and watch the package disappear from list](docs/demo/quickstart.gif)

<details>
<summary><b>A compromised repository can't get past the key you pinned</b></summary>

The trust root you give `init` is the only key that source's signatures are ever checked against. Re-sign the repository under someone else's key and the next fetch is refused — while the packages you already installed keep working.

![polypkg refusing a compromised repository: hello installs normally from the publisher whose key the profile pinned, the published tree is then replaced with one re-signed under an attacker's key, and the next upgrade fails with "trust document signature: signature verification failed: Incompatible key identifiers" while list still reports hello 1.0.0 installed](docs/demo/trust.gif)

Keep the trust root somewhere the repository operator cannot write. A `.pub` left inside the directory it validates is not pinned at all — whoever replaces the signatures replaces the key along with them. See [Trust policy](docs/trust-policy.md).

</details>

<details>
<summary><b>Drift: something edits the managed tree, and <code>apply</code> puts it back</b></summary>

The profile stays the source of truth. `status -vv` names every managed path that no longer matches the generation that placed it (removed, retyped, or with different content, link target, or declared mode), and re-applying reconciles them under the default drift policy. Installed files are copies by default, so editing polypkg's extract cache cannot change an installed command, and the next `apply` restores a modified cache from the signed artifact.

![polypkg drift detection: deleting a managed file makes status -vv report drift 1 entries with detail "hello/bin/hello (install): missing [policy: notify_heal]", then apply creates generation 2 and status returns to drift 0 entries](docs/demo/drift.gif)

</details>

<details>
<summary><b>Upgrading when the publisher ships a new version</b></summary>

`upgrade` re-resolves the profile against what the source offers now. Range-constrained packages move; exact pins do not.

![polypkg upgrade: a publisher adds hello 1.1.0 to the repository at serial 2, then upgrade applies generation 2 and list reports hello 1.1.0](docs/demo/upgrade.gif)

</details>

Two more recordings sit with the docs they belong to: [publishing a repository](docs/publishing.md) and [mirroring one for an air-gapped site](docs/mirroring.md).

<sub>All six are rendered with [VHS](https://github.com/charmbracelet/vhs) from the tapes in [`.taskfiles/demo/`](.taskfiles/demo/) — regenerate them with `task demo:all` (needs `vhs`, `ttyd`, and `ffmpeg` on `PATH`). The GIFs are stored in [Git LFS](CONTRIBUTING.md#recorded-demos): run `git lfs install` once, or they arrive as pointer files and the images above render broken.</sub>

----

> 🤖 LLM WARNING 🤖
>
> This project was written with LLM (AI) assistance.
>
> 🤖 LLM WARNING 🤖

----

## Contents

- [Demo](#demo) — recorded terminal sessions: install and rollback, refused signatures, drift, upgrade
- [Background](#background) — why this exists
- [Install](#install) — two paths; there is no tagged release yet
- [Quickstart](#quickstart) — `init`, `search`, `install`, `rollback`
- [Commands](#commands) — the full command reference · [Exit codes](#exit-codes)
- [Scripting](#scripting) — which commands emit which JSON schema
- [Environment](#environment) — `NO_COLOR`, `POLYPKG_*`, and the `XDG_*` directories
- [Glossary](#glossary) — profile, generation, drift, scope, substrate, bridge
- [How it works](#how-it-works-the-declarative-core) — profile format, weak dependencies, multiple sources
- [Trust policy](docs/trust-policy.md) — what polypkg verifies before it installs, and how to tighten it
- [Publishing a repository](#publishing-a-repository) · [Mirroring a repository](docs/mirroring.md) · [Authoring a package](#authoring-a-package) · [Verifying a release](#verifying-a-release)
- [Developing](#developing) · [Contributing](#contributing) · [License](#license)

## Background

Why did I make this? Honestly, we have a ton of package managers that all have different warts from growing organically
over the years. I wanted to see what would happen if I let an LLM go ham trying to write the "perfect" package manager
with support for everything I could possibly think of. Will it be good? I have no idea?! But it's an interesting
experiment.

Try it, have fun, see if it sucks, throw rocks at it!

## Install

Two independent paths. Pick one — they are alternatives, not steps.

### From source (Task)

Requires Go 1.26.6 or newer and [Task](https://taskfile.dev), this project's task runner.

```
task build    # produces bin/polypkg
task install  # copies it to ~/.local/bin/polypkg
```

`task install` runs `build` first, then uses the system `install(1)` to place the binary at `~/.local/bin/polypkg` (mode 0755). Make sure `~/.local/bin` is on your `$PATH`.

Run `task --list` to see all available targets.

### With the Go toolchain

Requires Go 1.26.6 or newer. No clone, no Task. A toolchain left at Go's default
`GOTOOLCHAIN=auto` fetches that patch release for you; see
[CONTRIBUTING.md](CONTRIBUTING.md) if yours is pinned to `local`.

```
go install github.com/trevor-vaughan/polypkg/cmd/polypkg@latest
```

This builds and drops `polypkg` into your `$GOBIN` (default `~/go/bin`); make sure that directory is on your `$PATH`.

### There is no tagged release yet

This repository publishes no semantic-version tags, so `@latest` does not resolve to a release — it resolves to a pseudo-version of the default branch. You get whatever was on `main` when you ran the command. To install a known commit instead, name it:

```
go install github.com/trevor-vaughan/polypkg/cmd/polypkg@<commit-sha>
```

Either install path produces a binary that reports `polypkg 0.1.0-dev` with no commit and no date. Those three values are injected by the release pipeline's linker flags, and neither `task build` nor `go install` supplies them.

That matters for one thing in particular: [SECURITY.md](SECURITY.md) asks a vulnerability reporter for "The version or commit (`polypkg --version`)" — and `--version` today cannot identify a build. Read the real revision out of the binary instead — Go records it whichever way you installed:

```
$ go version -m "$(command -v polypkg)" | awk '$1=="mod"{print; exit}'
	mod	github.com/trevor-vaughan/polypkg	v0.0.0-20260822230705-7c59b0ffb958
```

Built from a working tree with uncommitted changes, that line gains a `+dirty` suffix (`...-7c59b0ffb958+dirty`) — worth reporting as-is, since it says the binary does not match the named commit.

## Quickstart

```
polypkg init                 # set up your profile (scope, source URL, trust root)
polypkg search <name>        # find a package in your sources
polypkg install <name>       # add it to the profile and apply
polypkg list                 # show what's installed
polypkg upgrade              # re-apply; range-constrained packages pick up newer versions
polypkg remove <name>        # remove it from the profile and apply
polypkg rollback             # revert to the previous generation
```

**`polypkg init`**: writes a profile at the scope's default location (`~/.config/polypkg/profile.yaml` for user scope). Without `--source-url` and `--trust-root-file` it presents an interactive wizard on a TTY. For non-interactive or CI use:

```
polypkg init --source-url <URL> --trust-root-file <path>
```

A **trust root** is the repository's [minisign](https://jedisct1.github.io/minisign/) public key — a small `.pub` text file, published by whoever runs the repository, that every signature from that repository is checked against. minisign is a compact Ed25519 signing tool; the `.pub` file is the only part you need. polypkg calls this the trust root everywhere, and stores it in the profile as `trust_root`.

Whichever flag you use, the key is **copied into `<config>/trust/<source>.pub`** and the profile records that copy, so the file you pointed at is read once and never consulted again. See [Trust policy](docs/trust-policy.md) for why that matters.

The source is recorded as `native` by default; if the repository was published
under a different name, pass `--source-name <name>` to match it — each source's
name must equal the name embedded in its signed trust document, and a mismatch
is refused at fetch time (with a hint naming the correct source).

**Careful: `init` and `source add` spell the same two flags differently.** Copying a flag from one command into the other fails with `unknown flag`.

| Concept | `polypkg init` | `polypkg source add` |
|---|---|---|
| repository URL | `--source-url` | `--url` |
| trust root from a local file | `--trust-root-file` | `--trust-root` |
| trust root downloaded from a URL | `--trust-root-url` | `--trust-root-url` |
| confirm a downloaded key without a prompt | `--trust-root-fingerprint <key id>` | `--trust-root-fingerprint <key id>` |

`--trust-root-url` accepts `https://`, `file://`, or an absolute path; plain `http://` is refused. A downloaded key
must be confirmed before it is pinned: on a TTY, by answering a prompt that shows its key id; without one, by passing
`--trust-root-fingerprint <key id>`, where the key id is the one the publisher sees with `polypkg repo key show`. A
mismatch is refused. With a local file the fingerprint is optional and is checked when given.

**`polypkg search <name>`**: queries your configured source for packages whose name contains `<name>`. Marks packages that are already installed, and versions that are not published for this machine's platform.

**`polypkg install <name>`**: resolves the package, writes it into the profile, and applies. A bare name (`hello`) pins the newest available version as a `>=` floor. `<name>@<version>` pins exactly (`hello@1.2.3` writes `=1.2.3`). `<name>@<constraint>` is written verbatim (`hello@">=1.2"`). Validation is all-or-nothing: if any requested package is unknown, nothing is written. A package published only for other platforms is refused with a message that names them and this machine's platform.

**`polypkg list`**: shows installed packages in the current generation, including any exact pins. `-v` adds each package's platform: the `<os>/<arch>` its artifact was published for, or `any` for a platform-agnostic artifact.

**`polypkg upgrade`**: re-applies the profile so range-constrained packages pick up newer versions. Exact pins (`=X.Y.Z`) with a newer version available are reported as held back. Pass one or more package names to bump those exact pins to the newest available version.

**`polypkg remove <name>`**: removes the package from the profile and applies. All-or-nothing: if any named package is absent from the profile, nothing is written.

**`polypkg rollback`**: activates the newest complete generation older than the current one. A generation that an interrupted `apply` left incomplete is skipped, and `--to <N>` refuses one. `polypkg status -v` marks such generations `[incomplete]`, and `gc` removes them. A generation whose manifest is damaged (possible corruption or tampering) is also skipped and refused; `status -v` marks it `[damaged]`, and `gc` keeps it for you to inspect. Pass `--to <N>` to target a specific generation number. Like `apply`, `rollback` fails immediately if another polypkg command holds the lock.

## Commands

### Profile-editing

| Command | Description |
|---|---|
| `init` | Create a profile at the scope's default location (wizard or `--source-url`/`--trust-root-file` flags). |
| `install` (alias: `add`) | Add packages to the profile and apply. |
| `remove` (aliases: `rm`, `uninstall`) | Remove packages from the profile and apply. |
| `upgrade` (alias: `update`) | Re-apply; bump exact pins to newest with named args. |

### Inspection

| Command | Description |
|---|---|
| `search` | Search configured sources for packages matching a term. |
| `list` (alias: `ls`) | List installed packages in the current generation. |
| `info` (alias: `show`) | Show installed and available versions for a package, the platform of the artifact the newest would install (`any` when platform-agnostic), the other platforms that version is published for, and the installed package's platform when it has one. For a package published only for other platforms, a note names where it is published. |
| `status` | Show retained generations, drift, and GC preview (`-v`, `-vv`, `-vvv` for more detail). `-vv` lists the installed packages, tagging each per-platform package with `[platform: <os>/<arch>]`. Exit 3 = an installed package's builder key has been revoked; exit 5 = an installed package carries a revoked attestation; exit 4 = an installed source's revocation list is expired and not under a grace window (precedence 3 > 5 > 4). |
| `plan` | Compute the apply plan and report what would change. Exit 2 = changes pending, 0 = nothing to do. |

### Audit

| Command | Description |
|---|---|
| `attestation report` | Aggregate recorded provenance for every installed package across all retained generations into a `polypkg.attestation-report/v1` document. |

### Lifecycle

| Command | Description |
|---|---|
| `apply` | Apply the profile, creating a new generation. |
| `rollback` | Activate the newest complete generation before the current one (or `--to <N>` for a specific one). |
| `gc` | Remove old generations from the store (`--count`, `--age` flags) and any an interrupted apply left incomplete; never removes a damaged one, but names it; then prunes the extracted packages and cached downloads that no retained or pinned generation records (an attestation a generation does not record may be pruned and is re-downloaded and re-verified when next needed), listing what it removed (the first 20 of each kind in text; all of them under `--format json`). |
| `generation pin` / `generation unpin` | Exempt or un-exempt a generation from automatic GC. |

### Integration

| Command | Description |
|---|---|
| `link` | Symlink the current generation's commands into `~/.local/bin` — the [bridge](#glossary). |
| `unlink` | Remove all polypkg-created command links from `~/.local/bin`. |
| `alternatives` | Inspect and override which package provides a shared command name. |
| `completion` | Generate shell autocompletion scripts (bash, fish, zsh, powershell). |

### Maintenance

| Command | Description |
|---|---|
| `config reset` | Queue a config file for restore to package default on next apply. |
| `accept-drift` | Adopt the current on-disk state of a managed path as the new baseline. |
| `purge` | Delete a package's persistent state directory (destructive, irreversible; remove the package first). |

### Sources, publishing, and mirrors

These four are top-level command groups in `polypkg --help`, each with its own subcommands.

| Command | Description |
|---|---|
| `source` | Manage package sources and their trust roots: `source list`, `source add`, `source remove`. See [Managing sources](#managing-sources). |
| `repo` | Build and sign a repository clients install from: `repo init`, `repo add`, `repo remove`, `repo build`, `repo export-bundle`, `repo status`, `repo key show`, `repo revoke`. See [Publishing a repository](#publishing-a-repository). |
| `pkg` | Author a package source: `pkg init`, `pkg lint`, `pkg build`, `pkg explain`. See [Authoring a package](#authoring-a-package). |
| `mirror` | Offline mirror bundles: `mirror pull` fetches an upstream repository and re-publishes it locally; `mirror verify` checks a bundle's signature, freshness, and completeness. See [Mirroring a repository](docs/mirroring.md). |

## Exit codes

`plan`: 0 = no changes pending, 2 = changes pending, 1 = error.

`status`: 0 = ok, 1 = error, 3 = an installed package's builder key has been revoked, 5 = an installed package carries a revoked attestation, 4 = an installed source's revocation list is expired and not under a grace window (precedence 3 > 5 > 4).

All other commands: 0 = ok, 1 = error.

A **command group** with no subcommand is one of those errors. `alternatives`,
`attestation`, `config`, `generation`, `mirror`, `pkg`, `repo`, and `source`
write nothing to stdout, exit 1, and say what is missing on stderr:

```
$ polypkg repo
error: polypkg repo requires a subcommand
hint: run `polypkg repo --help` to list subcommands
```

An unrecognised subcommand (`polypkg repo bogus`) fails the same way. Asking for
help does not: `polypkg repo --help`, `-h`, and `polypkg help repo` print the
help text to stdout and exit 0.

## Scripting

`--format json` is a persistent flag on the root command, so every invocation accepts it. What it *produces* falls into three groups.

**Envelope commands** emit a versioned `polypkg.cli-result/v2` object: `schema`, `command`, `status`, and `data` on success; `schema`, `command`, `status: "error"`, and `error` on failure. Error objects carry a `hint` field when a suggested fix is available.

`accept-drift`, `alternatives auto`, `alternatives list`, `alternatives set`, `apply`, `config reset`, `gc`, `generation pin`, `generation unpin`, `info`, `init`, `install`, `link`, `list`, `mirror pull`, `mirror verify`, `pkg explain`, `purge`, `remove`, `repo add`, `repo build`, `repo export-bundle`, `repo init`, `repo key show`, `repo remove`, `repo revoke`, `repo status`, `rollback`, `search`, `source add`, `source list`, `source remove`, `unlink`, `upgrade`.

**Own-schema commands** emit a purpose-built document instead of the envelope. An error that aborts the command is still reported as a `cli-result/v2` error envelope.

| Command | Success schema |
|---|---|
| `plan` | `polypkg.plan/v1` |
| `status` | `polypkg.status/v1` |
| `attestation report` | `polypkg.attestation-report/v1` |

`status -v`/`-vv`/`-vvv` do not change the JSON: the full `status/v1` document is always emitted and the verbosity flags are ignored.

**Commands that ignore the flag.** `pkg lint`, `pkg build`, and `pkg init` always print human-readable text; `--format json` is accepted and has no effect. `pkg lint` has its own machine format instead — `--sarif` emits canonical SARIF 2.1.0, and `-o <file>` writes it to a file. `completion` writes a shell script.

A command group invoked with no subcommand honors the flag: stdout gets the
error envelope, stderr still gets the `error:`/`hint:` pair a human is reading.

```
$ polypkg repo --format json
{"schema":"polypkg.cli-result/v2","command":"repo","status":"error","error":"polypkg repo requires a subcommand","hint":"run `polypkg repo --help` to list subcommands"}
```

So a script cannot assume one uniform success predicate. Branch on `.schema`, not on `.status`:

```
polypkg --format json plan profile.yaml   # polypkg.plan/v1; exit 2 when changes are pending
polypkg --format json list                # polypkg.cli-result/v2
polypkg --format json status              # polypkg.status/v1; exit 3/4/5 carry meaning
```

Platform fields in the envelope data:

- `search`: each entry in `matches` has `versions` (installable on this machine)
  and `unavailable_versions` (published only for other platforms). `versions`
  can be empty when `unavailable_versions` is not, for a package published only
  for other platforms, so check it before installing.
- `info`: `platform` is the newest candidate's platform (`any` when
  platform-agnostic), `other_platforms` the other platforms that version is
  published for, and `installed_platform` the installed package's (`""` when not
  installed). For a package published only for other platforms, `platform` is
  `""`, `other_platforms` is non-empty, and `note` carries the reason (`<name>
  <version> is published for <platforms>; this host is <os>/<arch>`).
- `list`: each package carries `platform` (`any` when platform-agnostic).

## Environment

`NO_COLOR` is honored (suppresses ANSI color output).

polypkg's own settings are namespaced `POLYPKG_`. Beyond those it also reads the
[XDG directory variables](#xdg-directories), which relocate the paths documented
elsewhere in this README.

| Variable | Effect | Default |
|---|---|---|
| `POLYPKG_PROFILE` | Overrides default profile discovery. Outranked by an explicit positional profile argument, and by `--profile` on `install`/`remove`/`upgrade`. | unset — discovery per the [rules below](#how-it-works-the-declarative-core) |
| `POLYPKG_SYSTEM_PREFIX` | DESTDIR prefix for system scope: redirects every system-scope read and write under `<prefix>`. Precedence is `--prefix` flag > this variable > the profile's `scopes.<scope>.prefix` > empty (real FHS paths). `--prefix` with `--scope user` is an error, never a silent no-op. | unset |
| `POLYPKG_BRIDGE_ENABLED` | `false` stops polypkg managing the command symlink farm (`~/.local/bin`, or `<prefix>/usr/local/bin` for system scope). | `true` |
| `POLYPKG_COMPLETION_ENABLED` | `false` stops polypkg installing shell completion files. | `true` |
| `POLYPKG_DESKTOP_ENABLED` | `false` stops polypkg writing `.desktop` entries into the applications directory. | `true` |
| `POLYPKG_MIME_ENABLED` | `false` stops polypkg writing into the MIME packages directory. | `true` |
| `POLYPKG_REVOCATION_NEAR_EXPIRY_THRESHOLD` | How early a revocation list counts as "expiring soon". Same forms as other age settings (`14d`, `2w`, `12h`). | `14d` |
| `POLYPKG_REPO_KEY_PASSWORD` | Publisher-side only: unlocks the repository signing key for `repo build`, `repo revoke`, and `repo key show`. `--key-password-file <path>` takes precedence. See [docs/publishing.md](docs/publishing.md). | unset |

`POLYPKG_PROFILE`, `POLYPKG_SYSTEM_PREFIX`, and `POLYPKG_REPO_KEY_PASSWORD` are read directly. The rest are the environment layer over the config file (`config.yaml` in the scope's config directory — `~/.config/polypkg` for user scope, `<prefix>/etc/polypkg` for system scope): a config key `a.b` maps to `POLYPKG_A_B`, and the environment wins over the file.

That config file is small. polypkg reads five keys from it and no others:
`revocation.near_expiry_threshold`, plus the integrator toggles
`bridge.enabled`, `completion.enabled`, `desktop.enabled`, and `mime.enabled` —
exactly the five environment-layered rows in the table above. There is no
undocumented key here to script against. Retention is not a config key at all:
set `retention.count` and `retention.age` in the profile.

### XDG directories

User-scope paths are resolved through the XDG base-directory variables, so
setting one moves paths this README documents by their default. Each is honored
only when set to an **absolute** path; otherwise the platform default applies.
System scope is unaffected — it uses fixed locations (`/etc/polypkg`,
`/var/lib/polypkg`, `/usr/local/bin`), optionally under a `--prefix` DESTDIR.

| Variable | What it moves | Default | macOS default |
|---|---|---|---|
| `XDG_CONFIG_HOME` | the config dir — `config.yaml` and default profile discovery | `~/.config/polypkg` | `~/Library/Preferences/polypkg` |
| `XDG_DATA_HOME` | the data dir | `~/.local/share/polypkg` | `~/Library/Application Support/polypkg` |
| `XDG_STATE_HOME` | the state dir | `~/.local/state/polypkg` | `~/Library/Application Support/polypkg/state` |
| `XDG_BIN_HOME` | the [bridge](#glossary) — where `link` puts command symlinks | `~/.local/bin` | `~/.local/bin` |

Set `XDG_BIN_HOME` and the bridge is no longer at `~/.local/bin`; that is the
one most likely to surprise you, since `link`, `unlink`, and the glossary all
name the default.

`XDG_CONFIG_HOME` and `XDG_DATA_HOME` additionally carry the desktop-integration
and shell-completion directories, which follow the usual conventions rather than
polypkg's own: `$XDG_DATA_HOME/{applications,mime/packages,bash-completion/completions,zsh/site-functions}`
and `$XDG_CONFIG_HOME/fish/completions`. These take no `polypkg` subdirectory and
have no macOS-specific default — `~/.local/share` and `~/.config` everywhere.

Two variables are read incidentally, and neither changes where anything lands:
`PATH`, so `link` can warn when the bridge directory is not on it, and `USER`,
recorded as the actor in `generation pin` metadata (`unknown` when unset).

### What the state dir holds

The [state dir](#xdg-directories) (`/var/lib/polypkg` for system scope) holds
working data beside the generations in the data dir. None of it grows without
bound:

| Path | Contents | How it is bounded |
|---|---|---|
| `cache/<source>/` | Packages and attestations downloaded from an HTTP source, plus that source's latest signed metadata (`index.json`, `trust.json`, …). A local `file://` source is read in place and never cached. | Every successful `apply` deletes cached downloads that no retained or pinned generation records, once they are more than an hour old. In user scope `gc` does the same on demand; `gc` has no system-scope mode, so in system scope only the sweep after `apply` bounds it. A generation records its package and only the attestations its manifest names, so other attestations may be pruned; the next `plan` downloads and verifies them again. The signed metadata is overwritten by each fetch. |
| `pkg-extract/` | Unpacked packages that generations are installed from (and, under `policy: symlink`, link into). | The same sweep, by the same rule. |
| `audit.log` | One JSON object per line for each apply, `gc`, pin, and recorded security decision. `plan` never writes to it. | At 10 MiB it is renamed to `audit.log.1`; `audit.log.2` and `audit.log.3` keep older history and the oldest is deleted. `audit.log.lock` coordinates writers. |
| `apply.lock` | Held by `apply` and by the commands that change what it reads (packages and sources in the profile, generations, pins, and the files in this directory), including `source add`, `source remove`, and `source set-trust-root`. A command that finds it held stops at once and names the holder. | One small file. |
| `trust/` | The highest signed-metadata serial seen per source (anti-rollback), and each package's highest offered version, kept per host platform (downgrade guard). | One small file per source. |
| `accepted-drift.json`, `pending-resets.json` | Paths whose drift you adopted with `accept-drift`, and config files `config reset` queued for the next apply. | At most one entry per managed path. |

If a generation's manifest is damaged, or the current generation has no
manifest, the sweep keeps every cached download and extracted package: nothing
then records what that generation uses.

State files carry a format version. If a newer polypkg wrote one, an older
polypkg refuses to read it and says so —
`<path> was written by a newer polypkg (polypkg.ownership/v2; this version reads v1); upgrade polypkg` —
rather than guessing at its contents. A generation a newer polypkg pinned
stays pinned, and an older `gc` removes nothing while a generation manifest a
newer polypkg wrote is present.

## Glossary

- **profile**: the YAML/JSONC file declaring what should be installed; the single source of truth.
- **generation**: an immutable snapshot created by each apply; rollback switches between generations.
- **drift**: a managed path changed on disk since its generation was applied (removed, retyped, or with different content, link target, or declared mode); `status -vv` shows it, `apply` restores it under the default drift policy, `accept-drift` adopts it.
- **scope**: where software installs: `user` (your home, no root) or `system` (machine-wide).
- **substrate**: the storage backend a scope installs into (the default is the content store).
- **alternatives**: when several packages provide the same command, the arbitration that picks which one wins; `polypkg alternatives` inspects and overrides it.
- **bridge**: the symlink farm that puts the current generation's commands on your `$PATH` (`~/.local/bin` or `/usr/local/bin`). `link` builds it; `unlink` tears it down.
- **trust root**: a source's minisign public key (`.pub` file), against which every signature from that source is verified.

## How it works (the declarative core)

The imperative verbs above are sugar: `install`, `remove`, and `upgrade` edit the profile file and then call `apply`. Power users can edit the profile by hand and run `plan`/`apply` directly.

`plan` shows what would change (exit 2 = changes pending, exit 0 = nothing to do). `apply` makes the system match the profile and records an immutable generation.

A profile looks like this:

```yaml
# polypkg profile: the single source of truth for what's installed.
# Edit this file to add or remove packages, then run:
#   polypkg plan    (preview changes)
#   polypkg apply   (apply them)
schema: polypkg.spec/v1

# A short identifier for this machine (alphanumerics, hyphens, underscores).
name: my-machine

scopes:
  user:                   # installs under your home directory; no root required
    substrate: store      # content-store backend (the default and recommended choice)

sources:
  order: [native]         # priority order: the first source that has a package wins
  native:
    type: polypkg-native
    # URL of the package repository.
    url: https://repo.example.com/polypkg
    # Path to the repository's minisign public key (.pub file).
    # Obtain this from your repository operator.
    trust_root: /etc/polypkg/repo.pub
    # Optional (air-gap grace): accept this source's EXPIRED signed metadata
    # until this RFC3339 deadline. See docs/trust-policy.md.
    # accept_expiry_until: "2027-01-01T00:00:00Z"
    # Optional (supply-chain hardening): pin THIS source's sigstore trust root.
    # When set it is authoritative — the source's mirrored root is ignored.
    # See docs/trust-policy.md.
    # sigstore_root:
    #   valid_from: "2024-01-01T00:00:00Z"
    #   fulcio_ca: ["<base64 DER Fulcio root cert>"]
    #   rekor_keys: ["<base64 Rekor public key>"]

packages:
  user:
    hello:
      version: ">=1.0.0"   # any 1.x or newer; use "=1.0.0" to pin exactly
```

*scope*, *substrate*, *generation*, and *drift* are defined in the [Glossary](#glossary).

Note: `trust_root` is a file path to the repository's minisign public key (`.pub` file), not an inline key. Obtain the key from your repository operator. `init` and `source add` fill this in for you, pointing it at the copy they place under `<config>/trust/`; write it by hand only if you are managing the key store yourself, and keep it somewhere the repository operator cannot write.

**Source names are slugs.** Every key under `sources` — the source names, and
`order` itself — must match `^[a-zA-Z0-9_-]+$`, and that is checked when the
profile is parsed, before anything is fetched. A hand-edited profile carrying a
name outside the grammar no longer loads at all:

```
$ polypkg plan ~/.config/polypkg/profile.yaml
error: profile /home/you/.config/polypkg/profile.yaml is invalid:
  - '../acme' does not match pattern '^[a-zA-Z0-9_-]+$'
```

`polypkg init --source-name` and `polypkg source add` reject the same names up
front (`error: source name "../acme" is not a valid slug`), so a profile either
of them wrote is already conformant. For a hand-written one that is not, rename
the source under `sources` and in `sources.order` to match.

The two optional keys commented out above — `accept_expiry_until` and
`sigstore_root` — are supply-chain policy, documented in
[Trust policy](docs/trust-policy.md).

Default profile resolution: `$POLYPKG_PROFILE` if set, otherwise the first existing `profile.{yaml,yml,jsonc,json}` in the scope's config directory (`~/.config/polypkg` for user scope, `/etc/polypkg` for system scope).

### Weak dependencies

Package recipes may declare two kinds of optional dependency:

```yaml
# inside a polypkg.yaml (package recipe)
recommends:
  - name: jq             # install if satisfiable; skipped if it conflicts or is unavailable
    version: ">=1.6"
suggests:
  - name: bat            # surfaced in plan/apply output only; never installed automatically
```

`recommends` entries are pulled in automatically after the hard dependency solve succeeds. If a recommend conflicts with the already-selected set or cannot be found, it is dropped and reported — it never causes the overall install to fail. `suggests` entries are advertised but never installed regardless of policy.

**Policy.** By default recommends are installed. To disable them for a profile:

```yaml
# profile.yaml
recommends:
  install: false
```

To suppress them for a single run without editing the profile, pass `--no-recommends` to `plan` or `apply`. The flag takes precedence over the profile block.

**`--no-recommends` exists on `plan` and `apply` only.** `install`, `remove`, and `upgrade` call `apply` internally, but they do not accept or forward the flag — `polypkg install foo --no-recommends` fails with `unknown flag`. Those three take `--profile` plus the scope flags (`--scope`, `--prefix`) and nothing else. To install without recommends, either set `recommends.install: false` in the profile, or add the package to the profile by hand and run `polypkg apply --no-recommends`.

**Output.** `plan` and `apply` list skipped recommends under "skipped recommended packages:" and surfaced suggests under "suggested (not installed):". `status -vv` shows each package's `[weak]` tag and which package(s) recommended it. `info <package>` shows the `recommends:` and `suggests:` lists from the newest catalog candidate.

### Multiple sources

`sources.order` is a priority list. When more than one source offers a package
with the same name, the **first source in `order` that has it wins**; lower
sources are shadowed for that name. To prefer a different source's build, move
it earlier in `order` or pin the package.

A source "has" a package when it publishes that name for **any** platform, not
only for this machine's. If the first source publishes `tool` only for other
platforms, installing `tool` here fails with a message naming the platforms it
is published for; polypkg does not fall back to a lower source's build. That
rule prevents dependency confusion: otherwise a public source lower in `order`
could supply its own `tool` on every machine your private source does not build
for. To take a lower source's build deliberately, pin the package to it with
`source:`.

Pin a single package to a specific source with `source:`:

```yaml
sources:
  order: [stable, edge]
  stable:
    type: polypkg-native
    url: https://repo.example.com/stable
    trust_root: /etc/polypkg/stable.pub
  edge:
    type: polypkg-native
    url: https://repo.example.com/edge
    trust_root: /etc/polypkg/edge.pub

packages:
  user:
    tool:
      version: ">=1.0.0"
      source: edge      # always resolve `tool` from `edge`, ignoring order
```

Each source is verified independently against its own `trust_root`; an artifact
is only ever accepted under the signing keys of the source it came from. If any
configured source is unreachable, the operation fails rather than silently
falling back to a lower-priority source.

### Managing sources

`polypkg source` edits the profile's source list without hand-editing YAML. Comments and formatting are preserved.

```
polypkg source list
polypkg source add <name> --url <http(s)|file://>  --trust-root <path-to-.pub>
polypkg source add <name> --url <...> --trust-root-url <https-url> --trust-root-fingerprint <key id>
polypkg source set-trust-root <name> --trust-root <path-to-.pub> --trust-root-fingerprint <key id>
polypkg source remove <name>
```

`add` validates the URL and trust root before writing, and refuses a name that is already in the profile. The trust root can be a local `.pub` file (`--trust-root`) or downloaded from a URL (`--trust-root-url`: `https://`, `file://`, or an absolute path; plain `http://` is refused) and confirmed the first time you see it — trust on first use, or TOFU. On a TTY that confirmation is a prompt showing the key id; without one, pass `--trust-root-fingerprint <key id>` with the id the publisher gets from `polypkg repo key show`. With `--trust-root` the fingerprint is optional, and checked when given.

`remove` blocks removal of the last source because a profile with no sources is invalid; it also deletes the source's managed key copy, `<config>/trust/<name>.pub`, unless another source references it. Every route (`--trust-root`, `--trust-root-url`, `init`) pins that copy; the operator's original file is never touched, and neither is a hand-written `trust_root` outside `<config>/trust/`. Each named source must match the name embedded in its signed trust document.

`set-trust-root` is the only way to change the key a source is pinned to. It shows the pinned and the new key ids and needs the same confirmation as `add` (a prompt on a TTY, otherwise `--trust-root-fingerprint`, which must match the new key). It saves the new key as `<config>/trust/<name>.pub`, keeps the source's URL and its place in the order, and clears the source's anti-rollback memory so that a repository rebuilt with restarted serials is accepted. It works on a profile with a single source. Supplying the key that is already pinned changes nothing, unless you add `--reset-state`: that clears the anti-rollback memory anyway, for a repository that was re-created with the same key and restarted its serials. Because it lowers rollback protection until the next fetch, `--reset-state` requires `--trust-root-fingerprint`.

Remember that `source add` spells its flags `--url` and `--trust-root`, while `init` spells the same two `--source-url` and `--trust-root-file`. See the [table in the Quickstart](#quickstart).

If a source is legitimately rebuilt from scratch and its serials reset, polypkg's
anti-rollback memory refuses the fetch until the source is re-pinned with
`polypkg source set-trust-root` —
[Trust policy](docs/trust-policy.md#recovering-after-a-repository-is-re-created) has the recovery.

### Supply-chain verification

Everything a source serves is verified before it installs, with no configuration
required:

1. **Signed, fresh metadata** — the trust document and index are
   minisign-signed, carry a monotonic serial, and expire. Stale metadata, or a
   mirror trying to pin you to an older snapshot, is refused.
2. **Artifact signatures** — every downloaded artifact is checked against the
   source's signing key and the BLAKE3 content hash in the signed index. The
   signature also covers the package's name, version, and platform, and the
   package's own `polypkg.yaml` must agree with all three before anything
   installs.
3. **Attestations** — a per-package [in-toto](https://in-toto.io/) lint
   attestation is referenced from the signed index, so a mirror cannot strip it
   without invalidating that signature. An attestation that is present but does
   not verify refuses the install in **every** policy mode.

A verified attestation proves provenance, not benignity: the package was
lint-checked and published by the holder of the source's signing key, and has
not been substituted since. It does not mean the package is safe to run — vet
your sources.

`attestation.policy` (`warn` by default, or `require`/`off`) governs one
question only: what happens when a package carries *no* attestation. Everything
past that — requiring named predicate types, pinning the builder identities you
accept, the anti-downgrade posture floor, a source's `tier: off` safety valve,
freshness grace for an air-gapped mirror, and the revocation surfaces behind
`status` exit codes 3, 4, and 5 — lives in
**[docs/trust-policy.md](docs/trust-policy.md)**.

## Publishing a repository

`polypkg repo` builds and signs the repositories that `polypkg` installs from —
`repo init`/`add`/`build`, incremental rebuilds, prebuilt ingest, and
`repo revoke` for withdrawing a compromised builder key or a bad attestation.
See **[docs/publishing.md](docs/publishing.md)**.

`polypkg mirror` is a separate top-level command group, not a `repo`
subcommand: `mirror pull` clones an upstream repository under your own signing
key, and `mirror verify` checks an exported bundle before you serve it at an
air-gapped site. See **[docs/mirroring.md](docs/mirroring.md)**.

## Authoring a package

`polypkg pkg` is the package author's inner loop — scaffold, lint, and build an
unsigned artifact before publishing it with `repo`. See
**[docs/authoring.md](docs/authoring.md)**.

## Verifying a release

Release archives on GitHub carry GitHub build provenance ([SLSA](https://slsa.dev/)), a Cosign
keyless signature over the checksum manifest, and a per-archive Syft SBOM. See
**[docs/verifying.md](docs/verifying.md)** for the verification commands.

## Developing

```
task build            # compile to bin/polypkg
task test             # run unit + in-process integration tests with race detector
task test:fips        # same suite under GODEBUG=fips140=on (Go FIPS 140-3 module)
task test:integration # container-based E2E across centos/ubuntu/alpine (needs podman)
task test:vm          # opt-in VM-based LSM-enforcement tier (boots guests under QEMU; needs qemu)
task lint             # run golangci-lint
task fmt              # gofmt all packages
```

The last two are opt-in, excluded from `task check`, and need host setup of
their own. `test:integration` drives the real binary through the full lifecycle
in throwaway containers across a distro matrix; `test:vm` boots a guest with its
own kernel so an LSM can run enforcing regardless of the host, and asserts zero
denials. [CONTRIBUTING.md](CONTRIBUTING.md) has the setup;
`tests/e2e/README.md` and `tests/vm/README.md` have the topology and the honest
enforcement scope.

Architecture notes and design decisions are in `docs/dev/` at the repository root.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for how to build, test, and submit changes, and the [Code of Conduct](CODE_OF_CONDUCT.md) for community expectations. To report a security vulnerability, follow the [Security Policy](SECURITY.md) rather than opening a public issue.

Notable changes are tracked in [CHANGELOG.md](CHANGELOG.md).

## License

polypkg is free software, licensed under the **GNU General Public License v3.0**. See [LICENSE](LICENSE) for the full text.

Copyright (C) 2026 Trevor Vaughan.

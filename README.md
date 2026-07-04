# polypkg

[![test](https://github.com/trevor-vaughan/polypkg/actions/workflows/test.yml/badge.svg)](https://github.com/trevor-vaughan/polypkg/actions/workflows/test.yml)
[![lint](https://github.com/trevor-vaughan/polypkg/actions/workflows/lint.yml/badge.svg)](https://github.com/trevor-vaughan/polypkg/actions/workflows/lint.yml)
[![security](https://github.com/trevor-vaughan/polypkg/actions/workflows/security.yml/badge.svg)](https://github.com/trevor-vaughan/polypkg/actions/workflows/security.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/trevor-vaughan/polypkg.svg)](https://pkg.go.dev/github.com/trevor-vaughan/polypkg)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

`polypkg` is a declarative package manager for Linux, macOS, and FreeBSD. You describe what should be installed in a profile file; `polypkg apply` makes the system match it. Each apply creates an immutable generation, so if something breaks you can return to the previous state with a single command.

----

> 🤖 LLM WARNING 🤖
>
> This project was written with LLM (AI) assistance.
>
> 🤖 LLM WARNING 🤖

----

## Background

Why did I make this? Honestly, we have a ton of package managers that all have different warts from growing organically
over the years. I wanted to see what would happen if I let an LLM go ham trying to write the "perfect" package manager
with support for everything I could possibly think of. Will it be good? I have no idea?! But it's an interesting
experiment.

Try it, have fun, see if it sucks, throw rocks at it!

## Install

```
task build    # produces bin/polypkg
task install  # copies it to ~/.local/bin/polypkg
```

`task install` runs `build` first, then uses the system `install(1)` to place the binary at `~/.local/bin/polypkg` (mode 0755). Make sure `~/.local/bin` is on your `$PATH`.

Or install the latest tagged release straight from source with the Go toolchain:

```
go install github.com/trevor-vaughan/polypkg/cmd/polypkg@latest
```

This builds and drops `polypkg` into your `$GOBIN` (default `~/go/bin`); make sure that directory is on your `$PATH`.

This project uses [Task](https://taskfile.dev) as its task runner; run `task --list` to see all available targets.

## Quickstart

```
polypkg init                 # set up your profile (scope, source URL, trust key)
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

The source is recorded as `native` by default; if the repository was published
under a different name, pass `--source-name <name>` to match it — each source's
name must equal the name embedded in its signed trust document, and a mismatch
is refused at fetch time (with a hint naming the correct source).

**`polypkg search <name>`**: queries your configured source for packages whose name contains `<name>`. Marks packages that are already installed.

**`polypkg install <name>`**: resolves the package, writes it into the profile, and applies. A bare name (`hello`) pins the newest available version as a `>=` floor. `<name>@<version>` pins exactly (`hello@1.2.3` writes `=1.2.3`). `<name>@<constraint>` is written verbatim (`hello@">=1.2"`). Validation is all-or-nothing: if any requested package is unknown, nothing is written.

**`polypkg list`**: shows installed packages in the current generation, including any exact pins.

**`polypkg upgrade`**: re-applies the profile so range-constrained packages pick up newer versions. Exact pins (`=X.Y.Z`) with a newer version available are reported as held back. Pass one or more package names to bump those exact pins to the newest available version.

**`polypkg remove <name>`**: removes the package from the profile and applies. All-or-nothing: if any named package is absent from the profile, nothing is written.

**`polypkg rollback`**: activates the previous generation. Pass `--to <N>` to target a specific generation number.

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

packages:
  user:
    hello:
      version: ">=1.0.0"   # any 1.x or newer; use "=1.0.0" to pin exactly
```

Note: `trust_root` is a file path to the repository's minisign public key (`.pub` file), not an inline key. Obtain the key from your repository operator.

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

To suppress them for a single run without editing the profile, pass `--no-recommends` to `plan` or `apply`. Flag takes precedence over the profile block.

**Output.** `plan` and `apply` list skipped recommends under "skipped recommended packages:" and surfaced suggests under "suggested (not installed):". `status -vv` shows each package's `[weak]` tag and which package(s) recommended it. `info <package>` shows the `recommends:` and `suggests:` lists from the newest catalog candidate.

### Multiple sources

`sources.order` is a priority list. When more than one source offers a package
with the same name, the **first source in `order` that has it wins**; lower
sources are shadowed for that name. To prefer a different source's build, move
it earlier in `order` or pin the package.

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
polypkg source add <name> --url <...> --trust-root-url <url> --trust-root-yes
polypkg source remove <name>
```

`add` validates the URL and trust root before writing; the trust root can be a local `.pub` file (`--trust-root`) or downloaded and TOFU-confirmed from a URL (`--trust-root-url`, confirm with `--trust-root-yes` when not on a TTY). `remove` blocks removal of the last source because a profile with no sources is invalid; it also deletes the trust-root key that `--trust-root-url` persisted for that source, while leaving externally-supplied `--trust-root` files untouched. Each named source must match the name embedded in its signed trust document.

### Supply-chain verification

Everything a source serves is verified before it installs:

1. **Signed, fresh metadata.** A source's trust document and index are minisign-signed and carry a monotonic serial plus an `expires` bound. Metadata past its `expires` (with a small clock-skew tolerance) is refused with a "stale metadata refused; the publisher must re-sign" error — a mirror cannot pin you to an old-but-validly-signed catalog.
2. **Artifact signatures.** Every downloaded artifact is verified against the source's signing key and its BLAKE3 content hash from the signed index.
3. **Attestations.** Publishers sign a per-package [in-toto](https://in-toto.io/) lint attestation and reference it from the signed index (so it cannot be stripped without invalidating the index signature). When an index entry carries attestations, polypkg verifies the whole chain — the attestation signature under the dedicated `attestation` key role, the content-addressed hash bindings, and that the statement's subject digest matches the artifact — in **every** policy mode.

**What an attestation proves: provenance, not benignity.** A verified attestation means the package was lint-checked and published by the holder of the source's signing key and has not been substituted or tampered with since. It does not mean the package is safe to run — vet your sources.

**Policy.** The `attestation.policy` setting only governs packages whose index entry carries *no* attestation. A present-but-invalid attestation is always fatal, in every mode:

```yaml
# profile.yaml
attestation:
  policy: warn   # warn (default) | require | off
```

| Policy | Attestation absent | Attestation present but invalid |
|---|---|---|
| `warn` (default) | installs, warns on stderr | **refuses — always** |
| `require` | refuses | **refuses — always** |
| `off` | installs silently | **refuses — always** |

**Strip-resistance ends at the signer.** In-index references defeat a mirror — it cannot remove an attestation without invalidating the index signature — but not the publisher key itself: a compromised key (or a publisher running `repo build --skip-attestations`) can sign a fresh index with no attestation refs, which the default `warn` policy installs with only a stderr warning. Operators who treat attestation presence as an acceptance criterion must set `policy: require`, which turns attestation disappearance into a refusal.

The install-time verdict is recorded in the generation manifest: `status -vv` tags each package `[attested]` or `[unattested]`, and `info <package>` shows an `attestation:` line with the verified predicate type(s) and the policy that was in force at install. Packages installed before attestations existed carry no record and no tag.

**Downgrade guard.** polypkg remembers the highest version each source has offered for every package. A plan that resolves a package *below* that high-water mark is refused only when the source has **withdrawn** its top — the current signed index no longer offers any version at or above the mark. Picking an older version the index still carries (an upper-bounded range, a dependency constraint, a profile pin) is ordinary constraint resolution and is never refused. To knowingly accept a real withdrawal — say the publisher pulled a broken release — pin the exact version in the profile (`version: "=1.2.3"`).

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
| `info` (alias: `show`) | Show installed and available versions for a package. |
| `status` | Show retained generations, drift, and GC preview (`-v`, `-vv`, `-vvv` for more detail). |
| `plan` | Compute the apply plan and report what would change. Exit 2 = changes pending, 0 = nothing to do. |

### Lifecycle

| Command | Description |
|---|---|
| `apply` | Apply the profile, creating a new generation. |
| `rollback` | Activate the previous generation (or `--to <N>` for a specific one). |
| `gc` | Remove old generations from the store (`--count`, `--age` flags); also sweeps extracted-package dirs no retained generation references. |
| `generation pin` / `generation unpin` | Exempt or un-exempt a generation from automatic GC. |

### Integration

| Command | Description |
|---|---|
| `link` | Symlink the current generation's commands into `~/.local/bin`. |
| `unlink` | Remove all polypkg-created command links from `~/.local/bin`. |
| `alternatives` | Inspect and override which package provides a shared command name. |
| `completion` | Generate shell autocompletion scripts (bash, fish, zsh, powershell). |

### Maintenance

| Command | Description |
|---|---|
| `config reset` | Queue a config file for restore to package default on next apply. |
| `accept-drift` | Adopt the current on-disk state of a managed path as the new baseline. |
| `purge` | Delete a package's persistent state directory (destructive, irreversible; remove the package first). |

## Glossary

- **profile**: the YAML/JSONC file declaring what should be installed; the single source of truth.
- **generation**: an immutable snapshot created by each apply; rollback switches between generations.
- **drift**: a managed file changed on disk since its generation was applied; `status -vv` shows it, `accept-drift` adopts it.
- **scope**: where software installs: `user` (your home, no root) or `system` (machine-wide).
- **substrate**: the storage backend a scope installs into (the default is the content store).
- **alternatives**: when several packages provide the same command, the arbitration that picks which one wins; `polypkg alternatives` inspects and overrides it.
- **bridge**: the symlink farm that puts the current generation's commands on your `$PATH` (`~/.local/bin` or `/usr/local/bin`).

## Exit codes

`plan`: 0 = no changes pending, 2 = changes pending, 1 = error.

All other commands: 0 = ok, 1 = error.

## Scripting

All commands support `--format json`. Output is a versioned `polypkg.cli-result/v2` envelope; error objects carry a `hint` field when a suggested fix is available.

```
polypkg --format json plan profile.yaml
```

`NO_COLOR` is honored (suppresses ANSI color output).

`POLYPKG_PROFILE` overrides the default profile path for all commands that resolve a profile.

## Publishing a repository

`polypkg repo` builds and maintains the repositories that `polypkg` installs from.

```
polypkg repo init ./myrepo --source native    # scaffold + generate signing key
polypkg repo add ./pkgs/hello                  # register a package and (re)build
polypkg repo build                             # reconcile after editing the manifest by hand
polypkg repo status                            # show pending changes (exit 2 if a build is needed)
polypkg repo key show                          # print the public signing key + fingerprint
```

The repository is described declaratively by `polypkg-repo.yaml`; `add`/`remove`
are sugar that edit it then reconcile, exactly like `install`/`apply` on the
client side.

The signing key is generated **encrypted** and stored **outside** the published
directory (under your XDG data dir by default, or `--key-dir`). Provide its
password via `POLYPKG_REPO_KEY_PASSWORD` or `--key-password-file` — never as a
bare flag. Serve `./myrepo/public` over HTTP and distribute
`public/trust_root.pub` to clients as their `trust_root`. Clients must also
configure the source under the same name the repository was published with
(`repo init --source <name>`): the trust document is bound to that name, so a
profile that calls the source anything else is refused at fetch time. Tell
clients to run `polypkg init --source-name <name>` (or `polypkg source add
<name> ...`) when the repository was not published as the default `native`.
(`repo status` is a read-only probe and needs no password.)

The source URL in a consumer profile may be a local filesystem path instead of
an HTTP endpoint — useful for testing a freshly built repo or pointing at an
air-gapped mirror. Pass a `file://` URI (`file:///abs/path/to/public`) or a bare
absolute path to `polypkg init --source-url`; bare paths are canonicalized to
`file://` before the profile is written.

Builds are incremental: only packages whose source changed are re-packed and
re-signed, and the index/trust serial is bumped only when the published output
actually changes (a content change, a key rotation, or an expiry renewal —
see below).

**Freshness (`--valid-for`).** Every build stamps an `expires` bound into the
signed index and trust document (default `720h`, 30 days); consumers refuse
metadata past it. A no-op rebuild reuses the published `expires` while more
than half the window remains, so rapid rebuilds stay byte-identical and do not
bump the serial. Once the remaining window drops below its half-life, the next
build re-stamps a fresh window and bumps the serial — TUF-style re-signing
with no content change. `repo status` reports "metadata expiry refresh due"
(exit 2) when that renewal is pending, so re-run `repo build` at least every
half-window (15 days at the default) or clients will start refusing the
stale metadata.

**Attestations.** `repo build` re-runs the package linter on every (re)packed
package, refuses to publish any package with error-severity lint findings, and
publishes a signed in-toto lint attestation beside each artifact, referenced
from the signed index. Pass `--skip-attestations` to publish without them —
intended for a split-key setup where the signing key deliberately lacks the
attestation role. Caveat: a cached (unchanged) package keeps the attestation
decision it was built with; flipping `--skip-attestations` takes effect for a
package only after its source changes or the build cache is cleared.

**Pool layout.** Artifacts are published content-addressed under
`public/pool/<blake3-hash>.tar.zst`. Republishing a changed build of the same
version writes a *new* blob and repoints the index at it; old blobs persist
immutably so previously signed indexes — and consumer rollbacks — keep
resolving. The pool therefore grows with every republish until pool garbage
collection lands (future work).

**FIPS:** pass `--kdf pbkdf2` at init for FIPS-approved key encryption. The tool
runs clean under `GODEBUG=fips140=on` (`task test:fips`); Ed25519 signatures and
PBKDF2 key derivation route through Go's validated FIPS 140-3 module.

## Verifying a release

Release archives published on GitHub carry three independent supply-chain attestations.

GitHub build provenance (SLSA), checked with the GitHub CLI:

```
gh attestation verify polypkg_<version>_<os>_<arch>.tar.gz --repo trevor-vaughan/polypkg
```

A Cosign keyless signature over the checksum manifest (a Sigstore bundle):

```
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp 'https://github.com/trevor-vaughan/polypkg/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

Then confirm the downloaded archive against the verified manifest:

```
sha256sum -c checksums.txt
```

Each release also ships a per-archive Syft SBOM (`*.tar.gz.sbom.json`).

## Authoring a package

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

`task test:integration` drives the real built binary through the full lifecycle
(build & publish a signed repo → user- and system-scope install → upgrades,
conflicts, drift, anti-rollback, gc) inside throwaway containers across a
distro matrix. It needs rootless `podman` + `podman-compose`. See
`tests/e2e/README.md` for the topology, suite coverage, and what the matrix
does and does not prove about LSM enforcement.

`task test:vm` is the other half of that LSM story: an **opt-in** tier
(excluded from `task test` and `task check`) that boots a guest with its own
kernel under QEMU, so an LSM can run enforcing regardless of the host. It runs
the real binary's install → upgrade → remove lifecycle as root on CentOS Stream
10 (SELinux enforcing) and Ubuntu 24.04 (AppArmor) and asserts **zero LSM
denials**. On a host without `/dev/kvm` it runs under TCG emulation (~100s per
guest), which is why it is opt-in. See `tests/vm/README.md` for the topology,
runtime cost, and honest enforcement scope.

Architecture notes and design decisions are in `docs/dev/` at the repository root.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for how to build, test, and submit changes, and the [Code of Conduct](CODE_OF_CONDUCT.md) for community expectations. To report a security vulnerability, follow the [Security Policy](SECURITY.md) rather than opening a public issue.

Notable changes are tracked in [CHANGELOG.md](CHANGELOG.md).

## License

polypkg is free software, licensed under the **GNU General Public License v3.0**. See [LICENSE](LICENSE) for the full text.

Copyright (C) 2026 Trevor Vaughan.

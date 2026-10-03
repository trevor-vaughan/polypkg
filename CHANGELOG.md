# Changelog

All notable changes to polypkg are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it starts cutting releases. Nothing has been released yet, so everything
below lives under *Unreleased*; while the version stays below `1.0.0`, the CLI
and on-disk formats may change in breaking ways.

## [Unreleased]

### Added

- Recorded terminal demos in the README and the publishing, mirroring, and
  trust-policy guides. Six VHS tapes in `.taskfiles/demo/` render to
  `docs/demo/*.gif` via `task demo:all`; each records against a throwaway signed
  `file://` repository with `HOME` and the `XDG_*` directories redirected, so a
  render cannot touch a real profile. The GIFs are tracked in Git LFS —
  `git lfs install` is now required for a clone to render the docs correctly.
- Declarative profile model: describe the desired set of packages in a profile
  and run `plan`/`apply` to reconcile the system to it. Every `apply` becomes an
  immutable generation.
- `rollback` to any retained generation (anti-rollback enforced), `gc` with a
  grace window, and `generation pin`/`unpin` to exempt a generation from
  collection.
- Imperative convenience verbs (`install`, `remove`, `upgrade`, `search`,
  `info`) that edit the profile and apply.
- Inspection commands: `list`, `plan`, and `status` — the latter reporting
  drift, a GC preview, freshness-grace posture, and packages installed under a
  revoked builder key.
- User and system scopes backed by a content-store substrate.

- Multiple prioritized sources with per-package source pinning; each source is
  verified independently against its own trust root, acquired TOFU.
- Signed `polypkg-native` repositories with minisign-compatible Ed25519
  signatures.
- Repository publishing via `polypkg repo` (init, add/remove, build, status,
  key management) with encrypted signing keys stored outside the published tree
  and incremental, serial-bumping rebuilds.
- Offline mirror bundles: `repo export-bundle` writes a signed, self-contained
  tarball of a built repository, `repo pull` fetches upstream packages and
  re-publishes them into one, and `mirror verify` checks a bundle's manifest
  signature, freshness, and completeness before use.

- Trust-bundle and revocation-list primitives (`polypkg.trust-bundle`,
  `polypkg.revocation-list`), anchored by the source trust root and loaded with
  freshness plus serial anti-rollback, exposing a temporal builder-key query
  API.
- Carried external provenance at publish: `repo build` discovers
  `attestations/*.json` in a package source, binds each attestation's subjects
  to the packed bytes by digest (refusing provenance that describes nothing
  packed), stores the DSSE envelope with a publisher transport signature, emits
  a polypkg link attestation, and records the SARIF, carried, and link refs as a
  sorted multi-ref set in the signed index.
- Carried external provenance at install: polypkg re-binds each carried
  attestation's subjects by digest against the fetched tarball and extracted
  tree, refuses the install if a carried attestation binds nothing installed,
  and records bound refs in the manifest's `attestation.carried_bindings` at a
  `bound-unverified` tier — transport-verified and digest-bound, with external
  builder-signature verification against the keyring not yet performed.
- `polypkg attestation report` emits a deterministic provenance-evidence report
  from recorded evidence.

- Package manifests declare `actions:` — each item carrying a `phase` and an
  `action`; `ownership.json` and `plan --json` record the chosen action in an
  `action` field.
- Starlark-sandboxed package builds (RSS-limited), package linting (`lint`)
  emitting human or SARIF findings, and diff3 three-way config merge for drift.
- `pkg init` scaffolds a task-first package: it leads with the package identity,
  annotates each action inline, and includes a `path` action so the command
  lands on `$PATH` once published and installed. The `init` profile scaffold
  documents the `attestation.policy` knob.
- `pkg explain` prints an authoring reference — the lifecycle phases, every
  action and its parameters (discovered from the action registry), the
  `$PKG`/`$ACTIVE` path variables, and how to make a package OS/arch-aware with
  a computed `!starlark` parameter — honoring `--format text|json`.
- `init --source-name` and `source add` validate source names against the same
  reserved-name and slug rules, with a recovery hint when a source's configured
  name does not match the name bound into its signed trust document.

- Integration commands: `link`/`unlink` (bridge into `~/.local/bin`),
  `alternatives` arbitration (`auto` clears a manual selection), desktop/mime
  integration, and shell `completion` (bash, fish, zsh, powershell).
- Maintenance commands: `config reset`, `accept-drift`, and `purge`.
- JSON output (`--format json`, `polypkg.cli-result/v2` envelope), `NO_COLOR`
  support, and the `POLYPKG_PROFILE` override. `status` renders generation ages
  at their largest whole unit (42s / 8m / 3h / 2d), and `generation <unknown>`
  fails with an error and a hint rather than silently printing help.

- Extracted package trees are content-addressed
  (`pkg-extract/<name>-<version>+<hash16>`) and materialized by extract-to-temp
  plus atomic rename, so republishing different bytes under the same version
  cannot rewrite the tree a retained or pinned generation resolves through, and
  an interrupted extraction cannot leave a half-written directory behind.
- `gc` and every successful `apply` sweep extracted-package directories that no
  retained generation references (after a one-hour grace window that protects
  in-flight applies), keeping older pre-content-addressed layouts while a
  generation still references them and skipping fail-safe if any retained
  generation's manifest cannot be read.
- A poisoned download-cache entry — an artifact or attestation whose cached
  bytes fail signature or digest verification — is evicted and refetched once
  instead of wedging the client on the stale bytes.

- FIPS mode: runs clean under Go's FIPS 140-3 module (`GODEBUG=fips140=on`),
  with PBKDF2 key derivation available via `--kdf pbkdf2`.
- Runs on Linux, macOS, and FreeBSD.
- `go install github.com/trevor-vaughan/polypkg/cmd/polypkg@latest` support and
  build metadata (commit, date) in `polypkg --version`.
- Continuous integration (test matrix, lint, govulncheck, CodeQL, scheduled
  fuzzing, and the shared MegaLinter policy), Dependabot dependency updates, and
  a GoReleaser release pipeline producing Cosign-signed checksums, per-archive
  Syft SBOMs, and GitHub SLSA build-provenance attestations.

### Fixed

- `search`'s interactive picker can install again. The picker ran inside the
  closure that holds the apply lock, so the install it started could never
  acquire that lock and failed with `another polypkg command is already running
  (polypkg search)`. The catalog fetch now returns its rows and releases the
  lock before anything is printed or picked.
- `repo init --key-dir <relative-path>` records a key path later commands can
  find. It recorded the path verbatim, but manifest paths resolve against the
  manifest directory while `--key-dir` is relative to your working directory, so
  `repo init ./myrepo --key-dir ./keys` wrote the key where `repo add` would not
  look. An absolute `--key-dir` was unaffected.
- `repo add` no longer fails after publishing when the build-cache directory is
  absent. The cache defaults under the XDG data dir and is written after the
  repository is built, signed, and published, so a missing directory turned
  completed work into a non-zero exit.

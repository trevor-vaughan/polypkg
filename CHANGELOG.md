# Changelog

All notable changes to polypkg are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it starts cutting releases. Nothing has been released yet, so everything
below lives under *Unreleased*; while the version stays below `1.0.0`, the CLI
and on-disk formats may change in breaking ways.

## [Unreleased]

### Changed

- **BREAKING:** package manifests now declare `actions:` — each item carrying a
  `phase` and an `action` — instead of the former `verbs:`/`verb:`. The
  `ownership.json` and `plan --json` `verb` field is renamed to `action`.
  Existing on-disk generation stores must be re-applied to regenerate their
  ownership records under the new field name.
- The `pkg init` scaffold is task-first: it leads with the package identity,
  annotates each action inline, drops the redundant `dir` action (`install`
  creates its own parent directories), and points to `polypkg pkg explain`
  instead of an inline primer.

### Added

- `repo build` now carries external provenance: it discovers `attestations/*.json`
  in a package source, binds each attestation's subjects to the packed bytes by
  digest (refusing to publish provenance that describes nothing packed), stores
  the envelope verbatim in the pool with a publisher transport signature, emits a
  polypkg link attestation, and records SARIF + carried + link as a sorted
  multi-ref set in the signed index. Builder-signature verification is a later
  phase.

- The consumer now completes the two-point binding at install: after extraction,
  polypkg re-binds each carried attestation's subjects by digest against the
  installed bytes (the fetched tarball and extracted content tree) and refuses the
  install if a carried attestation binds nothing installed. Bound carried refs are
  recorded in the manifest's `attestation.carried_bindings` at a `bound-unverified`
  tier; the external builder signature is not yet verified.

- Internal trust-bundle primitive: `polypkg.trust-bundle/v1` (builder keyring +
  sigstore roots) and `polypkg.revocation-list/v1`, both anchored by the source
  `trust_root`, with freshness + serial anti-rollback loaders and a temporal
  builder-key query API. Foundational for carried external provenance; not yet
  wired into publish/install.

- Provenance carriage representation: optional `kind`/`format`/`subject_scope`/
  `subject_digests` on index attestation refs (additive to `polypkg.index/v2`),
  a generalized in-toto statement parse that accepts non-blake3 subjects, and a
  fail-closed multi-digest binding matcher. Not yet wired into publish/install.

- Provenance carriage foundations: the build cache now stores a list of
  attestation refs (`repo-cache/v3`, older caches cold-reset) so carried
  provenance survives rebuilds, and `ExtractCarriedSubjects` shallow-reads the
  subjects of a DSSE-wrapped or bare in-toto attestation. Not yet wired into
  publish.

- `polypkg pkg explain` prints an authoring reference: the lifecycle phases,
  every action and its parameters (discovered from the action registry), the
  `$PKG`/`$ACTIVE` path variables, and how to make a package OS/arch-aware with
  a computed `!starlark` parameter. Honors `--format text|json`.

- `init --source-name` records a non-default source name in the profile. The
  name is validated against the same reserved-name and slug rules as
  `source add`, which now also rejects invalid names before touching the
  profile.
- A recovery hint when a configured source's name does not match the name
  bound into its signed trust document, pointing at `polypkg source add` /
  `polypkg init --source-name` with the correct name.
- The `pkg init` scaffold includes a `path` action, so the scaffolded package's
  command lands on `$PATH` once published and installed.
- The `init` profile scaffold documents the `attestation.policy` knob.
- `gc` reports swept extract directories: a text line when nonzero, and an
  `extract_dirs_removed` count in the JSON result and audit record.

- Declarative profile model: describe the desired set of packages in a profile
  file and run `plan`/`apply` to make the system match it.
- Immutable generations with `rollback` (anti-rollback enforced) and `gc`,
  including `generation pin`/`unpin` to exempt a generation from collection.
- Imperative convenience verbs (`install`, `remove`, `upgrade`, `search`,
  `info`) that edit the profile and apply.
- Inspection commands: `list`, `status` (drift and GC preview), and `plan`.
- User and system scopes backed by a content-store substrate.
- Multiple prioritized sources with per-package source pinning; each source is
  verified independently against its own trust root.
- Signed `polypkg-native` repositories with minisign-compatible Ed25519
  signatures and TOFU trust-root acquisition.
- Repository publishing via `polypkg repo` (init, add/remove, build, status,
  key management) with encrypted signing keys stored outside the published tree
  and incremental, serial-bumping rebuilds.
- Integration commands: `link`/`unlink` (bridge into `~/.local/bin`),
  `alternatives` arbitration, and shell `completion` (bash, fish, zsh,
  powershell).
- Maintenance commands: `config reset`, `accept-drift`, and `purge`.
- JSON output (`--format json`, `polypkg.cli-result/v2` envelope), `NO_COLOR`
  support, and the `POLYPKG_PROFILE` override.
- FIPS mode: runs clean under Go's FIPS 140-3 module (`GODEBUG=fips140=on`),
  with PBKDF2 key derivation available via `--kdf pbkdf2`.
- Continuous integration (test matrix, lint, govulncheck, CodeQL, scheduled
  fuzzing, and the shared MegaLinter policy), Dependabot dependency updates,
  and a GoReleaser release pipeline producing Cosign-signed checksums,
  per-archive Syft SBOMs, and GitHub SLSA build-provenance attestations.
- `go install github.com/trevor-vaughan/polypkg/cmd/polypkg@latest` support and
  build metadata (commit, date) in `polypkg --version`.

### Fixed

- Extracted package trees are now content-addressed
  (`pkg-extract/<name>-<version>+<hash16>`) and materialized by
  extract-to-temp plus atomic rename. Republishing different bytes under the
  same version can no longer rewrite the tree a retained or pinned generation
  resolves through, and an interrupted extraction can no longer leave a
  half-written directory behind.
- `gc` and every successful `apply` now sweep extracted-package directories no
  retained generation references (after a one-hour grace window that protects
  in-flight applies), closing an unbounded disk leak. Directories in the older
  pre-content-addressed layout are kept while a generation still references
  them, and the sweep skips entirely (fail-safe) if any retained generation's
  manifest cannot be read.
- A poisoned download-cache entry — an artifact or attestation whose cached
  bytes fail signature or digest verification — is evicted and refetched once
  instead of wedging the client on the stale bytes forever.
- `status` renders generation ages at their largest whole unit (42s / 8m / 3h
  / 2d); everything younger than 30 minutes previously showed as "0s ago".
- `polypkg generation <unknown>` now fails with an error and a hint instead of
  silently printing help and exiting 0.

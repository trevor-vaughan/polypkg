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
- `mirror pull --all-versions` mirrors every published version of an unpinned
  package instead of only the latest; an explicit `name@version` selector
  still wins.

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
- `polypkg source set-trust-root <name>` replaces the key a source is pinned
  to. It shows the pinned and new key ids, needs confirmation
  (`--trust-root-fingerprint <key id>`, or a prompt on a TTY), keeps the
  source's URL and order position, and clears the source's anti-rollback state
  so a repository rebuilt from scratch is accepted again. It also works on a
  single-source profile, where the previously documented recovery
  (`source remove` then `source add`) could not run because `remove` refuses
  the last source. For a repository re-created with the same key,
  `--reset-state` clears the anti-rollback state even though the key is
  unchanged; it requires `--trust-root-fingerprint`.
- `--trust-root-fingerprint <key id>` on `init` and `source add` confirms a
  `--trust-root-url` download without a prompt, and checks a local trust-root
  file when given. The key id is the one `polypkg repo key show` prints.
- Per-platform packages. A package version can be published once per
  platform, and a client downloads only the artifact for its own platform.
  A package's `polypkg.yaml` takes an optional `platform:` (`<os>/<arch>` in
  Go's `GOOS`/`GOARCH` names, such as `linux/amd64`), and a repository lists
  one source per platform under the same name.
  - `pkg lint` rule PKG011 refuses a `platform:` that is not an `<os>/<arch>`
    pair `go tool dist list` names.
  - `repo build` refuses a version that mixes an entry without a platform
    with entries that have one, and refuses two entries with the same version
    and platform.
  - Installing a package published only for other platforms is refused with
    a message that names them and this machine's platform.
  - `info` shows the platform it would install, the other platforms
    published for that version, and the installed package's platform.
    `search` marks versions not published for this machine. `list -v` adds a
    platform column, and `status -vv` tags per-platform packages in its
    package listing. `list --format json` carries each package's platform, as
    do the revoked-builder and revoked-attestation entries of `status`.
  - Each generation's manifest records the installed artifact's platform,
    shown by `list -v`, `status -vv`, `info`, and `--format json` output.
  - Packages without `platform:` work as before on every host. See
    [docs/authoring.md](docs/authoring.md) for when to prefer per-platform
    artifacts over one artifact that selects files with `!starlark`.

### Changed

- `gc` now also prunes the download cache (`cache/<source>/` in the state
  dir), which used to keep every package ever downloaded. Cached packages and
  attestations that no retained or pinned generation records are removed
  once they are more than an hour old (an attestation a generation used but
  did not record is downloaded and verified again by the next `plan`); the
  sweep after every successful `apply` does the same. Like the extract sweep,
  it keeps everything while a generation is damaged or the current one has no
  manifest. `gc` lists the extract dirs and cached files it removed (the first
  20 of each in text output), and `--format json` adds `extract_dirs_pruned`
  and `cache_artifacts_pruned` (every name) and `cache_artifacts_removed`
  (count) beside the existing `extract_dirs_removed`.
- `audit.log` rotates at 10 MiB to `audit.log.1`, keeping three old files, so
  the audit trail stays under about 40 MiB. A new `audit.log.lock` file in the
  state dir coordinates concurrent writers.
- `plan` no longer opens `audit.log`. It never wrote events there; it only
  created the file and needed write access to it.
- **Breaking:** `--trust-root-yes` is removed from `init` and `source add`. It
  trusted whatever key the URL served. Unattended runs now pass
  `--trust-root-fingerprint <key id>`, and the download is refused unless it
  matches.
- **Breaking:** `source add` refuses a name that is already in the profile
  (`source "<name>" already exists`). Change a trust root with
  `source set-trust-root`; change anything else with `source remove` then
  `source add`.
- **Breaking:** `mirror pull --source-name` must be a valid slug
  (`^[a-zA-Z0-9_-]+$`); see Security.
- `source add`, `source remove`, and `source set-trust-root` take the apply
  lock and stop at once, naming the holder, while another command holds it.
  An `apply` running alongside could otherwise store a source's old
  anti-rollback serials right after `set-trust-root` cleared them.
- **Breaking (`polypkg-repo.yaml`):** `packages:` maps each name to a *list* of
  entries, so one repository can publish several versions of a package:

  ```yaml
  packages:
      hello:
          - source: ./pkgs/hello-1.0.0
          - source: ./pkgs/hello-1.1.0
  ```

  Existing manifests need each entry turned into a one-item list. `repo add`
  appends a new source and updates a repeated one; `repo remove <name>` drops
  every version and `repo remove <name>@<version>` drops one. An exact client
  pin now stays resolvable after the publisher ships a newer version, which is
  what the README's held-back wording has always described.
- **Behaviour change:** the `install` action copies by default. An `install`
  that omits `policy` used to place a symlink into polypkg's extract cache
  (`$XDG_STATE_HOME/polypkg/pkg-extract/`). It now places a regular file inside
  the generation with the source's permission bits, so the generation no longer
  depends on the cache and drift detection hashes the file that actually runs.
  Each retained generation holds its own copy, so installed packages use more
  disk. Authors who want the old placement can set `policy: symlink`. The first
  `apply` after upgrading replaces each such symlink with a copy.
- **Behaviour change:** a package archive with an entry that passes through or
  replaces a symlink earlier in the same archive is now refused at extraction
  (for example a symlink `a -> c` followed by a file `a/b`, or a symlink `l`
  followed by a file `l`). Archives made by `pkg build` cannot contain these,
  because it refuses symlinks in `content/`. Extraction also gives every
  regular file owner-read and every directory owner read, write and search,
  whatever mode the archive records, so an extracted package can always be
  checked against its artifact.
- **Breaking (repository index):** repositories publish `polypkg.index/v3`,
  which adds a per-entry `platform`. Clients refuse a `polypkg.index/v2`
  index with a message asking its operator to rebuild it.
  - Artifact signatures now also sign the platform (`platform=<os>/<arch>`,
    or `platform=any`), and an artifact signed without it is refused.
  - Publishers run `polypkg repo build` once with this version. The build
    cache format changed (`polypkg.repo-cache/v4`), so that build repacks and
    re-signs every package.
  - A mirror can pull from an upstream only after the upstream has rebuilt.
- With several sources, the first source in `sources.order` that publishes a
  name for any platform owns it. A machine that source has no build for gets
  the "published for …" error and is not served by a lower-priority source
  unless the package is pinned to that source with `source:`. This keeps a
  public source from standing in for a private package (dependency
  confusion).
- `search --format json`: `versions` lists only versions installable on this
  machine, and the new `unavailable_versions` lists the ones published only
  for other platforms. `versions` can now be empty for a package that is
  still listed, so check it before installing.
- `info --format json`: for a package published only for other platforms,
  `note` carries the reason (`<name> <version> is published for …; this host
  is …`), `platform` is `""`, and `other_platforms` is non-empty. New fields
  `platform`, `other_platforms`, and `installed_platform` describe the
  candidate and installed builds.
- The downgrade guard's high-water marks are kept per host platform in each
  source's state file under `trust/`, so machines of different platforms
  sharing one state directory no longer refuse each other's older builds. An
  existing un-keyed record is adopted by the first host that fetches the
  source.
- `mirror pull` mirrors every platform. "Latest" is now the newest version
  per package and platform, with platform-agnostic builds as their own group.
  A `name@version` selector pulls every platform build of that version. A
  narrowing note for a platform build names the platform
  (`hello (linux/amd64): mirrored …`), and notes for platform-agnostic
  packages are unchanged. An upstream index that lists one name, version, and
  platform twice fails the pull. Each artifact is staged under
  `<name>/<version>/<platform>/` (`linux-amd64` style, or `any`).
- `repo remove <name>@<version>` withdraws every entry for that version,
  which means every platform build of it. When it removes anything other
  than a single platform-agnostic entry, the text output lists each removed
  entry and its platform under the usual line. `--format json` adds
  `data.removed` (`[{"entry": …, "platform": …}]`) whenever a version is
  given. To withdraw one platform, delete its entry from
  `polypkg-repo.yaml`.

### Fixed

- An older polypkg reading state a newer polypkg wrote now says so —
  `<path> was written by a newer polypkg (polypkg.ownership/v2; this version
  reads v1); upgrade polypkg` — instead of failing with a schema-validation
  dump. A generation manifest a newer polypkg wrote is not mistaken for a
  damaged one: `gc` removes nothing while it is present.
- A document fetched from a source that a newer polypkg wrote is now
  reported as written by a newer polypkg, instead of failing strict decoding
  on an unknown field. This covers the index, trust document, trust bundle,
  revocation list, and export-bundle pool manifest.
- An older polypkg treats a generation pinned by a newer polypkg as pinned, so
  its `gc` cannot collect it.
- Validation errors for polypkg's own files no longer print your working
  directory as a `file://` URL.
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
- A power loss right after `apply` no longer leaves polypkg unusable.
  Generation files were renamed into place and the `active` pointer was
  switched without any fsync, so on XFS, ZFS, APFS (or ext4 outside
  `auto_da_alloc`) `active` could point at an empty `ownership.json`, and
  every command then failed with `unmarshal for validation: EOF`. The
  generation's files and directories are now fsynced before the switch and the
  store root after it.
- A generation left behind by an interrupted `apply` (killed or powered off
  before it committed, so it has no manifest) is no longer kept forever or
  used as a rollback target. `gc` and the cleanup after each `apply` remove it
  regardless of `--age`. `rollback` skips it, `rollback --to` and
  `generation pin` refuse it, `status -v` marks it `[incomplete]`
  (`"incomplete": true` in `--format json`), and `attestation report` skips it
  and names it instead of failing.
- A generation whose manifest is present but damaged (it does not parse, or
  names another generation) is treated as possible corruption or tampering,
  not as a crash, which cannot cause it. `gc` never removes it and names it,
  with a hint to inspect it and delete it by hand if it is not needed as
  evidence (`"damaged"` in `--format json`). `rollback --to` and
  `generation pin` refuse it, the default `rollback` skips it with a warning,
  `status -v` marks it `[damaged]` (`"damaged": true`), `attestation report`
  fails naming it, and the store sweep keeps every extracted package and
  cached download while it exists.
- `rollback` now takes the same lock as `apply`. Without it, a concurrent
  `apply` could garbage-collect the generation being rolled back to and leave
  the `active` pointer dangling.

### Security

- A repository index can no longer name a package with a path. Package and
  relation names in a signed index were used unchecked, and a package name
  became part of the directory its artifact was extracted to. An index signed
  with a compromised or malicious publisher key could therefore name a
  package `../../somewhere`. Now the index schema and the catalog loader
  require every package and relation name to be a slug (`^[a-zA-Z0-9_-]+$`).
  An artifact whose own `polypkg.yaml` disagrees with its index entry on
  name, version, or platform is refused before any action runs.
- The `dir` and `perms` actions no longer apply a mode with group-write,
  other-write, setuid, setgid, or sticky bits. They passed any octal mode
  straight to `chmod`, which ignores the umask. A package declaring
  `mode: "0o777"` therefore left root-owned, world-writable paths under the
  system active tree that `/usr/local/bin` links to, and any local user could
  replace a binary that root later runs. A mode written above `0o7777`
  (`"0o40000755"`) set a real setuid bit while the recorded mode read `0755`,
  so `status` did not report it. A four-digit `"0o4755"` was silently dropped
  to `0755` instead. A mode may now use only the bits in `0755`. `apply`
  refuses anything else in every scope, before touching the filesystem, and
  names the path and mode. `pkg lint` reports the same modes as `PKG010`. A
  package that relied on a group-writable directory must drop that bit.
- A source server can no longer hang `plan`, `apply`, `mirror pull`, or any
  other command that fetches from it. Fetches had only a 30-second limit on
  response headers, so a server that sent headers and then dripped the body,
  or went silent, froze the command until it was killed. A fetch now fails
  once the body goes 60 seconds without a byte. Repository metadata (the
  index, trust document, trust bundle, revocation list, and every signature)
  must also arrive within 5 minutes in total, so a server cannot hold it open
  by sending one byte a minute. Package artifacts, which can be up to 2 GiB,
  have only the 60-second idle limit, so a slow but steady download still
  completes. The error names the URL and says the server stalled.
- An https source can no longer be redirected to plain http, matching the
  `--trust-root-url` download. A redirect that leaves https is refused before
  the http request is made. Redirects from https to https, including to
  another host such as a CDN, are still followed, up to 10 hops.
- Trust roots supplied as a local file are now pinned by content, not by path.
  `init --trust-root-file` and `source add --trust-root` recorded the path you
  gave them and re-read the anchor from it on every verification, so a key that
  lived anywhere the repository operator could write was not pinned at all: the
  same write that replaced the signed metadata replaced the key that metadata is
  checked against, and verification passed. Every piece of guidance we ship —
  the README quickstart included — pointed the flag at the repository's own
  published tree, where `repo init` leaves the operator's copy, so the exposed
  configuration was the documented one. Both flags now copy the key into
  `<config>/trust/<source>.pub` and record that copy, matching what
  `--trust-root-url` and the wizard's pasted-key route already did. Your own
  file is read once and never consulted again.

  Two consequences worth knowing: the profile written by `init` and `source add`
  now names a path under `<config>/trust/` rather than the one you passed, and
  two sources can no longer be made to share one managed key by pointing
  `--trust-root` at another source's anchor — each gets its own copy. Existing
  profiles are untouched; to pin an anchor that is currently a bare path, copy
  the key to `<config>/trust/<source>.pub` and point the source's `trust_root`
  at that copy.
- `source add` with an existing name silently replaced that source's pinned
  trust root, so one `source add` run after a repository compromise (following
  instructions the attacker published, say) made the next `upgrade` accept the
  attacker's key. The name is now refused before any key is read. Nothing but
  `source set-trust-root` overwrites a pinned key: `init` and `source add` also
  refuse to replace a different key already at `<config>/trust/<source>.pub`
  (for example one left behind after deleting `profile.yaml`) and name the
  file.
- `--trust-root-url` refuses plain `http://`, and an https download no longer
  follows a redirect to http. The downloaded key anchors every later signature
  check; over plain http anyone on the network path could substitute their own,
  and `--trust-root-yes` accepted it unseen.
- A source or trust-root URL carrying credentials (`https://user:password@host/...`
  or a bare token, `https://TOKEN@host/...`) no longer prints them in errors
  from `plan`, `apply`, `install`, `upgrade`, `mirror pull`, `init` or
  `source add`/`set-trust-root`. Errors show the URL with its whole user info
  replaced by `xxxxx`. A URL that does not parse, or that cannot be split into
  user info and host, is shown only as `<scheme>://<redacted>`.
- `mirror pull` now enforces anti-rollback serial floors against each upstream.
  It used to accept any validly signed, unexpired upstream document regardless
  of serial, and it treated a missing revocation list as "nothing revoked". A
  replayed older revocation list, or a 404 in place of the current one,
  silently dropped upstream revocations from the mirror and from every
  air-gapped site fed by it. The pull now records the serials of each
  upstream's trust document, index, trust bundle and revocation list under
  `<key-dir>/<repo-source>.mirror-state/`. A later pull refuses any of them at
  a lower serial, and refuses a trust bundle or revocation list that has
  disappeared after being seen. The records are written only after a fully
  successful pull, and a corrupt record stops the pull instead of resetting.
  `--source-name` must now be a valid slug. The upstream's signed documents
  already had to match it, so a working configuration is unaffected. If an
  upstream is legitimately re-created, see "Resetting after an upstream is
  re-created" in `docs/mirroring.md`.
- An edit to polypkg's extract cache could change an installed command without
  polypkg noticing. Installs that omitted `policy` were symlinks into
  `$XDG_STATE_HOME/polypkg/pkg-extract/`, which the user can write. Drift
  detection compared only the link's own `lstat`, so `status` reported no drift
  and `apply` kept the edited file. Three changes close this:
  - `install` copies by default (see Changed).
  - Drift detection re-hashes the target of every `policy: symlink` install on
    each check, and reports a dangling one as missing.
  - Every `plan` and `apply` checks each reused extract dir against the signed
    artifact and re-extracts one that was modified, logging a warning. An edited
    cache therefore can't be copied into a new generation or stay live behind a
    symlink.

# Container-based E2E tests

A functional test tier that drives the **actually-built `polypkg` binary**
through its whole lifecycle inside throwaway containers, across a
CentOS / Ubuntu / Alpine matrix. It complements — does not replace — the
in-process Ginkgo suite under `tests/integration/`.

## Why this exists (altitude)

`tests/integration/` calls cobra commands in-process against an `httptest`
server. That is fast and covers a lot, but it cannot exercise:

- the real built binary as a real process (real argv, real exit codes);
- a real privilege boundary — `--scope system` writing to genuine
  `/etc/polypkg`, `/var/lib/polypkg`, `/usr/local/bin` as real root;
- a real network fetch of a signed repo over HTTP;
- portability across glibc/musl and across Linux Security Modules.

This tier does. It already paid for itself once: it caught that
`init --scope system` wrote a `user`-scoped profile (fixed in
`internal/cli/inittemplate.go`).

## Run it

```bash
task test:integration                 # full matrix: centos, ubuntu, alpine
task integration:run DISTRO=centos    # one distro, end to end
task integration:run DISTRO=ubuntu
task integration:run DISTRO=alpine
```

A single `run` does: `down` (clean slate) → `lsm-report` → `build` →
`publish` → `up` (repo-server, health-waited) → `user` → `system` →
`down` (deferred). Individual phases are also callable:

```bash
task integration:build   DISTRO=centos
task integration:publish DISTRO=centos
task integration:up      DISTRO=centos
task integration:user    DISTRO=centos
task integration:system  DISTRO=centos
task integration:down    DISTRO=centos
```

Venom reports land in `.test-output/e2e/<distro>/<scope>/` (gitignored), one
subdir per scope — `publish/`, `user/`, `system/` — so a full `run` retains all
three sets of results instead of the last scope overwriting the prior ones.

## Host requirements

Rootless `podman` plus `podman-compose`. On a host whose kernel overlay driver
rejects `userxattr`, the image build stops with:

```
Error: mounting an overlay over build context directory: ... userxattr: invalid argument
```

Point podman at fuse-overlayfs to get past it — `~/.config/containers/storage.conf`:

```toml
[storage]
driver = "overlay"

[storage.options.overlay]
mount_program = "/usr/bin/fuse-overlayfs"
```

Confirm with `podman info | grep graphDriverName`.

`task integration:run` tears down before it builds, so on a machine that has
never run the suite the first thing you see is a run of `Error: no container
with name or ID "e2e_..._1" found` lines. That is the teardown finding nothing
to remove, not a failure.

## Topology

```
fixtures/  ─┐                       (bind-mounted, ro)
            ▼
  publisher ──repo init/add──►  repo-pub  ◄──serves /public over HTTP── repo-server
   (venom)                      (volume)            :8080                 (python http.server)
                                   ▲                                          │
                                   │ rw (republish in anti-rollback)          │ http://repo-server:8080
                                   │                                          ▼
                            runner-user (non-root)  ◄────────────────►  fetch + install
                            runner-system (real root → /etc,/var,/usr/local)
```

- `repo-pub` / `repo-keys` are named volumes (podman auto-relabels for
  SELinux). The signing key lives outside the served output, as the producer
  guard requires.
- The runner image is a multi-stage static (`CGO_ENABLED=0`) build of
  `polypkg` + `venom`; venom is installed before the source copy so its slow
  layer caches independently. The image is matrix-parameterized by
  `--build-arg BASE_IMAGE`; the builder stage is shared, so venom compiles once.
- `venom/` and `fixtures/` are **bind-mounted**, so editing a suite needs no
  image rebuild — only a `polypkg` source change does.

## Suite → verb coverage

| Suite | Verbs / behavior |
|-------|------------------|
| `publish/00-publish` | `repo init/add/status/key show`; layout (content-addressed `pool/`), serial, fingerprint |
| `publish/20-attestation-publish` | `.att.json`/`.minisig` pool blobs; v2 index with `attestations`/`expires`; republish persists the old blob and bumps `revision` |
| `publish/30-mirror-verify` | `repo export-bundle` → `mirror verify` (2e-2 offline-mirror surface); a post-export content byte-flip (hash mismatch) and a smuggled un-listed file are both refused, then the pristine bundle is proven to still verify |
| `user/10-user-lifecycle` | `init`(explicit trust) → `source list` → `search` → `info` → `install` → `list` → `status` → `upgrade` → `remove` → `rollback` |
| `user/15-user-tofu` | `init --trust-root-url` over `file://`: plain-http refusal, non-TTY refusal without a fingerprint, mismatched-fingerprint refusal, headless accept with `--trust-root-fingerprint` (key id from `repo key show`); `source set-trust-root`: unchanged key, mismatched-fingerprint refusal leaves the pin intact |
| `system/20-system-lifecycle` | the lifecycle `--scope system` as real root in FHS paths; auto-bridge of exposed commands into `/usr/local/bin`; system-scope init regression |
| `user/30-conflicts` | `alternatives list/set/auto` (via the `alternatives` action); hard-conflict rejection; `unlink`/`link` of a bridged command |
| `user/40-drift` | tamper a placed file → `status` drift → `apply --heal-drift`; `accept-drift` of a drifted config path |
| `user/50-anti-rollback` | `repo add`/`repo build` to bump serial, fetch; serve a stale lower-serial index → consumer rejects |
| `user/55-deps` | `install` resolves and pulls a declared `depends` |
| `user/58-extract` | the `extract` action: a package whose content is a `.tar.gz` (built at test time with the runner's `tar`) is published, linted clean, and installed; `strip_components: 1` drops the archive's top directory, the unpacked `bin/hello` is a regular executable file (not a link into the extract cache), the `path`-exposed command runs from `~/.local/bin`, and `rollback` removes both the unpacked tree and the command |
| `user/60-gc-pin` | `generation pin`, `gc --count`, pinned generation survives |
| `user/70-edge-cases` | missing package; unsatisfiable constraint; `plan` dry-run; `generation list` wart; idempotent install; `purge` (remove-then-purge, non-TTY abort); `config reset` |
| `user/80-attestation` | install verifies + records attestation (`info`/`status -vv`); tampered `.att.json` refused; `require` refuses / `warn` warns on an unattested (`--skip-attestations`) repo. Expired-metadata refusal is NOT here — D13's 5-minute skew tolerance makes it unobservable without sleeping out the window; it lives in `tests/integration/e2e_freshness_test.go` (full CLI, deterministic clock) |
| `user/85-downgrade` | withdrawal-only anti-downgrade: re-adding an older version withdraws the top → plan refused; exact pin accepts; repo restored |
| `user/96-mirror-pull` | `mirror pull` (2e-4 offline mirror): fetch an attested upstream over `file://` → re-publish under a local key → export + `mirror verify` a bundle → install from the mirror with upstream provenance preserved; `--fresh` re-anchor drops provenance so a downstream `policy: require` fails closed, while the same policy installs from the non-fresh mirror |
| `user/97-attestation-gate-off` | G8: a source with `attestation: tier: off` disables the gate — `apply` emits an unsuppressible `SECURITY` warning, records an `attestation.gate_off` audit event, and `status`/`info` surface `[attestation gate OFF]` |
| `user/98-provenance-genuine` | genuine carried-SLSA install (2f-4): a builder-signed attestation installs `builder-verified` when the builder key is allow-listed (`info`/`status -vv`); an empty allow-list still installs under source-governance trust (spec §10.7); **G4** a carried subject offering agreeing sha256+sha512 installs `builder-verified` (multi-algo "all-overlap-must-agree" accepted); **G6** a genuine offline sigstore bundle whose `SigstoreRoot` is published in the trust bundle installs `verified-offline` with recorded Fulcio identity under `require` |
| `user/99-provenance-adversarial` | the fail-closed carried-provenance acceptance matrix, one case per threat (spec §11): **G1** rogue builder key absent from `builders.allow` refused; **G2** carried SLSA stripped from a re-signed index refused under `require`; **G4** a carried subject with a mismatched second digest, an only-`sha1` (forbidden weak) digest, or an only-uncomputable-algorithm digest is hard-refused by the install-time digest re-bind; **G5** selection is by digest not advisory name — relabeled subject still binds the correct file, a digest matching nothing is refused; **G7** a post-publish content substitution that re-packs and re-signs the artifact and strips the anchor-signed native artifact-bindings (transport + index hash still verify) is hard-refused by the builder-signed carried attestation's install-time re-bind; **G6** a sigstore bundle with its transparency-log inclusion proof stripped fails closed to `verified-transport-only` — installs under DEFAULT (no identity) but refused under `require`; **G9** index `predicate_type` disagreeing with the signed payload hard-refused; **G10** duplicate-JSON-key DSSE downgrades to `verified-transport-only`, refused under `require` |

Every top-level verb from `internal/cli/root.go` is invoked by a suite, **except
`eval-starlark`** — a hidden internal self-re-exec (the starlark sandbox child),
not a user verb. It is exercised indirectly whenever a package runs a starlark
action, and is intentionally not tested as a command. `link`/`unlink` are
user-only (no `--scope`); the system equivalent is the automatic bridge during
`apply` (suite 20).

**Adding a verb?** Add a row here and a suite/case that actually invokes it with
a meaningful assertion (not just an exit-code check).

## Carried-provenance fixtures

The G1/G2/G4/G5/G6/G7/G9/G10 rows in `user/99-provenance-adversarial` need genuinely
signed, then selectively tampered, served-repo trees — a forging primitive is
not something a shipped test fixture should embed. Instead
`tests/e2e/provenancegen` (`go run ./tests/e2e/provenancegen -o <dir>`) is a
deterministic, host-run Go tool that reuses the real `internal/repo`/
`internal/attest` signing code with fixed keys to mint one served-repo tree
per variant into `<dir>/<variant>/public`, printing `variant=<name>
allow_key=<base64>` per line so a venom suite can copy the builder's
allow-listed key literal. Because it calls the same signing/verification code
production does, a fixture verifies — or is refused — for exactly the reason
production would; the tampering lives in the generator, never in the shipped
container image.

The `integration:provenance:fixtures` task (`.taskfiles/integration.yml`) runs
the generator into `.test-output/e2e/provenance-fixtures` (+`chmod -R a+rX`
for rootless-podman read access) as a pre-step before `compose up`;
`compose.yaml` mounts that directory read-only into `runner-user` at
`/e2e/provenance-fixtures`. The venom suites read each tree over
`file:///e2e/provenance-fixtures/<variant>/public`.

| Variant | Used by | Proves |
|---------|---------|--------|
| `genuine` | `user/98-provenance-genuine` | builder-signed carried SLSA installs `builder-verified`; also the empty-allow-list edge (spec §10.7) |
| `g1-rogue` | `user/99-provenance-adversarial` (G1) | a builder key registered in the trust bundle but absent from the consumer's `builders.allow` is refused |
| `g2-strip` | `user/99-provenance-adversarial` (G2) | carried SLSA stripped from a re-signed index is refused under `require:[slsa]` |
| `g4-multialgo` | `user/98-provenance-genuine` (G4) | a carried subject offering agreeing `sha256`+`sha512` binds and installs `builder-verified` (multi-algo "all-overlap-must-agree" positive) |
| `g4-mismatch` | `user/99-provenance-adversarial` (G4) | a carried subject whose `sha256` matches but whose `sha512` is the hash of different bytes is hard-refused (all overlapping algorithms must agree) |
| `g4-sha1only` | `user/99-provenance-adversarial` (G4) | a carried subject offering only the forbidden weak `sha1` is refused on presence |
| `g4-nooverlap` | `user/99-provenance-adversarial` (G4) | a carried subject offering only an uncomputable algorithm (`sha3-512`) has nothing at or above the `sha256` floor and is refused |
| `g5-relabel` | `user/99-provenance-adversarial` (G5) | selection is by digest, not the advisory subject name — install binds the digest-matched file, not the misleading label |
| `g5-mismatch` | `user/99-provenance-adversarial` (G5) | a carried subject digest matching no packed file is refused |
| `g6-sigstore-genuine` | `user/98-provenance-genuine` (G6) | a genuine offline sigstore bundle whose `SigstoreRoot` is published in the trust bundle verifies offline and installs `verified-offline` with recorded Fulcio identity under `require` |
| `g6-no-inclusion-proof` | `user/99-provenance-adversarial` (G6) | the same sigstore bundle with its transparency-log inclusion proof stripped fails closed to `verified-transport-only`: installs under DEFAULT (no identity), refused under `require` |
| `g7-install-refused` | `user/99-provenance-adversarial` (G7) | a post-publish content substitution — re-packed artifact + re-signed transport + stripped anchor-signed native artifact-bindings + retargeted, re-signed index — passes transport/integrity but is refused by the builder-signed carried attestation's install-time re-bind |
| `g9-predicate` | `user/99-provenance-adversarial` (G9) | an index `predicate_type` that disagrees with the signed payload is hard-refused |
| `g10-dupkeys` | `user/99-provenance-adversarial` (G10) | a duplicate-JSON-key DSSE envelope downgrades to `verified-transport-only`, refused under `require` |

G-numbers are the umbrella spec's §11 acceptance-matrix threat IDs.

## LSM scope — what the matrix proves, honestly

The matrix's always-true guarantee is **userland universality**: one static
binary runs correctly on glibc (CentOS, Ubuntu) and musl (Alpine), across
three base userlands.

LSM **enforcement** is a property of the *host*, not the image. `integration:run`
prints the host state up front (e.g.
`LSM: selinux=false apparmor=false rootless=true`). On a host where the LSM is
disabled — as on the current build host — the containers are not LSM-confined,
and rootless podman cannot load a new AppArmor profile regardless. The harness
is written to work *when* an LSM enforces (`:z` relabels, no LSM-specific
`security_opt`), but confirming real enforcement requires an enforcing host.
That is the job of the future VM tier (see the design spec). Read the
`LSM:` line in a run's log before claiming enforcement was exercised.

## Notes for the curious

- The repo is **rolling**: `repo add` is keyed by package name, so a repo
  serves one version per package. Suites install bare names (newest) and assert
  version-agnostically; the upgrade case (suite 10, which runs first) is the one
  place a specific `1.0.0 → 1.1.0` bump is checked.
- Suites isolate themselves with a distinct `HOME`/`XDG_*` sandbox (the `px`
  prefix var), so they are order-insensitive within a runner.
- The benign `pod_e2e already exists` / `container ... already in use` lines
  podman-compose prints while `run` re-ensures the long-running `repo-server`
  are warnings, not failures.

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
Requires rootless `podman` + `podman-compose`.

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
| `user/10-user-lifecycle` | `init`(explicit trust) → `source list` → `search` → `info` → `install` → `list` → `status` → `upgrade` → `remove` → `rollback` |
| `user/15-user-tofu` | `init --trust-root-url --trust-root-yes`; non-TTY refusal + headless accept |
| `system/20-system-lifecycle` | the lifecycle `--scope system` as real root in FHS paths; auto-bridge of exposed commands into `/usr/local/bin`; system-scope init regression |
| `user/30-conflicts` | `alternatives list/set/auto` (via the `alternatives` action); hard-conflict rejection; `unlink`/`link` of a bridged command |
| `user/40-drift` | tamper a placed file → `status` drift → `apply --heal-drift`; `accept-drift` of a drifted config path |
| `user/50-anti-rollback` | `repo add`/`repo build` to bump serial, fetch; serve a stale lower-serial index → consumer rejects |
| `user/55-deps` | `install` resolves and pulls a declared `depends` |
| `user/60-gc-pin` | `generation pin`, `gc --count`, pinned generation survives |
| `user/70-edge-cases` | missing package; unsatisfiable constraint; `plan` dry-run; `generation list` wart; idempotent install; `purge` (remove-then-purge, non-TTY abort); `config reset` |
| `user/80-attestation` | install verifies + records attestation (`info`/`status -vv`); tampered `.att.json` refused; `require` refuses / `warn` warns on an unattested (`--skip-attestations`) repo. Expired-metadata refusal is NOT here — D13's 5-minute skew tolerance makes it unobservable without sleeping out the window; it lives in `tests/integration/e2e_freshness_test.go` (full CLI, deterministic clock) |
| `user/85-downgrade` | withdrawal-only anti-downgrade: re-adding an older version withdraws the top → plan refused; exact pin accepts; repo restored |

Every top-level verb from `internal/cli/root.go` is invoked by a suite, **except
`eval-starlark`** — a hidden internal self-re-exec (the starlark sandbox child),
not a user verb. It is exercised indirectly whenever a package runs a starlark
action, and is intentionally not tested as a command. `link`/`unlink` are
user-only (no `--scope`); the system equivalent is the automatic bridge during
`apply` (suite 20).

**Adding a verb?** Add a row here and a suite/case that actually invokes it with
a meaningful assertion (not just an exit-code check).

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

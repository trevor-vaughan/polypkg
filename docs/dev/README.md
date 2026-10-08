# Developer documentation

Maintainer-facing notes on how polypkg is built. End users should start at the
top-level [README.md](../../README.md); contributors setting up a dev
environment should start at [CONTRIBUTING.md](../../CONTRIBUTING.md) (build,
test, and lint targets, the FIPS re-run of the suite, and PR conventions).

Read these before reworking a subsystem:

- **[Architecture](architecture.md)** — the apply pipeline end to end
  (`profile → planner (resolver) → runner → generation → integrators`), the CLI
  command tree, and a one-line map of every `internal/` package. Start here.
- **[Supply chain](supply-chain.md)** — the consumer half of trust: the signed wire
  formats, the per-package verification chain, the four carried-attestation
  tiers, freshness and anti-rollback, prebuilt ingest, and the mirror hop. Read
  it before touching `trust`, `attest`, `planner`, or `mirror`.
- **[Repo publisher](repo-publisher.md)** — design and internals of
  `polypkg repo`: on-disk format, trust model, encrypted key container,
  incremental build cache, expiry renewal, manifest edits, and FIPS posture.

## Test tiers

The test strategy spans three tiers, in increasing cost and fidelity:

- In-process Ginkgo suites under `tests/integration/`, entered through
  [`suite_test.go`](../../tests/integration/suite_test.go) and run by
  `task test`. Watch the names: `task test:integration` runs the container
  tier below, not this directory, and nothing named "integration" runs this
  one.
- **[Container E2E](../../tests/e2e/README.md)** — drives the real built binary
  through its full lifecycle in throwaway containers across a
  CentOS/Ubuntu/Alpine matrix (`task test:integration`). Needs rootless
  `podman` and `podman-compose`.
- **[VM LSM tier](../../tests/vm/README.md)** — opt-in QEMU guests that boot
  under an enforcing Linux Security Module (LSM: SELinux or AppArmor) and
  prove zero denials across a real lifecycle (`task test:vm`). Unless `rpm -q`
  already finds the QEMU toolchain, the run shells out to `sudo dnf install`,
  so it prompts for a password and assumes an RPM-based distro. On anything
  else, install `DEP_PKGS` from `.taskfiles/vm.yml` by hand first.

`task test` measures coverage across packages (`-coverpkg=./internal/...`), so
each `coverage: NN% of statements in ./internal/...` line it prints is the
share of *all* of `./internal/...` that one package's tests reach, not that
package's own coverage. Read coverage from the merged profile instead:
`go tool cover -func=.test-output/coverage.out` lists each function's coverage
and ends with the overall total.

## CI workflows

Each file in `.github/workflows/` and what it runs:

| Workflow | Trigger | Runs |
|----------|---------|------|
| `test` | push to `main`, PRs to `main`, called by `Release` | `task test` on Linux and macOS; `task test:fips`; `task build:cross` for freebsd/amd64, freebsd/arm64, linux/arm64 |
| `lint` | push to `main`, PRs to `main`, called by `Release` | golangci-lint |
| `integration` | push to `main`, PRs to `main`, called by `Release` | the container tier, one job per distro (`task integration:run DISTRO=…`) under rootless podman, on a runner pinned to `ubuntu-24.04` |
| `release-snapshot` | push to `main`, PRs to `main` | `goreleaser check`, then an unsigned `goreleaser release --snapshot` of every release archive and its SBOM |
| `security` | push to `main`, PRs to `main` | govulncheck (`task vuln`) and CodeQL |
| `MegaLinter` | push to `main`, every PR | the shared MegaLinter policy |
| `fuzz` | nightly, manual | the mutating fuzzer over every `Fuzz*` target in turn (`task fuzz:all FUZZTIME=180s`); failing inputs are uploaded as the `fuzz-failing-inputs` artifact |
| `Release` | a `v*` tag | `lint`, `test`, `integration` and govulncheck (`task vuln`) on the tagged commit, then, in the `release` environment and only if the tagged commit is on `main`, GoReleaser builds, signs, and publishes, and the archives, SBOMs and checksums get build provenance |

Why it is shaped this way:

- **The release re-runs the gates.** A tag can name any commit, not only
  one CI saw as a branch head, so `Release` calls `lint`, `test` and
  `integration` through `workflow_call`, runs `task vuln` in its own job,
  and its publish job `needs` all four. Only that job holds
  `contents: write` and `id-token: write`; the gates run with a read-only
  token. `Release` runs govulncheck itself rather than calling `security`,
  because CodeQL there needs `security-events: write`. The publish job also
  refuses a tagged commit that is not an ancestor of `origin/main`, so tag
  only after the change is merged.
- **Concurrency.** `test`, `lint`, `integration` and `release-snapshot`
  cancel a superseded run only on pull requests. Their concurrency groups
  are named after the workflow file rather than `github.workflow`, which
  inside `workflow_call` is the caller's name, so the gates `Release` calls
  never cancel each other. `Release` queues a second run for the same tag
  instead of cancelling one mid-publish.
- **The snapshot skips signing.** Keyless cosign needs the OIDC token only
  the tag-triggered release is granted. Everything else in
  `.goreleaser.yaml`, including the SBOMs, runs on every PR.
- **Platform coverage differs.** Linux runs every tier. macOS runs `task test`.
  FreeBSD and linux/arm64 are compiled and vetted (`build:cross`) and linked
  (the snapshot), but no runner executes them.
- **The container tier needs no TMPDIR override in CI.** A hosted runner's
  `/var/tmp` is not on overlayfs; the job logs `df -T` to keep that
  checkable. `podman-compose` is installed at a pinned version because the
  runner image does not ship it, and the runner image is pinned to
  `ubuntu-24.04` so the podman it supplies does not change unannounced.

### What the release gates do and do not protect against

The gates and the on-`main` check stop an honest mistake: tagging a commit
that fails CI, or one that never reached `main`. They do not stop someone
who can push a `v*` tag from publishing whatever they like, because the
tagged commit carries its own `release.yml` and can drop the gates. That
protection comes from repository settings, which the maintainer configures
on GitHub:

- **The `release` environment.** The publish job runs in it; GitHub creates
  it on the first run. Restrict its deployment tags to `v*`, and optionally
  add a required reviewer so every publish waits for approval.
- **A tag ruleset** on `v*` that limits who may create, update, or delete
  release tags.
- **Required status checks** on `main`'s branch protection, so nothing
  merges past a failing gate. Besides the existing checks, add `fips`,
  `cross (freebsd, amd64)`, `cross (freebsd, arm64)`, `cross (linux, arm64)`,
  `e2e (centos)`, `e2e (ubuntu)`, `e2e (alpine)` and `snapshot`.

## Fuzzing

Every `Fuzz*` test runs its seed corpus as an ordinary test under `task test`.
Mutation fuzzing is separate and opt-in: `task fuzz` fuzzes one target
(`FUZZTARGET` in `FUZZPKG`) for `FUZZTIME`. `task fuzz:all` finds every target
with `go test -list '^Fuzz' ./...` and fuzzes each in turn for `FUZZTIME`,
because `go test -fuzz` takes one target per run. It runs every target even
after one fails, then fails, naming them. The nightly `fuzz` workflow runs
`task fuzz:all FUZZTIME=180s` and, on failure, uploads the failing inputs
(`testdata/fuzz/` under each failing package) as the `fuzz-failing-inputs`
artifact. The upload matches every `testdata/fuzz/` directory, so the artifact
also carries the committed seed corpus in
`internal/archive/testdata/fuzz/FuzzExtractArchive/`; those files are not
failures.

`task fuzz` passes `-fuzzminimizetime=0` unless `FUZZMINIMIZETIME` says
otherwise, which turns off Go's minimization of new inputs. Under Go's default
of 60s the extraction targets stall within seconds: the log shows a few dozen to
a couple of thousand execs, then `0/sec` for the rest of the run. The parser
targets stall the same way later in a run. A corpus that earlier runs left in
the fuzz cache hides the stall, because few inputs then reach new coverage;
`go clean -fuzzcache` brings it back. `GODEBUG=fuzzdebug=1` shows the
cause. Each input that reaches new coverage is queued for minimization, and a
worker spends the full 60s on it. An extraction run creates a temp dir and
writes files (milliseconds per exec), and the byte-removal passes over a
several-KB tar have thousands of candidates, so the budget always runs out.
The first second of fuzzing finds more such inputs than there are workers, and
the coordinator counts executions only when a worker reports back, so every
worker is busy minimizing and the counter stops. With minimization off,
`FuzzExtractTar` ran about 215,000 execs in 60s on 4 workers; with the default
it ran 67.

The cost is that a failing input is saved as the fuzzer found it, not shrunk.
It still reproduces with `go test -run='<FuzzName>/<file>' <package>`. To get a
shrunk input, rerun with `FUZZMINIMIZETIME=60s` (or `Nx` for N runs) and accept
the slower search.

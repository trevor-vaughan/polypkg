# Developer documentation

Maintainer-facing notes on how polypkg is built. End users should start at the
top-level [README.md](../../README.md); contributors setting up a dev
environment should start at [CONTRIBUTING.md](../../CONTRIBUTING.md) (build,
test, and lint targets, the FIPS re-run of the suite, and PR conventions).

Read these before reworking a subsystem:

- **[Architecture](architecture.md)** — the apply pipeline end to end
  (`profile → planner (resolver) → runner → generation → integrators`), the CLI
  command tree, and a one-line map of every `internal/` package. Start here.
- **[Supply chain](supply-chain.md)** — the consumer half of trust: the v2 wire
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

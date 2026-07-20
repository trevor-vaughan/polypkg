# Developer documentation

Maintainer-facing notes on how polypkg is built. End users should start at the
top-level [README.md](../../README.md); contributors setting up a dev
environment should start at [CONTRIBUTING.md](../../CONTRIBUTING.md) (build,
test, and lint targets, the FIPS tier, and PR conventions).

Read these before reworking a subsystem:

- **[Architecture](architecture.md)** — the apply pipeline end to end
  (`profile → planner (resolver) → runner → generation → integrators`) and a
  one-line map of every `internal/` package. Start here.
- **[Repo publisher](repo-publisher.md)** — design and internals of
  `polypkg repo`: on-disk format, trust model, encrypted key container,
  incremental build cache, and FIPS posture.

## Test tiers

The test strategy spans three tiers, in increasing cost and fidelity. Each has
its own reference:

- In-process Ginkgo suites under `tests/integration/` (run by `task test`).
- **[Container E2E](../../tests/e2e/README.md)** — drives the real built binary
  through its full lifecycle in throwaway containers across a
  CentOS/Ubuntu/Alpine matrix (`task test:integration`).
- **[VM LSM tier](../../tests/vm/README.md)** — opt-in QEMU guests that prove
  zero LSM denials under enforcing SELinux/AppArmor (`task test:vm`).

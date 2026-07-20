# Security Policy

`polypkg` installs software and verifies the authenticity of what it installs.
Its security posture is therefore part of its core contract, and vulnerability
reports are taken seriously.

> **Experimental project.** polypkg is a personal experiment (see the README).
> It has not been independently audited. Do not rely on it as the sole control
> protecting a production system, and treat the guarantees below as
> best-effort rather than warranted.

## Supported versions

Only the latest released version (the tip of `main`) receives security fixes.
There are no long-term support branches. If you are running an older build,
upgrade before reporting.

| Version        | Supported          |
|----------------|--------------------|
| latest `main`  | :white_check_mark: |
| anything older | :x:                |

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report it through **GitHub's private vulnerability reporting** tool:

> **[Report a vulnerability →](https://github.com/trevor-vaughan/polypkg/security/advisories/new)**

You can also reach it from the repository's **Security** tab → **Report a
vulnerability**. This opens a private security advisory visible only to you and
the maintainers, where the fix can be discussed and coordinated.

Please include:

- The version or commit (`polypkg --version`) and the OS/distribution.
- A description of the issue and its impact.
- Reproduction steps or a proof of concept, if you have one.
- Any suggested remediation.

### What to expect

This is a hobby project maintained on a best-effort basis, so timelines are
targets, not guarantees:

- **Acknowledgement** within 7 days.
- **Initial assessment** (severity, whether it reproduces) within 30 days.
- Coordinated disclosure once a fix is available. Reporters are credited in the
  release notes unless they ask to remain anonymous.

Please allow a reasonable window for a fix before any public disclosure.

## Scope

Security-relevant areas include, but are not limited to:

- **Signature verification and trust** — bypassing minisign signature checks,
  trust-root confusion between sources, TOFU acceptance flaws, or accepting an
  artifact under a key other than the one belonging to its source.
- **Anti-rollback / replay** — accepting a repository index or trust document
  with a lower serial than one already trusted.
- **Artifact handling** — path traversal, symlink, or decompression-bomb issues
  when extracting packages (`tar`/`zstd`).
- **Privilege and isolation** — system-scope operations writing outside their
  declared substrate, or escaping the intended install root.
- **Key material** — leakage of repository signing keys or their passwords
  (e.g. keys written into the published directory, or a password exposed on a
  command line).

### Out of scope

- Vulnerabilities in upstream packages served by a repository (report those to
  the package or repository operator).
- Attacks that require a trust root the user explicitly and knowingly installed
  for a hostile source — distributing a trusted key is the operator's
  responsibility.
- Denial of service from a repository the user has chosen to trust.

## Cryptography notes

polypkg uses Ed25519 signatures (minisign-compatible) and supports running
under Go's FIPS 140-3 validated module (`GODEBUG=fips140=on`, `task test:fips`).
Repository signing keys are generated encrypted and stored outside the
published directory. See the README's *Publishing a repository* section for the
trust model.

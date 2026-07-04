# Contributing to polypkg

Thanks for your interest in polypkg. It's an experiment (see the README), and
rocks thrown at it — bug reports, fixes, and ideas — are welcome.

By participating you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md).

> LLM-assisted/driven contributions _ARE WELCOME_.
>
> Repeated spurious submissions of unfounded bugs or poorly tested code will result in a ban from contributing to the project.

## Ground rules

- **Discuss large changes first.** For anything beyond a bug fix or small
  improvement, open an issue describing the problem before writing code, so we
  can agree on the approach.
- **Security issues do not go in the public tracker.** Follow the
  [Security Policy](SECURITY.md) instead.
- **Keep changes focused.** One logical change per pull request. Avoid drive-by
  reformatting of unrelated code.

## Development setup

polypkg builds with **Go 1.26+** and uses [Task](https://taskfile.dev) as its
task runner. Run `task --list` to see every target.

```
task build            # compile to bin/polypkg
task test             # unit + in-process integration tests, with the race detector
task test:fips        # the same suite under Go's FIPS 140-3 module (GODEBUG=fips140=on)
task lint             # golangci-lint across all packages
task fmt              # gofmt all packages
task vuln             # scan dependencies with govulncheck
task check            # lint + test together (the gate CI enforces)
```

Heavier, opt-in tiers (not part of `task check`):

```
task test:integration # container-based E2E across centos/ubuntu/alpine (needs rootless podman)
task test:vm          # VM-based LSM-enforcement tier under QEMU (needs qemu)
task fuzz             # mutating fuzzer (vars FUZZTARGET, FUZZTIME, FUZZPKG)
```

See `tests/e2e/README.md` and `tests/vm/README.md` for what those tiers cover.

## Before you open a pull request

1. `task fmt` — code is gofmt-clean.
2. `task check` — lint and the full race-enabled test suite pass.
3. New behavior has tests, including negative and edge cases. Bug fixes come
   with a regression test that fails before the fix and passes after.
4. User-facing changes update the README and any affected docs. Notable changes
   get a `CHANGELOG.md` entry under the `Unreleased` heading.

Test artifacts belong in `.test-output/` (gitignored); don't commit them.

## Commit and pull request conventions

- Write commit subjects in the imperative mood, 72 characters or less
  (`fix: reject trust root with mismatched name`). The body explains *why*, not
  *what*.
- **Sign off your commits** with the [Developer Certificate of Origin][dco]:
  `git commit -s`. This adds a `Signed-off-by` line certifying you have the
  right to submit the change under the project's license.
- Rebase on the current `main` and keep history readable; squash fixup commits
  before review.

## Architecture and design

Architecture notes and design decisions live in `docs/dev/`. Read the relevant
notes there before reworking a subsystem.

## Licensing of contributions

polypkg is licensed under the **GNU General Public License v3.0** (see
[LICENSE](LICENSE)). By contributing, you agree that your contributions are
licensed under the same terms.

[dco]: https://developercertificate.org/

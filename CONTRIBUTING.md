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

polypkg builds with **Go 1.26.6 or newer** and uses [Task](https://taskfile.dev)
as its task runner. Run `task --list` to see every target.

`go.mod` says `go 1.26.6` — a patch-level floor, not a minor-level one. Most
people never notice it. Go's own default is `GOTOOLCHAIN=auto`, which downloads
the named toolchain on demand, so an older `go` on your `$PATH` still builds the
tree.

You will notice it if your toolchain is pinned to `local`, which some
distribution packages do (`/usr/lib/golang/go.env` on RHEL-family systems sets
`GOTOOLCHAIN=local`). Then the build refuses rather than fetching:

```
$ go build ./cmd/polypkg
go: go.mod requires go >= 1.26.6 (running go 1.26.5; GOTOOLCHAIN=local)
```

Either install 1.26.6+ or set `GOTOOLCHAIN=go1.26.6` for the build.

The floor is a security one, not a language-feature one. Go 1.26.5 ships four
standard-library vulnerabilities that `task vuln` reports as *called* by this
code, not merely present in it. The one that decides the floor is GO-2026-5972,
unbounded recursion in `encoding/asn1`, which govulncheck traces straight
through signature verification:

```
Vulnerability #3: GO-2026-5972
    Enforce maximum recursion depth in encoding/asn1
    Found in: encoding/asn1@go1.26.5
    Fixed in: encoding/asn1@go1.26.6
      #2: internal/attest/sigstore.go:162:26: attest.VerifySignedEntity calls verify.Verifier.Verify, which eventually calls asn1.UnmarshalWithParams
```

The other three reach `net/url` through schema validation and `crypto/tls` and
`net/http` through the source fetch. On 1.26.6 the same scan reports no
vulnerabilities, so the floor is a hard `go` directive rather than a
`toolchain` hint a build can ignore.

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
task test:integration # container-based E2E across centos/ubuntu/alpine
task test:vm          # VM-based LSM-enforcement tier under QEMU
task fuzz             # mutating fuzzer (vars FUZZTARGET, FUZZTIME, FUZZPKG)
```

Both container and VM tiers need host setup that `task check` does not:

- `test:integration` needs rootless `podman` **and** `podman-compose`. Where the
  kernel's native overlay rejects `userxattr`, the image build fails with
  `mounting an overlay over build context directory ... invalid argument`; write
  `~/.config/containers/storage.conf` with `[storage] driver="overlay"` and
  `[storage.options.overlay] mount_program="/usr/bin/fuse-overlayfs"` to get past
  it.
- `test:vm` needs more than QEMU: `vm:deps` installs the whole `DEP_PKGS` set
  from `.taskfiles/vm.yml` (`qemu-kvm-core qemu-img xorriso edk2-ovmf
  openssh-clients selinux-policy-devel checkpolicy`) via `sudo dnf`, so it
  prompts for a password and assumes an RPM-based distro. Elsewhere, install
  that set by hand first — `vm:deps`'s `rpm -q` guard cannot pass, so every run
  falls through to `dnf` and fails.

See `tests/e2e/README.md` and `tests/vm/README.md` for what those tiers cover.

## Recorded demos

The GIFs in `docs/demo/` are stored in **Git LFS**. Run `git lfs install` once
before cloning or pulling. Without it those paths arrive as ~130-byte pointer
files and the images in the README render broken — with no error to tell you
why.

Each GIF is rendered from a committed VHS tape in `.taskfiles/demo/`:

```
task demo:all                        # re-render all six
task demo:render SCENARIO=quickstart # just one
```

Rendering needs `vhs`, `ttyd`, and `ffmpeg` on `PATH`. Install `vhs` with
`go install github.com/charmbracelet/vhs@latest`; `ttyd` and `ffmpeg` come from
your package manager.

`.taskfiles/scripts/demo.sh` builds each recording's sandbox: a throwaway signed
`file://` repository under `mktemp -d`, with `HOME` and all four `XDG_*`
directories redirected into it. A render therefore cannot read or write your
real profile or generation store, and never touches the working tree.

Two rules for changing a tape:

- **Never stage output.** Run the sequence by hand against a freshly built
  binary first, and script only what you actually saw. A recording that shows
  output polypkg does not produce is worse than no recording.
- **Re-check the payoff frame.** Every tape exists to put one specific line on
  screen — `[verified]`, a drift count, a refused signature. After re-rendering,
  confirm that line is still visible before committing the GIF.

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

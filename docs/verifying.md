# Verifying a release

> How to check that a polypkg release archive is the artifact this project's
> release workflow built, and that nobody altered it in transit.

Work through the four steps in order. Order matters — step 4 is meaningless
unless step 3 passed first. See [What each check proves](#what-each-check-proves).

## Before you start

You need:

- **`gh`** (GitHub CLI) **2.51.0 or newer**, and authenticated. The
  `gh attestation` command set landed in 2.49.0, but `--signer-workflow` —
  recommended in [step 2](#2-verify-the-build-provenance) — only arrived in
  2.51.0; on 2.49.0 or 2.50.0 it fails with `unknown flag: --signer-workflow`.
  `gh attestation verify` queries the GitHub API, so run `gh auth login` first
  if you have not.
- **`cosign`**. Install it from
  [sigstore/cosign](https://github.com/sigstore/cosign) — the release workflow
  uses the same tool to produce the signature.
- **A SHA-256 checker.** `sha256sum` on Linux, `shasum` on macOS. FreeBSD ships
  `sha256sum` too, but it only learned GNU long options in 14.0 —
  [step 4](#4-check-the-archive-against-the-verified-manifest) has a form that
  works on 13.x as well.
- **Network access.** `gh` talks to the GitHub API; `cosign` fetches Sigstore
  trust-root material to validate the signing certificate.

Throughout, the worked example is tag `v1.2.0` on `linux/amd64`.

Note the filename: GoReleaser's `.Version` strips the leading `v`, so tag
`v1.2.0` produces `polypkg_1.2.0_linux_amd64.tar.gz` — not `polypkg_v1.2.0_...`.
Substitute your own tag, OS (`linux`, `darwin`, `freebsd`) and arch
(`amd64`, `arm64`).

## 1. Download the release files

Three files are needed, not one. The archive alone cannot be verified.

```
gh release download v1.2.0 \
  --repo trevor-vaughan/polypkg \
  --pattern 'polypkg_1.2.0_linux_amd64.tar.gz' \
  --pattern 'checksums.txt' \
  --pattern 'checksums.txt.sigstore.json'
```

Or grab the same three from the release page at
<https://github.com/trevor-vaughan/polypkg/releases>.

## 2. Verify the build provenance

The release workflow attests each archive with
[SLSA](https://slsa.dev) (Supply-chain Levels for Software Artifacts)
build provenance, predicate type `https://slsa.dev/provenance/v1`. The
attestation is a signed statement binding the artifact's SHA-256 digest to the
repository, the workflow file, the commit, and the Actions run that produced it.
It answers "where did these bytes come from", which a checksum cannot.

```
gh attestation verify polypkg_1.2.0_linux_amd64.tar.gz --repo trevor-vaughan/polypkg
```

A pass looks like this. gh always prints a policy block between the loaded
attestation and the verdict — one dotted line per criterion, derived from the
flags you passed — which is elided here:

```
Loaded digest sha256:0982d8720a59d0559ddc2826c9048164183e2e86da300361805c505e6e603c8d for file://polypkg_1.2.0_linux_amd64.tar.gz
Loaded 1 attestation from GitHub API

The following policy criteria will be enforced:
[predicate type, source repository owner URI, subject alternative name, OIDC
issuer, and whatever else your flags imply — one line each]

✓ Verification succeeded!
```

The decisive line is `✓ Verification succeeded!`, with exit status `0`. Anything
else — `no attestations found`, a certificate-identity mismatch, a non-zero exit
— means **do not install the archive**.

`--repo` pins the identity to this repository but not to a particular workflow
within it. To also pin the signing workflow, add
`--signer-workflow trevor-vaughan/polypkg/.github/workflows/release.yml`
(gh 2.51.0 or newer).

## 3. Verify the signature over the checksum manifest

`checksums.txt` is signed with a keyless Cosign signature. The signing
certificate is issued by Fulcio against the GitHub Actions OIDC identity of the
release job, so verification checks *who* signed rather than *which key* signed.
The identity pattern is anchored at both ends and accepts only this
repository's `release.yml` workflow running for a version tag, not any other
workflow or branch in the repository.

```
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/trevor-vaughan/polypkg/\.github/workflows/release\.yml@refs/tags/v[^/]+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

A pass prints, on stderr:

```
Verified OK
```

Exit status `0` and the line `Verified OK` together mean the manifest is
authentic. A non-zero exit — `no matching signatures`, an expired or mismatched
certificate — means **stop; do not proceed to step 4**.

> **Bundle format.** The release signs with `cosign sign-blob
> --new-bundle-format`, so `checksums.txt.sigstore.json` is a Sigstore protobuf
> bundle rather than cosign's legacy bundle JSON. That is the interoperable
> format — the one other Sigstore verifiers such as `sigstore-python` and
> `sigstore-go` are built to read, which is the point of using it. This document
> covers the cosign path only. The release signs with cosign v3.0.6, and the
> command above is written for cosign v3, which reads this format by default:
> `--new-bundle-format` is not needed when verifying.

## 4. Check the archive against the verified manifest

Only now does the checksum mean anything. The manifest lists twelve files — six
os/arch archives plus their six SBOMs — and you downloaded one of them, so use
`--ignore-missing`.

Note what the manifest does *not* list: `checksums.txt` itself and its signature
`checksums.txt.sigstore.json`. Both are published release assets, but they are
the subject and the proof of step 3, not entries in the manifest.

```
# Linux (GNU coreutils), FreeBSD 14.0 and newer
sha256sum --ignore-missing -c checksums.txt

# macOS
shasum -a 256 --ignore-missing -c checksums.txt
```

A pass — one `OK` line per file you actually have, and exit status `0`:

```
polypkg_1.2.0_linux_amd64.tar.gz: OK
```

A tampered archive looks like this, with exit status `1`:

```
polypkg_1.2.0_linux_amd64.tar.gz: FAILED
sha256sum: WARNING: 1 computed checksum did NOT match
```

Under `shasum` the per-file lines are byte-identical; only the summary carries
the program name, so on macOS that last line reads
`shasum: WARNING: 1 computed checksum did NOT match`.

**Do not install on any non-zero exit.**

### FreeBSD 13 and older

FreeBSD's `sha256sum` is a link to `md5(1)`, and GNU long options only reached
it in 14.0. On 13.x the option string is parsed by plain `getopt`, so nothing
beginning `--` is recognized at all: `--ignore-missing` gets you an illegal-option
error and a usage line, not a verification.

Filter the manifest down to your own file instead, then check that. The
`-c <file>` form works on every FreeBSD release, and on Linux too:

```
grep ' polypkg_1.2.0_freebsd_amd64.tar.gz$' checksums.txt > mine.txt
sha256sum -c mine.txt
```

The trailing `$` matters: without it the pattern also matches the SBOM line,
which names a file you may not have downloaded.

### Why `--ignore-missing`

Without it, every file listed in the manifest that you did not download is
reported as `FAILED open or read`, and the command exits `1` even though your
archive is intact — a real pass looks like a failure. GNU coreutils also writes
one `No such file or directory` line to stderr per missing file; `shasum` does
not. Interleaved as a terminal would show them, and abbreviated with `...`:

```
sha256sum: polypkg_1.2.0_darwin_amd64.tar.gz: No such file or directory
polypkg_1.2.0_darwin_amd64.tar.gz: FAILED open or read
sha256sum: polypkg_1.2.0_darwin_amd64.tar.gz.sbom.json: No such file or directory
polypkg_1.2.0_darwin_amd64.tar.gz.sbom.json: FAILED open or read
...
polypkg_1.2.0_linux_amd64.tar.gz: OK
sha256sum: polypkg_1.2.0_linux_amd64.tar.gz.sbom.json: No such file or directory
polypkg_1.2.0_linux_amd64.tar.gz.sbom.json: FAILED open or read
...
sha256sum: WARNING: 11 listed files could not be read
```

## What each check proves

**Running step 4 on its own verifies nothing.** `checksums.txt` is an ordinary
text file published beside the archive. An attacker who can replace the archive
can replace the manifest to match it, and `sha256sum -c` will happily report
`OK`. The manifest is only trustworthy because step 3 proved it was signed by
this project's release workflow.

That is the chain:

- Step 3 binds `checksums.txt` to the release workflow's signing identity.
- `checksums.txt` binds the archive bytes to that manifest.
- Step 4 binds the file on your disk to those bytes.

Break the chain — skip step 3, or run step 4 against a manifest you never
verified — and the remaining steps prove only that two files you downloaded from
the same place agree with each other.

Step 2 is a separate, stronger claim about origin: these bytes were built by
this workflow, from this commit, in this repository.

### Coverage

| Artifact | Build provenance (step 2) | Cosign signature (step 3) |
| --- | --- | --- |
| `polypkg_*.tar.gz` | yes | indirectly, via `checksums.txt` |
| `checksums.txt` | yes | yes |
| `*.sbom.json` | yes | indirectly, via `checksums.txt` |

### Limits worth knowing

These two attestations are not independent roots of trust. Both are minted by
the same job in `.github/workflows/release.yml`, under the same GitHub Actions
OIDC identity. Each catches a different class of tampering after the fact —
neither is a second opinion on the other, and a compromise of that workflow run
would produce both.

## Software bill of materials

Each release also ships a per-archive SPDX-JSON SBOM generated by
[Syft](https://github.com/anchore/syft), named after the archive it describes:

```
polypkg_1.2.0_linux_amd64.tar.gz.sbom.json
```

SBOMs get the same coverage as the archives. They carry their own build
provenance, and they are listed in `checksums.txt`, so the signed manifest binds
their bytes too:

```
gh release download v1.2.0 \
  --repo trevor-vaughan/polypkg \
  --pattern 'polypkg_1.2.0_linux_amd64.tar.gz.sbom.json'

gh attestation verify polypkg_1.2.0_linux_amd64.tar.gz.sbom.json --repo trevor-vaughan/polypkg
```

If you already ran steps 3 and 4, re-running step 4 with the SBOM present picks
it up as well — no separate manifest is involved.

Once verified, inspect one:

```
# list packages
jq -r '.packages[] | "\(.name) \(.versionInfo)"' polypkg_1.2.0_linux_amd64.tar.gz.sbom.json

# scan for known vulnerabilities
grype sbom:./polypkg_1.2.0_linux_amd64.tar.gz.sbom.json
```

# Verifying a release

> How to verify the supply-chain attestations on a published polypkg release archive.

Release archives published on GitHub carry three independent supply-chain attestations.

GitHub build provenance (SLSA), checked with the GitHub CLI:

```
gh attestation verify polypkg_<version>_<os>_<arch>.tar.gz --repo trevor-vaughan/polypkg
```

A Cosign keyless signature over the checksum manifest (a Sigstore bundle):

```
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp 'https://github.com/trevor-vaughan/polypkg/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

Then confirm the downloaded archive against the verified manifest:

```
sha256sum -c checksums.txt
```

Each release also ships a per-archive Syft SBOM (`*.tar.gz.sbom.json`).

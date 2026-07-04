# repo publisher: design and internals

`polypkg repo` is the producer counterpart to the consumer's fetch/verify path.
This document describes the on-disk format, the trust model, the key container,
the incremental build system, and the FIPS posture. It is aimed at maintainers
who need to understand or modify the publisher code, not users of the CLI.

Package layout: `internal/repo/` (signer, keystore, pack, cache, build/Builder +
Inspector, scaffold, manifest\_edit) and `internal/cli/repo*.go` (thin command
wrappers).

---

## On-disk repository layout

After a successful `repo build`, the published directory (`output`, default
`./public`) contains:

```
public/
  trust_root.pub          # minisign Ed25519 public key (distributed to clients)
  trust.json              # polypkg.trust/v2 JSON document (serial, expires, key roles)
  trust.json.minisig      # detached minisig over trust.json
  index.json              # polypkg.index/v2 JSON document (expires, pool refs, attestations)
  index.json.minisig      # detached minisig over index.json
  pool/
    <blake3>.tar.zst           # content-addressed packed artifact (zstd tar)
    <blake3>.tar.zst.minisig   # detached minisig over the artifact
    <blake3>.att.json          # signed in-toto lint attestation (canonical JSON)
    <blake3>.att.json.minisig  # detached minisig over the attestation
```

Pool blobs are named by the BLAKE3 hash of their own bytes (D10). Republishing
a changed build of the same version writes a NEW blob and repoints the index;
old blobs persist immutably so previously signed indexes (and consumer
rollbacks) keep resolving. The index entry's `revision` field is an
informational ordinal counting republishes of one version; it derives from the
build cache, floored against the published index, so a lost cache continues
the published ordinal instead of resetting to 1 (`content_hash` is the
disambiguator, not `revision`). The pool grows
monotonically until pool GC lands (future work). Blobs and their signatures
are always written before the index/trust metadata that references them, so a
published index never points at a missing blob.

### Signature format

Signatures use minisign's legacy `Ed` format: pure Ed25519 over the raw bytes of
the signed payload (no prehash). A `.minisig` file has four lines:

```
untrusted comment: <human label>
<base64("Ed" + keyID[8] + sig[64])>
trusted comment: <binding metadata>
<base64(globalSig[64])>
```

The *global signature* covers `sig[:] || trustedComment` (no prefix), preventing
the trusted comment from being swapped post-hoc. This matches what
[go-minisign](https://pkg.go.dev/github.com/jedisct1/go-minisign) verifies.
Public keys and signatures produced here verify with the stock `minisign` CLI.

**Trusted-comment bindings:**

| File | Trusted comment |
|---|---|
| artifact | `name=<name> version=<ver> hash=blake3:<hex>` (hash of the artifact bytes) |
| attestation | `name=<name> version=<ver> hash=blake3:<hex>` (hash of the `.att.json` bytes) |
| `index.json` | `serial=<N> ts=1970-01-01T00:00:00Z` |
| `trust.json` | `serial=<N>` |

The content hash in the artifact trusted comment is `blake3:` followed by the
lowercase hex of a 32-byte BLAKE3 digest (`lukechampine.com/blake3`). The
consumer verifies this hash before using the artifact.

The build timestamp is fixed to `1970-01-01T00:00:00Z` (not wall time), making
repeated no-op builds byte-identical. The monotonic serial provides ordering
for consumers instead.

---

## Trust model

The trust chain is self-anchoring with a single key:

1. `trust_root.pub` is the minisign public key file given to clients at setup time.
2. `trust.json` (schema `polypkg.trust/v2`) lists the active signing key with
   roles `["index", "artifact", "attestation"]`. It carries a monotonic
   `serial`, an `issued_at` timestamp (fixed to the epoch, informational), and
   an `expires` freshness bound shared with the index.
3. `trust.json.minisig` is signed by the **same key** that is listed inside the
   document — the key self-certifies. The consumer verifies the signature using
   the trust root they already hold.

This is a valid minimal trust chain: the consumer already trusts the public key
(out-of-band), so the trust document's purpose is to enumerate roles, enable
key rotation, and carry the serial that gates replay attacks. A compromised
index, artifact, or attestation cannot be injected without also possessing the
private key, and the `expires` bound closes the freeze attack: a mirror cannot
pin clients to a stale-but-validly-signed serial past the validity window
(consumers apply a 5-minute clock-skew tolerance).

The `attestation` role separates concerns for a future split-key setup: a
signing key that deliberately lacks the role publishes with
`--skip-attestations`, and consumers treat those packages per their
`attestation.policy` (absent ≠ invalid; a present-but-invalid attestation is
always fatal on the consumer side).

Key structure (`internal/repo/signer.go`, `Keypair`):

- `keyID`: 8 random bytes, hex-encoded in the key file and trusted comments.
- `pub`: 32-byte Ed25519 public key.
- `PublicKeyBase64()`: `base64("Ed" + keyID[8] + pub[32])` — the form stored in
  `trust_root.pub` and `trust.json.keys[].pubkey`.

---

## Encrypted key container (`polypkg.repo-key/v1`)

Signing keys are never stored in plaintext. The container format is a JSON file:

```json
{
  "schema": "polypkg.repo-key/v1",
  "kdf": "scrypt",
  "salt": "<base64>",
  "n": 65536, "r": 8, "p": 1,
  "key_id": "<16 hex chars>",
  "nonce": "<base64>",
  "ciphertext": "<base64>"
}
```

- **Encryption**: AES-256-GCM over the 32-byte Ed25519 seed.
- **KDF** (selectable at `repo init --kdf`):
  - `scrypt` (default): N=65536, r=8, p=1 — interactive-grade cost.
  - `pbkdf2`: PBKDF2-SHA256 with 600 000 iterations — FIPS 140-3 approved.
- **Additional data (AAD)**: the raw 8-byte key ID is passed as GCM AAD, binding
  the ciphertext to the key ID in the file header. Tampering the `key_id` field
  causes authentication failure.
- **File permissions**: 0600. Written via temp-file + rename (atomic).

The scrypt N field is capped at `1<<20` on load to prevent memory exhaustion
from a crafted file. An N≤1 is also rejected as invalid.

**Scope note**: the encrypted container format is intentionally *not* compatible
with the stock `minisign` secret-key file format. The public keys and detached
signatures it produces remain fully minisign-verifiable. Secret key interop with
`minisign` is out of scope by design.

---

## Incremental build cache (`polypkg.repo-cache/v2`)

The build cache lives beside the signing key (in `keyDir`, outside the served
output directory). It is a JSON file (`<source>.build-cache.json`) with this
structure:

```json
{
  "schema": "polypkg.repo-cache/v2",
  "serial": 5,
  "entries": {
    "./pkgs/hello": {
      "fingerprint": "<sha256 hex>",
      "content_hash": "blake3:<hex>",
      "artifact": "pool/<hex>.tar.zst",
      "version": "1.2.3",
      "revision": 1,
      "att_predicate_type": "https://polypkg.dev/attestation/sarif/v1",
      "att_artifact": "pool/<hex>.att.json",
      "att_content_hash": "blake3:<hex>"
    }
  }
}
```

The `att_*` fields reconstruct the index's attestation ref on a cache hit; they
are empty for entries built under `--skip-attestations`. That is the flag's
cache-hit CAVEAT: an unchanged package reuses the attestation decision it was
built with, so flipping `--skip-attestations` takes effect for a package only
after its source changes or the cache is cleared. Any schema other than v2 is
treated as a cold cache (full re-pack), never a fatal error.

**Source fingerprint** (`SourceFingerprint` in `cache.go`): SHA-256 over the
sorted list of `relpath\x00size\x00mtimeNano` for every file under the source
directory. This is cheap to compute and changes whenever any file in the source
tree changes (content, size, or mtime). It does not re-read file content, so it
can give false negatives if mtime is reset without content change — acceptable
for a build cache, not for a security boundary.

**Serial bump policy**: the monotonic serial is incremented only when the
published output actually changes. A build that reuses every cache entry and
produces a byte-identical index does not bump the serial, leaving `repo status`
at exit 0. The serial also bumps when the on-disk `trust_root.pub` does not
match the currently loaded key (key rotation detection), and when the expiry
renewal below re-stamps `expires` with no content change (the index bytes
differ, so the byte-compare catches it). The serial recorded in the cache is
floored at the serial already published in the output directory, so a lost or
corrupt cache cannot regress — and thus reuse — a serial.

**Freshness / expiry renewal (`--valid-for`, D13/D-C1)**: every build threads
one `expires` value (default 720h) into both the index and the trust document.
`computeExpires` reuses the currently published `expires` when nothing changed
AND more than half the validity window remains — keeping no-op rebuilds
byte-identical and serial-stable — and otherwise stamps `now + validFor`.
`Inspector.Pending` predicts the same half-life threshold (using the default
window; `repo status` has no `--valid-for` flag), reporting "metadata expiry
refresh due" so status and build never disagree at the default window. A repo
published with a custom `--valid-for` (say 24h) can show pending in status
while a default-window build would no-op.

**Attestation generation (D6/D7, D-C4)**: for every (re)packed package the
builder re-runs the `pkglint` engine, refuses to publish if any error-severity
finding fires (no partial publish — lint runs before any pool write), renders
canonical SARIF, assembles the in-toto Statement (subject digest = the
artifact's BLAKE3), canonicalizes it, and signs it under the attestation role.
The statement is byte-identical to `pkg build`'s unsigned `.att.json` preview
(D12). `--skip-attestations` bypasses all of this for newly built packages;
see the cache caveat above for unchanged ones.

**Atomicity**: individual pool writes use temp-file + rename, so a partial
write is never visible to concurrent readers. The metadata set — `index.json`,
`trust.json`, their `.minisig`s, and `trust_root.pub` — is published via
`writeAtomicBatch`: every file is staged to a temp sibling first, and only
when all five are staged are they renamed into place. A failure during the
write phase (the common out-of-space/permission case) aborts before any
rename, leaving the previously published set untouched and internally
consistent. A rename-phase failure (rare — same directory, no allocation) can
still leave a partial set; the cache is saved only on full success, so the
next build re-publishes the full set, self-healing it.

---

## FIPS posture

The tool runs clean under `GODEBUG=fips140=on` (Go's FIPS 140-3 module). Run
`task test:fips` to verify.

| Primitive | FIPS status under `fips140=on` |
|---|---|
| Ed25519 (`crypto/ed25519`) | Validated — routes through the Go boringcrypto/FIPS module |
| AES-256-GCM (`crypto/aes`, `crypto/cipher`) | Validated |
| PBKDF2-SHA256 (`crypto/pbkdf2`) | Validated (when `--kdf pbkdf2` is used) |
| scrypt (`golang.org/x/crypto/scrypt`) | **Not validated** — external package, not in the FIPS module |
| BLAKE3 (`lukechampine.com/blake3`) | **Not validated** — external C-backed package |

Operators targeting a FIPS environment should:

1. Use `polypkg repo init --kdf pbkdf2` so the key encryption KDF is validated.
2. Accept that content hashes remain BLAKE3 (an artifact of the index format shared
   with the consumer, which also uses BLAKE3). `fips140=on` permits non-validated
   code paths for hashing purposes; only key-material operations route through the
   validated module.

`fips140=only` mode (which would reject all non-validated primitives, including
BLAKE3 and scrypt) is **not** currently supported. Migrating the content hash
from BLAKE3 to SHA-256 is a breaking change to the index format and is deferred.

---

## Package layout summary

```
internal/repo/
  signer.go          Keypair, GenerateKeypair, SignArtifact, SignAttestation, SignIndex, SignTrust, ContentHash
  keystore.go        SaveKey, LoadKey, KDF constants, encrypted container format
  pack.go            PackArtifact, ReadPackageSource (packs source dir into .tar.zst)
  cache.go           BuildCache, LoadBuildCache, SourceFingerprint
  build.go           Inspector (Pending), Builder (Build), loadLayout, computeExpires, writeAtomic(Batch)
  scaffold.go        InitRepo, InitOptions, InitResult
  manifest_edit.go   AddPackage, RemovePackage (edit polypkg-repo.yaml)
  error.go           PublishError (structured error with Hint)

internal/cli/
  repo.go            newRepoCmd, newRepoInitCmd, repoKeyPassword, defaultKeyDir, mapPublishError
  repobuild.go       newRepoBuildCmd, newRepoStatusCmd, addRepoCommonFlags, buildRepo
  repoaddremove.go   newRepoAddCmd, newRepoRemoveCmd
  repokey.go         newRepoKeyCmd, newRepoKeyShowCmd
```

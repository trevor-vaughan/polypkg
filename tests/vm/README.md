# VM-based LSM-enforcement tests

A functional test tier that boots a **real guest with its own kernel** and
drives the **actually-built `polypkg` binary** through a full install → upgrade
→ remove lifecycle as real root, under an **enforcing** Linux Security Module.
It complements — does not replace — the container tier under `tests/e2e/` and
the in-process Ginkgo suite under `tests/integration/`.

## Why this exists (altitude)

The container tier (`tests/e2e/`) proves **userland universality**: one static
binary runs correctly across glibc and musl userlands. But a container shares
the **host** kernel, and an LSM is a property of that kernel. On the current
build host SELinux and AppArmor are disabled, so the containers are never
LSM-confined — the e2e tier is honest that it *cannot* prove enforcement (see
its "LSM scope" section).

This tier closes that gap. A VM boots its **own** kernel, so SELinux can run
`enforcing` and AppArmor profiles are loaded regardless of host state. It
answers one question: does polypkg's system-scope install plus its
symlink-based active-root model operate **cleanly** under an enforcing LSM —
correct security contexts and **zero denials** across a real upgrade?

"Clean" is the load-bearing word. The headline assertion is not that polypkg
*ran* but that it accrued **zero LSM denials** during the whole lifecycle
(`ausearch -m AVC` on SELinux, `journalctl -k | grep apparmor=DENIED` on
AppArmor). A tool can survive an enforcing kernel while quietly racking up
denials that a future policy tightening would turn into failures; this tier
rejects that state.

## Guests

Both are validated and green.

| Guest | Kernel LSM | Enforcement gate |
|-------|-----------|------------------|
| CentOS Stream 10 | SELinux **enforcing** | `getenforce` = `Enforcing` |
| Ubuntu 24.04 | AppArmor enabled/enforcing | `aa-enabled` |

## Run it

```bash
task test:vm                 # both guests (DISTRO defaults to all)
task test:vm DISTRO=centos   # one guest
task test:vm DISTRO=ubuntu
```

This tier is **opt-in**. It is deliberately **not** part of `task test` or
`task check` (see "Runtime cost" below for why). `task test:vm` is an alias that
runs `vm:deps` then `vm:run`. The `vm:*` tasks are also callable directly:

```bash
task vm:deps    # install the QEMU/TCG toolchain + qemu-system-x86_64 symlink
task vm:build   # build the static polypkg + venom binaries for in-guest use
task vm:run     # boot the guest(s) and run the suites (DISTRO=centos|ubuntu|all)
task vm:clean   # remove run artifacts (keeps the cached base images)
```

Results land in `.test-output/vm/run/<distro>/venom-{install,upgrade}/`
(gitignored). Cached base images live under `.test-output/vm/images/`.

## Base image pins

Each guest in `guests_test.go` carries an `imageURL` and an `imageSHA256`. The
harness verifies the checksum before a downloaded image is promoted into the
cache, so an image that fails the pin never becomes the base for a later run.

The URL must name a **dated compose**, never a rolling alias:

| Distro | Pin this | Not this |
|--------|----------|----------|
| CentOS Stream | `…/CentOS-Stream-GenericCloud-10-20260818.0.x86_64.qcow2` | `…-GenericCloud-10-latest.x86_64.qcow2` |
| Ubuntu | `…/releases/24.04/release-20260814/…` | `…/releases/24.04/release/…` |

Upstream republishes the aliases in place. A checksum pinned against one is
correct only until the distro cuts its next image, and then every run fails
verification against an image nobody chose. `TestGuestImagesPinToDatedCompose`
enforces this under plain `task test` — no QEMU required.

To refresh a pin, take the compose and its published sum together:

```bash
# CentOS Stream — index: https://cloud.centos.org/centos/10-stream/x86_64/images/
curl -s https://cloud.centos.org/centos/10-stream/x86_64/images/CentOS-Stream-GenericCloud-10-20260818.0.x86_64.qcow2.SHA256SUM
# SHA256 (CentOS-Stream-GenericCloud-10-20260818.0.x86_64.qcow2) = 578ef6128c97…

# Ubuntu — index: https://cloud-images.ubuntu.com/releases/24.04/
curl -s https://cloud-images.ubuntu.com/releases/24.04/release-20260814/SHA256SUMS | grep server-cloudimg-amd64.img
# 6e40c07ae715… *ubuntu-24.04-server-cloudimg-amd64.img
```

Update `imageURL` and `imageSHA256` in the same edit, then delete the stale
cached image (`.test-output/vm/images/`) so the next run re-downloads. A
mismatch against an already-cached image names that path in its error.

## Topology

```
host                                                  guest (own kernel, LSM enforcing)
────                                                  ─────────────────────────────────
build polypkg (CGO_ENABLED=0) ──┐
build/install venom ────────────┤
                                ▼
   sign a repo on the host ──► public/  ──scp──►  guest:/…/public
                                                       │
   per-run CoW overlay of cached image ──qemu──►  boot + cloud-init (seed ISO, /dev/sr0)
        + cloud-init seed ISO (ephemeral root key)     │
                                                       ▼
   ssh/scp over user-mode SLIRP hostfwd ◄────► assert gate (getenforce / aa-enabled)
                                                  serve repo in-guest:
                                                    systemd-run … python3 -m http.server 8080
                                                  run venom INSIDE the guest as real root
                                                       │
                                                       ▼
                                                  ausearch -m AVC  /  apparmor=DENIED  → must be CLEAN
```

- Orchestration is `github.com/anatol/vmtest` (Go), which drives
  `qemu-system-x86_64`. The harness uses vmtest for boot, the QEMU process
  lifecycle, and console capture. **Guest I/O (ssh/scp) goes through the system
  `ssh`/`scp`** over a user-mode SLIRP `hostfwd` port — rootless-safe, needs no
  privileges, no `tap`/bridge setup. Each guest forwards a distinct host port
  (CentOS `2207`, Ubuntu `2208`) so the two can run back-to-back without
  collision.
- Per guest, per run, the harness boots a **per-run copy-on-write overlay** of a
  cached cloud image plus a cloud-init **seed ISO** that injects an ephemeral
  root SSH key. The base image is downloaded and cached once; the overlay keeps
  each run from mutating the cache.
- The harness waits for SSH, **asserts the enforcement gate** (the guest is
  actually `Enforcing` / AppArmor is actually enabled — a misconfigured guest
  fails here, not silently), builds a signed repo on the host with the freshly
  built `polypkg`, pushes the static `polypkg` + `venom` binaries, the repo's
  `public/` dir, and the two venom suites into the guest, serves the repo
  in-guest, and runs **Venom inside the guest as real root**.

## Lifecycle the suites prove

Two phases, proving a real upgrade under enforcement:

| Phase | Suite | What it does |
|-------|-------|--------------|
| install | `venom/25-lsm-install.venom.yml` | install `hello@1.0.0` (+`tool-a`); assert `hello` prints `1.0.0` and the bridged `widget` command works |
| upgrade | `venom/26-lsm-upgrade.venom.yml` | host publishes `hello@1.1.0` and refreshes the in-guest repo → upgrade; assert `hello` prints `1.1.0` → remove; assert the bridged command is gone |

Throughout both phases, the **denial probe must stay CLEAN**. That is the
property this tier exists to defend.

## Enforcement depth — why zero-denial alone is shallow, and what closes it

polypkg runs **unconfined** in the guest (no LSM policy of its own — see the
scope notes below). A bare "the lifecycle ran with zero denials" check on an
unconfined process is therefore weak: nothing was constrained, so nothing could
be denied. After the install suite passes, the tier adds two checks that
actually exercise the policy against polypkg's files.

### 1. Label correctness — SELinux only (`assertLabelsClean`)

`restorecon -nvR /var/lib/polypkg /usr/local/bin/widget /etc/polypkg` runs as a
dry run; if it reports `would relabel` on anything, the test fails. Passing
means polypkg created every one of those files with the context the targeted
policy already expects, so a *confined* consumer reaching them sees correctly
labeled files. The paths come from the guest descriptor's `labelPaths`; the
check is a no-op on AppArmor (`labelPaths` empty — AppArmor has no path labels).

### 2. Runtime confined-consumer READ test — both guests (`assertConfinement`)

A consumer is placed in a confined SELinux domain / AppArmor profile via a
**systemd transient unit** (`systemd-run` with `SELinuxContext=` or
`AppArmorProfile=`) and runs `cat /usr/local/bin/widget` — which resolves
through the bridge symlink to the real file under `/var/lib/polypkg`. Each guest
ships a **positive** consumer and a **negative-control** consumer:

| Guest | Artifact | Positive domain/profile | Negative-control domain/profile |
|-------|----------|-------------------------|---------------------------------|
| CentOS | `confine/polypkg_consumer.te` (compiled to a `.pp` on the host via the refpolicy devel Makefile, `semodule -i`'d in the guest) | `polypkg_consumer_t` — granted `var_lib_t` read | `polypkg_consumer_narrow_t` — no `var_lib_t` read |
| Ubuntu | `confine/polypkg-consumer.aa` (`apparmor_parser -r`'d in the guest) | `polypkg_consumer` — grants `/var/lib/polypkg/** r` | `polypkg_consumer_narrow` — only `/usr/local/bin/** r` |

The positive consumer must read the target (prints `widget`). The negative
control must be **denied** — both narrow domains can still *start* `cat` (the
SELinux module grants each `bin_t` `entrypoint` so the failure is the read, not
a spurious `203/EXEC`), they just lack the label/path that reaches the
`/var/lib` resident. A denied negative control is what proves the enforcement is
live; if it succeeded the positive result would be meaningless (a false green).

**Why READ and not exec.** The feasibility spike found that a confined systemd
unit — even the default service domain — *cannot exec* polypkg's
`/var/lib`-resident bridged command: that file carries the SELinux `var_lib_t`
**data** label, not an executable type, so the exec fails with `EACCES` and
produces **no AVC** at all. This is a real characteristic of polypkg's bridging
model: a confined service cannot directly exec a polypkg-bridged command without
custom policy granting `var_lib_t` execute. What it *can* do, governed by label
and path, is **read** polypkg-installed config and data. The test therefore
exercises that realistic, label-governed read path rather than a contrived exec.

**These `.te`/`.aa` files are TEST ARTIFACTS** — a stand-in for a typical
confined service consuming polypkg's files. They are **not** polypkg production
LSM policy; polypkg still ships none of its own (see the scope sections).

**Honest asymmetry.** SELinux confined-safety is proven two ways — by label
(`restorecon -n`) and by the runtime read test. AppArmor is proven by the
runtime read test only; it has no path-label concept, so there is no
`restorecon`-equivalent dry run to add.

**Denial-gate caveat.** The negative control deliberately triggers an LSM
denial. So the tier's final zero-denial gate filters out `polypkg_consumer*`
records (`grep -v polypkg_consumer` in both `denialProbe`s) before asserting
CLEAN. The filter is narrow: any *real* lifecycle denial is still caught. A
future maintainer adjusting the probe should keep that exclusion scoped to the
test consumers, not widen it.

## File layout

| Path | Role |
|------|------|
| `harness.go` | always-compiled pure helpers (`accelFor`, `qemuParams`), unit-tested in `harness_unit_test.go` and run under `task test` |
| `harness_vm_test.go` (`//go:build vm`) | the VM-only plumbing (boot + ssh/scp + image cache + host-side signed-repo build). Behind the build tag and in a `_test.go` file so the default `task lint`/`task test` chain excludes the QEMU harness entirely |
| `guests_test.go` | the per-distro `guests` descriptors (image URL + sha, seed file, enforcement probe, denial probe, forwarded ssh port), plus the pin invariant that guards them. Deliberately **not** behind the `vm` tag, so `task test` catches a bad image pin without needing QEMU — see "Base image pins" below |
| `vmtest_test.go` (`//go:build vm`) | the `TestLSM` per-distro integration test (build tag `vm`, so it never runs under `task test`) |
| `seed/centos-user-data.yaml`, `seed/ubuntu-user-data.yaml` | cloud-init seeds |
| `venom/25-lsm-install.venom.yml`, `venom/26-lsm-upgrade.venom.yml` | in-guest Venom suites |
| `confine/polypkg_consumer.te` | CentOS confined-consumer SELinux module source (positive + negative-control domains); compiled to a `.pp` on the host and `semodule -i`'d in the guest. A test artifact, not production policy |
| `confine/polypkg-consumer.aa` | Ubuntu confined-consumer AppArmor profile pair (positive + negative-control); `apparmor_parser -r`'d in the guest. A test artifact, not production policy |
| `.taskfiles/vm.yml` | the `vm:*` tasks; the root `Taskfile.yml` `test:vm` alias wraps them |

## Runtime cost — be honest

The current build host has **no `/dev/kvm`**, so QEMU runs under **TCG software
emulation**. Boot-to-green is roughly **~100s per guest** (slower on a cold run
that must download the base image). The harness detects `/dev/kvm`: it uses KVM
when present and TCG otherwise, and **logs which path it took**, so a slow TCG
run is never mistaken for native acceleration. This emulation cost is exactly
why the tier is opt-in and excluded from the default gates — paying ~3 minutes
of CPU emulation on every `task test` would not be worth it.

## AppArmor scope — what the Ubuntu guest proves, honestly

Ubuntu runs AppArmor in enforcing mode with the **distro's** profiles, but
polypkg ships **no AppArmor profile of its own**. So this tier tests
*"polypkg runs clean on an AppArmor-enforcing kernel — zero denials."* It
deliberately does **not** author a synthetic profile to confine *polypkg
itself*: that would test a hand-written profile, not polypkg. If polypkg ever
ships an official AppArmor profile, confined-operation testing of polypkg
becomes a separate follow-up, and a new suite asserting that polypkg works
*within* its own profile would belong here.

The confined-consumer profile pair shipped under `confine/` (see the
enforcement-depth section above) is a different thing: it confines a *consumer
of* polypkg's installed files, not polypkg, and exists only to prove that those
files are reachable exactly as their path/label grants allow. It is a test
artifact, not polypkg policy.

The SELinux guest is stronger by nature: the distro's targeted policy applies
type-enforcement contexts to the files polypkg places, so "zero AVCs" is a
statement about polypkg's own files and the contexts it leaves behind, not just
about distro packages.

## Maintainer gotchas (discovered during bring-up)

- **`-cpu max` is mandatory.** CentOS/RHEL 10 require `x86-64-v3`. QEMU's
  default `qemu64` CPU is `v1`, so the guest kernel halts before console init.
  Symptom: a 0-byte serial log and no disk writes — it looks exactly like a
  hang.
- **Use BIOS boot, not OVMF/UEFI.** The GenericCloud images are SeaBIOS
  (BIOS-boot). OVMF finds no ESP and falls through to PXE.
- **Attach the seed as a CD-ROM drive, not vmtest's `CdRom` field.** cloud-init
  reads the seed from `/dev/sr0` (DataSourceNoCloud). vmtest's `CdRom` field
  injects `-boot d`, which boots *from* the CD instead of the disk.
- **`QemuOptions.Timeout` caps the entire QEMU process lifetime**, not just
  boot. It is set to `40m` to outlast a full TCG run; `task vm:run` passes the
  same `-timeout 40m` to `go test`.
- **Launch the in-guest repo server with `systemd-run`, not `cmd & sleep`.** A
  process backgrounded over an SSH channel holds that channel open, so the
  provisioning call hangs. `systemd-run` detaches it into a transient unit and
  the SSH command returns.

## Relationship to the other tiers

```
tests/integration/   in-process cobra calls vs httptest      — fast, broad, no real boundary
tests/e2e/           real binary, real root, real HTTP, in containers
                       → proves userland universality; CANNOT prove LSM enforcement (shared host kernel)
tests/vm/  (here)    real binary, real root, real HTTP, in a VM with its own kernel
                       → proves polypkg runs CLEAN under an ENFORCING LSM (SELinux / AppArmor)
```

The e2e tier and this tier are the two halves of the LSM story: e2e shows
polypkg is portable; vm shows it is policy-clean where a kernel actually
enforces.

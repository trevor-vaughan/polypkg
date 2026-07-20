// Package vm implements the opt-in, VM-based LSM-enforcement test tier:
// it boots CentOS/Ubuntu guests under QEMU and runs polypkg's lifecycle
// inside them under SELinux/AppArmor enforcement. The heavy harness lives in
// build-tagged (`vm`) test files; this file holds only pure, always-compiled
// helpers exercised by the unit tests.
package vm

import (
	"fmt"
	"os"
)

// accelFor returns the QEMU accelerator to use: kvm when the kvm device node
// exists, tcg (pure software emulation) otherwise. kvmPath is injectable for tests.
func accelFor(kvmPath string) string {
	if _, err := os.Stat(kvmPath); err == nil {
		return "kvm"
	}
	return "tcg"
}

// qemuParams builds the QEMU args passed via vmtest.QemuOptions.Params: accel,
// CPU model, RAM/CPU, user-mode (SLIRP) networking with SSH forwarded to a
// loopback host port, and the cloud-init seed as a CD-ROM drive. User-mode
// networking needs no privileges — this is what makes it rootless. vmtest
// itself injects the headless console (-nographic -display none -serial/-monitor
// unix sockets), so we must NOT add -display/-serial here or QEMU sees duplicates.
//
// SPIKE FINDINGS (confirmed on this host) — do not drop these:
//   - "-cpu max" is MANDATORY: CentOS/RHEL 10 requires x86-64-v3; the default
//     qemu64 CPU is v1, so the guest kernel halts before console init.
//   - The GenericCloud image is BIOS-boot (SeaBIOS, default machine); no OVMF.
//   - Attach the seed as a CD-ROM drive (cloud-init finds it at /dev/sr0 via
//     DataSourceNoCloud) and leave the disk as the boot device.
func qemuParams(accel string, sshPort int, seedISO string) []string {
	return []string{
		"-accel", accel,
		"-cpu", "max",
		"-m", "2048",
		"-smp", "2",
		"-netdev", fmt.Sprintf("user,id=n0,hostfwd=tcp:127.0.0.1:%d-:22", sshPort),
		"-device", "virtio-net-pci,netdev=n0",
		"-drive", "file=" + seedISO + ",media=cdrom",
	}
}

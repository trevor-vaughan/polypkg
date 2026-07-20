//go:build vm

package vm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/anatol/vmtest"
)

// guest describes a distro target for the LSM tier. Values were confirmed by
// the feasibility spike on this host.
type guest struct {
	name        string // "centos" | "ubuntu"
	imageFile   string // basename under VM_IMAGE_DIR
	imageURL    string // download source
	imageSHA256 string // checksum to verify the cached base ("" = unpinned, first bring-up)
	seedFile    string // cloud-init user-data under tests/vm/seed/
	loginUser   string // "root" (we inject the root key via cloud-init)
	sshPort     int    // distinct forwarded host port per guest (avoid collisions)
	// enforceProbe must print "OK" on stdout iff the LSM is enforcing.
	enforceProbe string
	// denialProbe must print "CLEAN" iff no LSM denials were recorded since boot.
	denialProbe string
	// labelPaths: paths whose SELinux contexts must already match policy
	// (restorecon -n reports nothing). Empty on non-SELinux guests (AppArmor).
	labelPaths []string
}

var guests = map[string]guest{
	"centos": {
		name:         "centos",
		imageFile:    "centos.qcow2",
		imageURL:     "https://cloud.centos.org/centos/10-stream/x86_64/images/CentOS-Stream-GenericCloud-10-latest.x86_64.qcow2",
		imageSHA256:  "f08ee2e1fbfebbaa7726860ca1068a7ba37f2ab8628d1434e1347535d09e77ee", // DevSkim: ignore DS173237 - public CentOS cloud image SHA-256 pin (supply-chain integrity), not a secret
		seedFile:     "centos-user-data.yaml",
		loginUser:    "root",
		sshPort:      2207,
		enforceProbe: `[ "$(getenforce)" = "Enforcing" ] && echo OK`,
		// Exclude our own deliberate confinement negative-control denials
		// (polypkg_consumer*); the gate still catches any real lifecycle denial.
		denialProbe: `! ausearch -m AVC -ts boot 2>/dev/null | grep -v polypkg_consumer | grep -q . && echo CLEAN`,
		labelPaths:  []string{"/var/lib/polypkg", "/usr/local/bin/widget", "/etc/polypkg"},
	},
	"ubuntu": {
		name:         "ubuntu",
		imageFile:    "ubuntu.img",
		imageURL:     "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img",
		imageSHA256:  "5fa5b05e5ec239858c4531485d6023b0896448c2df7c63b34f8dae6ea6051a44", // DevSkim: ignore DS173237 - public Ubuntu cloud image SHA-256 pin (supply-chain integrity), not a secret
		seedFile:     "ubuntu-user-data.yaml",
		loginUser:    "root",
		sshPort:      2208,
		enforceProbe: `aa-enabled >/dev/null 2>&1 && echo OK`,
		// Exclude our own deliberate confinement negative-control denials
		// (profile=polypkg_consumer_narrow); the gate still catches any real one.
		denialProbe: `! journalctl -k --no-pager 2>/dev/null | grep 'apparmor=.DENIED' | grep -v polypkg_consumer | grep -q . && echo CLEAN`,
	},
}

// bootedGuest holds a running VM and the connection details to drive it.
type bootedGuest struct {
	qemu    *vmtest.Qemu
	sshPort int
	keyPath string
}

// testingT is the minimal subset of *testing.T the harness needs.
type testingT interface{ Logf(string, ...any) }

func trimLine(s string) string { return strings.TrimSpace(s) }

// boot starts the guest from a per-run overlay of baseImage with the cloud-init
// seed attached as a CD-ROM, using KVM when available and TCG otherwise.
// SPIKE: pass the full machine via Params; do NOT use vmtest Disks/CdRom fields
// (CdRom injects -boot d; we must boot the disk). vmtest is used only for
// process lifecycle + console capture.
func boot(t testingT, baseImage, seedISO, runDir string, sshPort int) (*bootedGuest, error) {
	overlay := filepath.Join(runDir, "overlay.qcow2")
	if out, err := exec.Command("qemu-img", "create", "-f", "qcow2",
		"-F", "qcow2", "-b", baseImage, overlay).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("overlay: %w: %s", err, out)
	}
	accel := accelFor("/dev/kvm")
	t.Logf("VM accel=%s (TCG is slow; ~90s to SSH on this no-KVM host)", accel)
	params := append(qemuParams(accel, sshPort, seedISO),
		"-drive", "file="+overlay+",if=virtio,format=qcow2")
	opts := &vmtest.QemuOptions{
		Architecture:    vmtest.QEMU_X86_64,
		OperatingSystem: vmtest.OS_LINUX,
		Params:          params,
		Verbose:         true,
		// Timeout caps the whole QEMU process lifetime, not just boot. Under TCG
		// the full two-phase lifecycle (boot + install suite + upgrade suite) runs
		// well past 20m, so size this to the task's go-test -timeout (40m) and let
		// the test timeout govern instead of QEMU pre-empting mid-suite.
		Timeout: 40 * time.Minute,
	}
	q, err := vmtest.NewQemu(opts)
	if err != nil {
		return nil, fmt.Errorf("start qemu: %w", err)
	}
	return &bootedGuest{qemu: q, sshPort: sshPort}, nil
}

func (g *bootedGuest) sshArgs(extra ...string) []string {
	// LogLevel=ERROR silences the "Permanently added ... to known hosts" notice
	// that ssh otherwise writes to stderr; CombinedOutput would mix it into the
	// probe output and break exact-match assertions like getenforce == "OK".
	base := make([]string, 0, 13+len(extra))
	base = append(base,
		"-i", g.keyPath, "-p", fmt.Sprint(g.sshPort),
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR", "-o", "ConnectTimeout=10", "root@127.0.0.1",
	)
	return append(base, extra...)
}

// waitSSH polls until the guest accepts SSH or the deadline passes.
func (g *bootedGuest) waitSSH(ctx context.Context) error {
	deadline := time.Now().Add(15 * time.Minute)
	for time.Now().Before(deadline) {
		if exec.CommandContext(ctx, "ssh", g.sshArgs("true")...).Run() == nil {
			return nil
		}
		time.Sleep(10 * time.Second)
	}
	return fmt.Errorf("guest SSH not reachable before deadline")
}

func (g *bootedGuest) run(ctx context.Context, script string) (string, error) {
	out, err := exec.CommandContext(ctx, "ssh", g.sshArgs(script)...).CombinedOutput()
	return string(out), err
}

func (g *bootedGuest) push(ctx context.Context, local, remote string) error {
	args := []string{"-i", g.keyPath, "-P", fmt.Sprint(g.sshPort),
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		"-r", local, "root@127.0.0.1:" + remote}
	if out, err := exec.CommandContext(ctx, "scp", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("push %s: %w: %s", local, err, out)
	}
	return nil
}

func (g *bootedGuest) pull(ctx context.Context, remote, local string) error {
	args := []string{"-i", g.keyPath, "-P", fmt.Sprint(g.sshPort),
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		"-r", "root@127.0.0.1:" + remote, local}
	if out, err := exec.CommandContext(ctx, "scp", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("pull %s: %w: %s", remote, err, out)
	}
	return nil
}

func genKey(runDir string) (priv, pub string, err error) {
	priv = filepath.Join(runDir, "id_ed25519")
	if out, e := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "",
		"-f", priv).CombinedOutput(); e != nil {
		return "", "", fmt.Errorf("ssh-keygen: %w: %s", e, out)
	}
	b, e := os.ReadFile(priv + ".pub")
	return priv, strings.TrimSpace(string(b)), e
}

func buildSeed(seedTemplate, runDir, pubkey string) (string, error) {
	tpl, err := os.ReadFile(seedTemplate)
	if err != nil {
		return "", err
	}
	ud := filepath.Join(runDir, "user-data")
	if err := os.WriteFile(ud,
		[]byte(strings.ReplaceAll(string(tpl), "__SSH_PUBKEY__", pubkey)), 0o644); err != nil {
		return "", err
	}
	md := filepath.Join(runDir, "meta-data")
	if err := os.WriteFile(md, []byte("instance-id: polypkg-vm\nlocal-hostname: polypkg-vm\n"), 0o644); err != nil {
		return "", err
	}
	iso := filepath.Join(runDir, "seed.iso")
	if out, err := exec.Command("xorriso", "-as", "mkisofs", "-volid", "cidata",
		"-joliet", "-rock", "-output", iso, ud, md).CombinedOutput(); err != nil {
		return "", fmt.Errorf("seed iso: %w: %s", err, out)
	}
	return iso, nil
}

// ensureImage returns the cached base image path, downloading from the guest's
// URL if absent. Verifies imageSHA256 when set; empty sum logs the computed sum
// to pin later. Download URL lives only in the guest descriptor.
func ensureImage(g guest, imageDir string) (string, error) {
	if err := os.MkdirAll(imageDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(imageDir, g.imageFile)
	if _, err := os.Stat(path); err != nil {
		tmp := path + ".part"
		if out, e := exec.Command("curl", "-fL", "-o", tmp, g.imageURL).CombinedOutput(); e != nil {
			return "", fmt.Errorf("download %s: %w: %s", g.imageURL, e, out)
		}
		if err := os.Rename(tmp, path); err != nil {
			return "", err
		}
	}
	sum, err := sha256File(path)
	if err != nil {
		return "", err
	}
	if g.imageSHA256 == "" {
		fmt.Printf("WARNING: %s sha256=%s is unpinned; record it in the guests map (harness_vm_test.go)\n", g.imageFile, sum)
	} else if sum != g.imageSHA256 {
		return "", fmt.Errorf("%s sha256 mismatch: got %s want %s", g.imageFile, sum, g.imageSHA256)
	}
	return path, nil
}

// buildRepoBase produces a signed repo (hello@1.0.0 + the other fixtures) under
// runDir/repo using the freshly built polypkg, mirroring the publish suite.
// Returns the repo's public/ dir (the only part the guest needs).
func buildRepoBase(ctx context.Context, polypkgBin, fixturesDir, runDir string) (string, error) {
	repo := filepath.Join(runDir, "repo")
	keys := filepath.Join(runDir, "keys")
	for _, d := range []string{repo, keys} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return "", err
		}
	}
	manifest := filepath.Join(repo, "polypkg-repo.yaml")
	run := func(args ...string) error {
		c := exec.CommandContext(ctx, polypkgBin, args...)
		c.Env = append(os.Environ(), "POLYPKG_REPO_KEY_PASSWORD=test-pw")
		if out, err := c.CombinedOutput(); err != nil {
			return fmt.Errorf("polypkg %v: %w: %s", args, err, out)
		}
		return nil
	}
	if err := run("repo", "init", repo, "--source", "native", "--key-dir", keys); err != nil {
		return "", err
	}
	for _, p := range []string{"hello", "tool-a", "tool-b", "goodbye", "breaker", "needs-hello"} {
		if err := run("repo", "add", filepath.Join(fixturesDir, p), "--manifest", manifest, "--key-dir", keys); err != nil {
			return "", err
		}
	}
	return filepath.Join(repo, "public"), nil
}

// publishUpgrade adds hello@1.1.0 to the existing manifest (rolling repo → 1.1.0
// becomes the published hello), enabling a real upgrade.
func publishUpgrade(ctx context.Context, polypkgBin, fixturesDir, runDir string) error {
	repo := filepath.Join(runDir, "repo")
	keys := filepath.Join(runDir, "keys")
	c := exec.CommandContext(ctx, polypkgBin, "repo", "add",
		filepath.Join(fixturesDir, "hello-1.1.0"),
		"--manifest", filepath.Join(repo, "polypkg-repo.yaml"), "--key-dir", keys)
	c.Env = append(os.Environ(), "POLYPKG_REPO_KEY_PASSWORD=test-pw")
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("publish upgrade: %w: %s", err, out)
	}
	return nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

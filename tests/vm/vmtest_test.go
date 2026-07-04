//go:build vm

package vm

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var distroFlag = flag.String("distro", "centos", "guest to run: centos|ubuntu|all")

func runDirFor(t *testing.T, name string) string {
	d := filepath.Join(os.Getenv("VM_OUT_DIR"), "run", name)
	// Start each run from a clean dir: ssh-keygen and the seed builder refuse to
	// overwrite, so stale artifacts from a prior run would abort the boot.
	if err := os.RemoveAll(d); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

// bootGuest: keypair → seed → ensure image → boot → wait SSH → assert
// enforcement. runDir is the caller-owned, already-cleaned per-guest run dir
// (see runDirFor) — bootGuest does not create or wipe it, so the caller can
// safely build other artifacts (e.g. the host-side repo) in the same dir.
func bootGuest(t *testing.T, ctx context.Context, g guest, runDir string) *bootedGuest {
	priv, pub, err := genKey(runDir)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := buildSeed(filepath.Join("seed", g.seedFile), runDir, pub)
	if err != nil {
		t.Fatal(err)
	}
	base, err := ensureImage(g, os.Getenv("VM_IMAGE_DIR"))
	if err != nil {
		t.Fatal(err)
	}
	bg, err := boot(t, base, seed, runDir, g.sshPort)
	if err != nil {
		t.Fatal(err)
	}
	bg.keyPath = priv
	t.Cleanup(func() { bg.qemu.Shutdown() })
	if err := bg.waitSSH(ctx); err != nil {
		t.Fatal(err)
	}
	out, err := bg.run(ctx, g.enforceProbe)
	if err != nil || trimLine(out) != "OK" {
		t.Fatalf("enforcement gate failed for %s: out=%q err=%v", g.name, out, err)
	}
	return bg
}

func mustAbs(t *testing.T, p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func mustRun(t *testing.T, ctx context.Context, g *bootedGuest, s string) {
	if out, err := g.run(ctx, s); err != nil {
		t.Fatalf("guest cmd %q: %v: %s", s, err, out)
	}
}

func mustPush(t *testing.T, ctx context.Context, g *bootedGuest, l, r string) {
	if err := g.push(ctx, l, r); err != nil {
		t.Fatal(err)
	}
}

// assertLabelsClean fails if any guest path is mislabeled relative to policy:
// `restorecon -nvR` must report no relabel actions. SELinux-only; a no-op when
// the guest has no labelPaths (e.g. AppArmor). A relabel finding means polypkg
// created a mislabeled file — a real defect, surfaced not masked.
func assertLabelsClean(t *testing.T, ctx context.Context, bg *bootedGuest, g guest) {
	if len(g.labelPaths) == 0 {
		return
	}
	// No `2>&1; echo RC=$?` trailer: that would always exit 0 and mask a real
	// restorecon failure (missing path / tooling error) as a false green. Let
	// restorecon's own exit propagate via err (bg.run uses CombinedOutput, so
	// stderr is still captured into out for the message).
	out, err := bg.run(ctx, "restorecon -nvR "+strings.Join(g.labelPaths, " "))
	if err != nil {
		t.Fatalf("restorecon dry-run failed on %s: %v\n%s", g.name, err, out)
	}
	if strings.Contains(strings.ToLower(out), "would relabel") {
		t.Fatalf("%s: polypkg left mislabeled files (restorecon would relabel):\n%s", g.name, out)
	}
}

// runConfined READS the bridged target (its real file is under /var/lib/polypkg,
// reached via the /usr/local/bin/widget symlink) by running `cat` under the named
// confined domain/profile via a systemd transient unit. kind is "selinux" or
// "apparmor". Exec of the var_lib_t target is impossible under SELinux (spike), so
// the discriminator is READ access.
func runConfined(ctx context.Context, bg *bootedGuest, kind, name string) (string, error) {
	var prop string
	switch kind {
	case "selinux":
		prop = "-p SELinuxContext=system_u:system_r:" + name + ":s0"
	case "apparmor":
		prop = "-p AppArmorProfile=" + name
	}
	return bg.run(ctx, "systemd-run "+prop+" --wait --pipe -- /usr/bin/cat /usr/local/bin/widget")
}

// assertConfinement loads the guest's confinement artifact, then proves a
// correctly-permitted confined consumer CAN read the bridged /var/lib target
// (positive) while a too-narrow one is DENIED (negative control — proves
// enforcement is live and characterizes polypkg's /var/lib consume contract).
func assertConfinement(t *testing.T, ctx context.Context, bg *bootedGuest, g guest) {
	var kind, posDomain, negDomain string
	switch g.name {
	case "centos":
		kind = "selinux"
		posDomain, negDomain = "polypkg_consumer_t", "polypkg_consumer_narrow_t"
		mustRun(t, ctx, bg, "semodule -i /e2e/confine/polypkg_consumer.pp")
	case "ubuntu":
		kind = "apparmor"
		posDomain, negDomain = "polypkg_consumer", "polypkg_consumer_narrow"
		mustRun(t, ctx, bg, "apparmor_parser -r -W /e2e/confine/polypkg-consumer.aa")
	default:
		return
	}

	// Positive: must read the target cleanly. Assert on the file's distinctive
	// content ("widget from tool-a"), not just "widget" — the latter also appears
	// in a denial message ("cat: /usr/local/bin/widget: Permission denied"), so it
	// would not distinguish a successful read from a denied one.
	out, err := runConfined(ctx, bg, kind, posDomain)
	if err != nil || !strings.Contains(out, "widget from tool-a") {
		t.Fatalf("%s: confined consumer %q could not read the bridged target: err=%v out=%q",
			g.name, posDomain, err, out)
	}

	// Negative control: must be DENIED. If it SUCCEEDS, confinement isn't real and
	// the positive result is meaningless.
	nout, nerr := runConfined(ctx, bg, kind, negDomain)
	if nerr == nil {
		t.Fatalf("%s: narrow consumer %q unexpectedly read the bridged target (enforcement not live): %q",
			g.name, negDomain, nout)
	}
	// ...and the denial must be a READ permission denial (the /var/lib
	// discriminator), not an unrelated confounder (e.g. a spurious exec failure).
	if !strings.Contains(nout, "Permission denied") {
		t.Fatalf("%s: narrow consumer %q failed but not via a permission denial — suspect confounder: %q",
			g.name, negDomain, nout)
	}
}

func TestLSM(t *testing.T) {
	ctx := context.Background()
	binDir := os.Getenv("VM_BIN_DIR")
	fixtures := mustAbs(t, "../e2e/fixtures")
	for name, g := range guests {
		if *distroFlag != "all" && *distroFlag != name {
			continue
		}
		t.Run(name, func(t *testing.T) {
			runDir := runDirFor(t, name)
			bg := bootGuest(t, ctx, g, runDir)
			polypkgBin := filepath.Join(binDir, "polypkg")

			pub, err := buildRepoBase(ctx, polypkgBin, fixtures, runDir)
			if err != nil {
				t.Fatal(err)
			}

			mustRun(t, ctx, bg, "mkdir -p /usr/local/bin /repo /e2e && rm -rf /repo/public")
			mustPush(t, ctx, bg, polypkgBin, "/usr/local/bin/polypkg")
			mustPush(t, ctx, bg, filepath.Join(binDir, "venom"), "/usr/local/bin/venom")
			mustPush(t, ctx, bg, pub, "/repo/public")
			mustPush(t, ctx, bg, "venom/25-lsm-install.venom.yml", "/e2e/25-lsm-install.venom.yml")
			mustPush(t, ctx, bg, "venom/26-lsm-upgrade.venom.yml", "/e2e/26-lsm-upgrade.venom.yml")
			mustRun(t, ctx, bg, "chmod +x /usr/local/bin/polypkg /usr/local/bin/venom")
			// Launch the repo server as a transient systemd unit. A plain
			// "setsid python3 ... & sleep 3" keeps the SSH channel's stdout open
			// and ssh never returns EOF, so the run() call would block until QEMU
			// is killed. systemd-run fully detaches the process into its own unit,
			// so ssh returns immediately. The unit serves /repo/public live, so a
			// later re-push of that dir updates the served bytes without a restart.
			mustRun(t, ctx, bg, "systemd-run --unit=polypkg-http --quiet --working-directory=/repo/public python3 -m http.server 8080 && sleep 2")

			mustRun(t, ctx, bg, "mkdir -p /e2e/confine")
			switch g.name {
			case "centos":
				mustPush(t, ctx, bg, filepath.Join(binDir, "polypkg_consumer.pp"), "/e2e/confine/polypkg_consumer.pp")
			case "ubuntu":
				mustPush(t, ctx, bg, "confine/polypkg-consumer.aa", "/e2e/confine/polypkg-consumer.aa")
			}

			out, err := bg.run(ctx, "cd /e2e && venom run --output-dir /e2e/out-install 25-lsm-install.venom.yml")
			t.Logf("install venom:\n%s", out)
			_ = bg.pull(ctx, "/e2e/out-install", filepath.Join(runDir, "venom-install"))
			if err != nil {
				t.Fatalf("install suite failed in %s: %v", name, err)
			}

			assertLabelsClean(t, ctx, bg, g)

			assertConfinement(t, ctx, bg, g)

			if err := publishUpgrade(ctx, polypkgBin, fixtures, runDir); err != nil {
				t.Fatal(err)
			}
			mustRun(t, ctx, bg, "rm -rf /repo/public")
			mustPush(t, ctx, bg, pub, "/repo/public")

			out, err = bg.run(ctx, "cd /e2e && venom run --output-dir /e2e/out-upgrade 26-lsm-upgrade.venom.yml")
			t.Logf("upgrade venom:\n%s", out)
			_ = bg.pull(ctx, "/e2e/out-upgrade", filepath.Join(runDir, "venom-upgrade"))
			if err != nil {
				t.Fatalf("upgrade suite failed in %s: %v", name, err)
			}

			d, derr := bg.run(ctx, g.denialProbe)
			if derr != nil || trimLine(d) != "CLEAN" {
				dump, _ := bg.run(ctx, "ausearch -m AVC -ts boot 2>/dev/null; journalctl -k --no-pager 2>/dev/null | grep -i denied")
				t.Fatalf("LSM denials detected in %s:\n%s", name, dump)
			}
		})
	}
}

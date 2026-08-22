package vm

import (
	"regexp"
	"strings"
	"testing"
)

// guest describes a distro target for the LSM tier. Values were confirmed by
// the feasibility spike on this host.
//
// These descriptors live in an untagged file so the pin invariant below is
// enforced by the ordinary `task test` run. Gating them behind `//go:build vm`
// would mean only a host with QEMU and 40 minutes to spare could catch a
// regression in the image pins.
type guest struct {
	name        string // "centos" | "ubuntu"
	imageFile   string // basename under VM_IMAGE_DIR
	imageURL    string // download source — must name an immutable dated compose
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

// imageURL MUST address a dated compose, never a rolling alias
// ("…-latest.x86_64.qcow2", ".../releases/24.04/release/"). Upstream republishes
// those aliases in place, so any imageSHA256 pinned against one goes stale the
// next time the distro composes an image — see TestGuestImagesPinToDatedCompose.
//
// To refresh a pin: pick a newer compose from the index, take its published sum
// from the sibling .SHA256SUM / SHA256SUMS file, and update both fields together.
//   - https://cloud.centos.org/centos/10-stream/x86_64/images/
//   - https://cloud-images.ubuntu.com/releases/24.04/
var guests = map[string]guest{
	"centos": {
		name:         "centos",
		imageFile:    "centos.qcow2",
		imageURL:     "https://cloud.centos.org/centos/10-stream/x86_64/images/CentOS-Stream-GenericCloud-10-20260818.0.x86_64.qcow2",
		imageSHA256:  "578ef6128c978ceaa1f30c808ba0184275dbcc2fc22bda047b16ccba0a7f500b", // DevSkim: ignore DS173237 - public CentOS cloud image SHA-256 pin (supply-chain integrity), not a secret
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
		imageURL:     "https://cloud-images.ubuntu.com/releases/24.04/release-20260814/ubuntu-24.04-server-cloudimg-amd64.img",
		imageSHA256:  "6e40c07ae715f744f84af0bec76415cc1987dd115b4b8de437818561f01a3733", // DevSkim: ignore DS173237 - public Ubuntu cloud image SHA-256 pin (supply-chain integrity), not a secret
		seedFile:     "ubuntu-user-data.yaml",
		loginUser:    "root",
		sshPort:      2208,
		enforceProbe: `aa-enabled >/dev/null 2>&1 && echo OK`,
		// Exclude our own deliberate confinement negative-control denials
		// (profile=polypkg_consumer_narrow); the gate still catches any real one.
		denialProbe: `! journalctl -k --no-pager 2>/dev/null | grep 'apparmor=.DENIED' | grep -v polypkg_consumer | grep -q . && echo CLEAN`,
	},
}

// datedCompose matches the YYYYMMDD stamp both distros embed in an immutable
// compose path: CentOS as "…-GenericCloud-10-20260818.0…", Ubuntu as
// "…/releases/24.04/release-20260814/…". Rolling aliases carry no such stamp.
var datedCompose = regexp.MustCompile(`\d{8}`)

// TestGuestImagesPinToDatedCompose guards the pairing that broke the tier once:
// a fixed imageSHA256 pinned against a rolling "-latest" URL. That combination
// cannot hold — upstream republishes the alias over a new compose and every run
// then fails checksum verification against an image nobody chose. A pinned sum
// is only meaningful when the URL it guards is immutable.
func TestGuestImagesPinToDatedCompose(t *testing.T) {
	for name, g := range guests {
		t.Run(name, func(t *testing.T) {
			if g.imageSHA256 == "" {
				t.Skip("unpinned guest (first bring-up); nothing to keep immutable")
			}
			if !datedCompose.MatchString(g.imageURL) {
				t.Errorf("imageURL has no YYYYMMDD compose stamp, so it is a rolling alias "+
					"that upstream will republish over: %s\npin it to a dated compose instead", g.imageURL)
			}
			// "-latest" and a bare "/release/" segment are the two aliases that
			// actually bit us; name them explicitly so the failure is obvious.
			for _, alias := range []string{"-latest.", "/release/", "/current/"} {
				if strings.Contains(g.imageURL, alias) {
					t.Errorf("imageURL contains rolling alias %q: %s", alias, g.imageURL)
				}
			}
		})
	}
}

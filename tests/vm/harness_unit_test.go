package vm

import (
	"slices"
	"strings"
	"testing"
)

func TestAccelSelectsTCGWithoutKVM(t *testing.T) {
	if got := accelFor("/nonexistent/kvm"); got != "tcg" {
		t.Fatalf("accelFor(absent) = %q, want tcg", got)
	}
	if got := accelFor("/dev/null"); got != "kvm" { // /dev/null exists → kvm branch
		t.Fatalf("accelFor(present) = %q, want kvm", got)
	}
}

func TestQemuParamsContainHostfwdAccelAndCPU(t *testing.T) {
	p := qemuParams("tcg", 2222, "/run/seed.iso")
	joined := strings.Join(p, " ")
	if !slices.Contains(p, "tcg") {
		t.Fatalf("params missing tcg accel: %v", p)
	}
	// -cpu max is mandatory for EL10 (x86-64-v3) guests; see spike findings.
	if !slices.Contains(p, "max") {
		t.Fatalf("params missing -cpu max: %v", p)
	}
	if !strings.Contains(joined, "hostfwd=tcp:127.0.0.1:2222-:22") {
		t.Fatalf("params missing hostfwd for port 2222: %v", p)
	}
	if !strings.Contains(joined, "file=/run/seed.iso,media=cdrom") {
		t.Fatalf("params missing seed cdrom drive: %v", p)
	}
}

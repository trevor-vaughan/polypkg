package action

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// plantEscape builds a scope whose directory contains a symlink "evil" pointing
// to an outside directory — simulating a symlink planted by an earlier action.
// Any later action that traverses "evil" must refuse to escape the scope.
func plantEscape() (scope Scope, outside string) {
	dir := GinkgoT().TempDir()
	scope = Scope{
		ActiveRoot:  filepath.Join(dir, "active"),
		PackageName: "hello",
		PackageRoot: filepath.Join(dir, "pkg"),
	}
	pkgScope := filepath.Join(scope.ActiveRoot, scope.PackageName)
	Expect(os.MkdirAll(pkgScope, 0o755)).To(Succeed())
	Expect(os.MkdirAll(scope.PackageRoot, 0o755)).To(Succeed())
	outside = filepath.Join(dir, "outside")
	Expect(os.MkdirAll(outside, 0o755)).To(Succeed())
	Expect(os.Symlink(outside, filepath.Join(pkgScope, "evil"))).To(Succeed())
	return scope, outside
}

var _ = Describe("Action path confinement", func() {
	It("Dir refuses to mkdir through an escaping symlink", func() {
		scope, outside := plantEscape()
		target := filepath.Join(scope.ActiveRoot, scope.PackageName, "evil", "sub")

		inv := Invocation{Action: "dir", Params: map[string]any{"path": target, "mode": "0o755"}}
		_, err := Dir(inv, scope)
		Expect(err).To(HaveOccurred(), "dir must refuse to mkdir through an escaping symlink")

		_, statErr := os.Stat(filepath.Join(outside, "sub"))
		Expect(statErr).To(HaveOccurred(), "nothing may be created outside the scope")
	})

	It("Perms refuses to chmod through an escaping symlink", func() {
		scope, outside := plantEscape()
		secret := filepath.Join(outside, "secret")
		Expect(os.WriteFile(secret, []byte("x"), 0o600)).To(Succeed())
		target := filepath.Join(scope.ActiveRoot, scope.PackageName, "evil", "secret")

		inv := Invocation{Action: "perms", Params: map[string]any{"path": target, "mode": "0o777"}}
		_, err := Perms(inv, scope)
		Expect(err).To(HaveOccurred(), "perms must refuse to chmod through an escaping symlink")

		info, statErr := os.Stat(secret)
		Expect(statErr).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o600)), "outside file mode must be unchanged")
	})

	It("Symlink refuses to place a link through an escaping symlink", func() {
		scope, outside := plantEscape()
		dest := filepath.Join(scope.ActiveRoot, scope.PackageName, "evil", "link")

		inv := Invocation{Action: "symlink", Params: map[string]any{"src": "/whatever", "dest": dest}}
		_, err := Symlink(inv, scope)
		Expect(err).To(HaveOccurred(), "symlink must refuse to place a link through an escaping symlink")

		_, statErr := os.Lstat(filepath.Join(outside, "link"))
		Expect(statErr).To(HaveOccurred(), "no link may be placed outside the scope")
	})

	It("Install refuses to place through an escaping symlink", func() {
		scope, outside := plantEscape()
		src := filepath.Join(scope.PackageRoot, "f")
		Expect(os.WriteFile(src, []byte("data"), 0o644)).To(Succeed())
		dest := filepath.Join(scope.ActiveRoot, scope.PackageName, "evil", "x")

		inv := Invocation{Action: "install", Params: map[string]any{"src": src, "dest": dest, "policy": "symlink"}}
		_, err := Install(inv, scope)
		Expect(err).To(HaveOccurred(), "install must refuse to place through an escaping symlink")

		_, statErr := os.Lstat(filepath.Join(outside, "x"))
		Expect(statErr).To(HaveOccurred(), "nothing may be placed outside the scope")
	})

	It("Install (hardlink) refuses to place through an escaping symlink", func() {
		// The hardlink policy is the one file-placing path that creates its target
		// via an absolute-path os.Link rather than an os.Root operation; its
		// confinement relies on the preceding destRoot.MkdirAll refusing to
		// traverse the planted symlink. Guard that path explicitly.
		scope, outside := plantEscape()
		src := filepath.Join(scope.PackageRoot, "f")
		Expect(os.WriteFile(src, []byte("data"), 0o644)).To(Succeed())
		dest := filepath.Join(scope.ActiveRoot, scope.PackageName, "evil", "x")

		inv := Invocation{Action: "install", Params: map[string]any{"src": src, "dest": dest, "policy": "hardlink"}}
		_, err := Install(inv, scope)
		Expect(err).To(HaveOccurred(), "install hardlink must refuse to place through an escaping symlink")

		_, statErr := os.Lstat(filepath.Join(outside, "x"))
		Expect(statErr).To(HaveOccurred(), "no hardlink may be placed outside the scope")
	})
})

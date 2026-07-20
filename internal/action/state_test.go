package action

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("State", func() {
	newScope := func() (Scope, string) {
		dir := GinkgoT().TempDir()
		scope := Scope{
			ActiveRoot:  filepath.Join(dir, "active"),
			StateRoot:   filepath.Join(dir, "state"),
			PackageName: "hello",
		}
		dest := filepath.Join(scope.ActiveRoot, "hello", "var", "lib", "app")
		return scope, dest
	}

	It("creates the stable dir and an active-tree symlink pointing at it", func() {
		scope, dest := newScope()
		inv := Invocation{Action: "state", PackageName: "hello", Phase: PhasePostPlace,
			Params: map[string]any{"path": dest}}
		res, err := State(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Expected.FileType).To(Equal("state"))
		Expect(res.DriftPolicy).To(Equal("state"))

		stable := filepath.Join(scope.StateRoot, "hello", "var", "lib", "app")
		info, err := os.Stat(stable)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.IsDir()).To(BeTrue())

		target, err := os.Readlink(dest)
		Expect(err).NotTo(HaveOccurred())
		Expect(target).To(Equal(stable))
		Expect(res.Expected.Target).To(Equal(stable))
	})

	It("never touches existing stable contents and is idempotent", func() {
		scope, dest := newScope()
		inv := Invocation{Action: "state", PackageName: "hello", Phase: PhasePostPlace,
			Params: map[string]any{"path": dest}}
		_, err := State(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		stable := filepath.Join(scope.StateRoot, "hello", "var", "lib", "app")
		Expect(os.WriteFile(filepath.Join(stable, "db"), []byte("data"), 0o600)).To(Succeed())

		_, err = State(inv, scope) // re-apply
		Expect(err).NotTo(HaveOccurred())
		got, err := os.ReadFile(filepath.Join(stable, "db"))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(got)).To(Equal("data"))
	})

	It("treats state as a file-placing action", func() {
		Expect(IsFilePlacing("state")).To(BeTrue())
	})

	It("rejects a missing path param", func() {
		_, err := State(Invocation{Action: "state", Params: map[string]any{}}, Scope{StateRoot: "/x"})
		Expect(err).To(MatchError(ContainSubstring("missing required param 'path'")))
	})

	It("rejects an empty StateRoot", func() {
		scope, dest := newScope()
		scope.StateRoot = ""
		_, err := State(Invocation{Action: "state", PackageName: "hello", Params: map[string]any{"path": dest}}, scope)
		Expect(err).To(MatchError(ContainSubstring("state root")))
	})

	It("rejects a path outside the package scope", func() {
		scope, _ := newScope()
		_, err := State(Invocation{Action: "state", PackageName: "hello",
			Params: map[string]any{"path": filepath.Join(scope.ActiveRoot, "other", "f")}}, scope)
		Expect(err).To(MatchError(ContainSubstring("outside")))
	})
})

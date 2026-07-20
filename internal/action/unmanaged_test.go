package action

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Unmanaged", func() {
	It("records a ghost ownership entry and creates nothing on disk", func() {
		dir := GinkgoT().TempDir()
		scope := Scope{ActiveRoot: filepath.Join(dir, "active"), PackageName: "hello"}
		dest := filepath.Join(scope.ActiveRoot, "hello", "var", "run", "app.sock")
		inv := Invocation{Action: "unmanaged", PackageName: "hello", Phase: PhasePostPlace,
			Params: map[string]any{"path": dest}}
		res, err := Unmanaged(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Outcome).To(Equal("ok"))
		Expect(res.Expected.FileType).To(Equal("ghost"))
		Expect(res.Expected.ContentHash).To(BeEmpty())
		Expect(res.DriftPolicy).To(Equal("unmanaged"))
		_, statErr := os.Lstat(dest)
		Expect(os.IsNotExist(statErr)).To(BeTrue())
	})

	It("treats unmanaged as a file-placing action", func() {
		Expect(IsFilePlacing("unmanaged")).To(BeTrue())
	})

	It("rejects a missing path param", func() {
		_, err := Unmanaged(Invocation{Action: "unmanaged", Params: map[string]any{}}, Scope{})
		Expect(err).To(MatchError(ContainSubstring("missing required param 'path'")))
	})

	It("rejects a path outside the package scope", func() {
		dir := GinkgoT().TempDir()
		scope := Scope{ActiveRoot: filepath.Join(dir, "active"), PackageName: "hello"}
		inv := Invocation{Action: "unmanaged", PackageName: "hello",
			Params: map[string]any{"path": filepath.Join(scope.ActiveRoot, "other", "f")}}
		_, err := Unmanaged(inv, scope)
		Expect(err).To(MatchError(ContainSubstring("outside")))
	})
})

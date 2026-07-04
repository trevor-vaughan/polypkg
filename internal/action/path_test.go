package action

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Path", func() {
	newScope := func() (Scope, string) {
		dir := GinkgoT().TempDir()
		scope := Scope{ActiveRoot: filepath.Join(dir, "active"), PackageName: "hello"}
		source := filepath.Join(scope.ActiveRoot, "hello", "bin", "hello")
		return scope, source
	}

	It("creates a shared bin symlink pointing at the package's own binary", func() {
		scope, source := newScope()
		inv := Invocation{Action: "path", PackageName: "hello", Phase: PhasePostPlace,
			Params: map[string]any{"name": "hello", "source": source}}
		res, err := Path(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Outcome).To(Equal("ok"))
		Expect(res.Path).To(Equal(filepath.Join(scope.ActiveRoot, "bin", "hello")))
		Expect(res.Expected.FileType).To(Equal("symlink"))
		Expect(res.Expected.Target).To(Equal(source))

		link := filepath.Join(scope.ActiveRoot, "bin", "hello")
		target, err := os.Readlink(link)
		Expect(err).NotTo(HaveOccurred())
		Expect(target).To(Equal(source))
	})

	It("is a file-placing action", func() {
		Expect(IsFilePlacing("path")).To(BeTrue())
	})

	It("is idempotent on re-apply", func() {
		scope, source := newScope()
		inv := Invocation{Action: "path", PackageName: "hello",
			Params: map[string]any{"name": "hello", "source": source}}
		_, err := Path(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		_, err = Path(inv, scope)
		Expect(err).NotTo(HaveOccurred())
	})

	It("rejects an invalid name", func() {
		scope, source := newScope()
		for _, bad := range []string{"", "a/b", "..", ".", "a b", "/x"} {
			_, err := Path(Invocation{Action: "path", PackageName: "hello",
				Params: map[string]any{"name": bad, "source": source}}, scope)
			Expect(err).To(MatchError(ContainSubstring("name")), "name %q", bad)
		}
	})

	It("rejects a missing source", func() {
		scope, _ := newScope()
		_, err := Path(Invocation{Action: "path", PackageName: "hello",
			Params: map[string]any{"name": "hello"}}, scope)
		Expect(err).To(MatchError(ContainSubstring("source")))
	})

	It("rejects a source outside the package namespace", func() {
		scope, _ := newScope()
		outside := filepath.Join(scope.ActiveRoot, "other", "bin", "hello")
		_, err := Path(Invocation{Action: "path", PackageName: "hello",
			Params: map[string]any{"name": "hello", "source": outside}}, scope)
		Expect(err).To(MatchError(ContainSubstring("outside")))
	})
})

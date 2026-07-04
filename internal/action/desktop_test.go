package action

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Desktop", func() {
	newScope := func() (Scope, string) {
		dir := GinkgoT().TempDir()
		scope := Scope{ActiveRoot: filepath.Join(dir, "active"), PackageName: "tool"}
		source := filepath.Join(scope.ActiveRoot, "tool", "share", "org.foo.Bar.desktop")
		return scope, source
	}

	It("installs a .desktop symlink at applications/<basename>", func() {
		scope, source := newScope()
		inv := Invocation{Action: "desktop", PackageName: "tool", Phase: PhasePostPlace,
			Params: map[string]any{"source": source}}
		res, err := Desktop(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Outcome).To(Equal("ok"))
		Expect(res.Path).To(Equal(filepath.Join(scope.ActiveRoot, "applications", "org.foo.Bar.desktop")))
		Expect(res.Expected.FileType).To(Equal("symlink"))
		Expect(res.Expected.Target).To(Equal(source))
		tgt, err := os.Readlink(res.Path)
		Expect(err).NotTo(HaveOccurred())
		Expect(tgt).To(Equal(source))
	})

	It("is a file-placing action", func() {
		Expect(IsFilePlacing("desktop")).To(BeTrue())
	})

	It("rejects a source whose basename is not <id>.desktop", func() {
		scope, _ := newScope()
		bad := filepath.Join(scope.ActiveRoot, "tool", "share", "foo.txt")
		_, err := Desktop(Invocation{Action: "desktop", PackageName: "tool",
			Params: map[string]any{"source": bad}}, scope)
		Expect(err).To(MatchError(ContainSubstring("source basename")))
	})

	It("rejects a bare .desktop basename (empty id)", func() {
		scope, _ := newScope()
		bad := filepath.Join(scope.ActiveRoot, "tool", "share", ".desktop")
		_, err := Desktop(Invocation{Action: "desktop", PackageName: "tool",
			Params: map[string]any{"source": bad}}, scope)
		Expect(err).To(MatchError(ContainSubstring("source basename")))
	})

	It("rejects a missing source", func() {
		scope, _ := newScope()
		_, err := Desktop(Invocation{Action: "desktop", PackageName: "tool",
			Params: map[string]any{}}, scope)
		Expect(err).To(MatchError(ContainSubstring("required")))
	})

	It("rejects a source outside the package scope", func() {
		scope, _ := newScope()
		_, err := Desktop(Invocation{Action: "desktop", PackageName: "tool",
			Params: map[string]any{"source": "/etc/foo.desktop"}}, scope)
		Expect(err).To(MatchError(ContainSubstring("outside")))
	})

	It("rejects malformed .desktop basenames", func() {
		scope, _ := newScope()
		base := filepath.Join(scope.ActiveRoot, "tool", "share") // in-scope parent dir
		for _, fname := range []string{
			"foo.txt",     // no .desktop suffix
			".desktop",    // empty id
			"..desktop",   // id "." -> rejected by leading-alnum anchor
			"a b.desktop", // interior space
			"foo.Desktop", // wrong-case suffix (not stripped -> stem==base)
			"_x.desktop",  // leading underscore not allowed by the grammar
		} {
			_, err := Desktop(Invocation{Action: "desktop", PackageName: "tool",
				Params: map[string]any{"source": filepath.Join(base, fname)}}, scope)
			Expect(err).To(MatchError(ContainSubstring("source basename")), "fname=%s", fname)
		}
	})

	It("is idempotent on re-apply", func() {
		scope, source := newScope()
		inv := Invocation{Action: "desktop", PackageName: "tool",
			Params: map[string]any{"source": source}}
		_, err := Desktop(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		res, err := Desktop(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		tgt, err := os.Readlink(res.Path)
		Expect(err).NotTo(HaveOccurred())
		Expect(tgt).To(Equal(source))
	})
})

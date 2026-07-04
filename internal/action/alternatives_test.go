package action

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Alternatives", func() {
	newScope := func() (Scope, string, string) {
		dir := GinkgoT().TempDir()
		active := filepath.Join(dir, "active")
		altRoot := filepath.Join(dir, "alternatives")
		scope := Scope{ActiveRoot: active, AltRoot: altRoot, PackageName: "neovim"}
		source := filepath.Join(active, "neovim", "bin", "nvim")
		return scope, source, altRoot
	}

	It("creates the constant consumer link bin/<name> -> altRoot/<name>", func() {
		scope, source, altRoot := newScope()
		res, err := Alternatives(Invocation{Action: "alternatives", PackageName: "neovim",
			Params: map[string]any{"name": "editor", "source": source, "priority": 30}}, scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Outcome).To(Equal("ok"))
		Expect(res.Path).To(Equal(filepath.Join(scope.ActiveRoot, "bin", "editor")))
		Expect(res.Expected.FileType).To(Equal("symlink"))
		Expect(res.Expected.Target).To(Equal(source))
		Expect(res.Expected.Priority).To(Equal(30))

		link := filepath.Join(scope.ActiveRoot, "bin", "editor")
		target, rerr := os.Readlink(link)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(target).To(Equal(filepath.Join(altRoot, "editor")))
	})

	It("is a file-placing action", func() {
		Expect(IsFilePlacing("alternatives")).To(BeTrue())
	})

	It("is idempotent on re-apply", func() {
		scope, source, _ := newScope()
		inv := Invocation{Action: "alternatives", PackageName: "neovim",
			Params: map[string]any{"name": "editor", "source": source, "priority": 30}}
		_, err := Alternatives(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		_, err = Alternatives(inv, scope)
		Expect(err).NotTo(HaveOccurred())
	})

	It("rejects an invalid name", func() {
		scope, source, _ := newScope()
		for _, bad := range []string{"", "a/b", "..", ".", "a b", "/x"} {
			_, err := Alternatives(Invocation{Action: "alternatives", PackageName: "neovim",
				Params: map[string]any{"name": bad, "source": source, "priority": 1}}, scope)
			Expect(err).To(MatchError(ContainSubstring("name")), "name %q", bad)
		}
	})

	It("rejects a missing source", func() {
		scope, _, _ := newScope()
		_, err := Alternatives(Invocation{Action: "alternatives", PackageName: "neovim",
			Params: map[string]any{"name": "editor", "priority": 1}}, scope)
		Expect(err).To(MatchError(ContainSubstring("source")))
	})

	It("rejects a source outside the package namespace", func() {
		scope, _, _ := newScope()
		outside := filepath.Join(scope.ActiveRoot, "other", "bin", "nvim")
		_, err := Alternatives(Invocation{Action: "alternatives", PackageName: "neovim",
			Params: map[string]any{"name": "editor", "source": outside, "priority": 1}}, scope)
		Expect(err).To(MatchError(ContainSubstring("outside")))
	})

	It("rejects a missing priority", func() {
		scope, source, _ := newScope()
		_, err := Alternatives(Invocation{Action: "alternatives", PackageName: "neovim",
			Params: map[string]any{"name": "editor", "source": source}}, scope)
		Expect(err).To(MatchError(ContainSubstring("priority")))
	})

	It("rejects a non-integer priority", func() {
		scope, source, _ := newScope()
		_, err := Alternatives(Invocation{Action: "alternatives", PackageName: "neovim",
			Params: map[string]any{"name": "editor", "source": source, "priority": "abc"}}, scope)
		Expect(err).To(MatchError(ContainSubstring("priority")))
	})

	It("accepts a numeric-string priority (the Starlark-resolved param form)", func() {
		scope, source, _ := newScope()
		res, err := Alternatives(Invocation{Action: "alternatives", PackageName: "neovim",
			Params: map[string]any{"name": "editor", "source": source, "priority": "30"}}, scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Expected.Priority).To(Equal(30))
	})

	It("accepts a priority of 0 as a valid lowest tier", func() {
		scope, source, _ := newScope()
		res, err := Alternatives(Invocation{Action: "alternatives", PackageName: "neovim",
			Params: map[string]any{"name": "editor", "source": source, "priority": 0}}, scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Expected.Priority).To(Equal(0))
	})

	It("places a man follower consumer link pointing at the .followers middle area", func() {
		scope, source, altRoot := newScope()
		res, err := Alternatives(Invocation{Action: "alternatives", PackageName: "neovim",
			Params: map[string]any{"master": "editor", "link": "man/man1/editor.1", "source": source}}, scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Outcome).To(Equal("ok"))
		Expect(res.Path).To(Equal(filepath.Join(scope.ActiveRoot, "man", "man1", "editor.1")))
		Expect(res.Expected.Master).To(Equal("editor"))
		Expect(res.Expected.Target).To(Equal(source))
		Expect(res.Expected.Priority).To(BeZero())
		tgt, rerr := os.Readlink(filepath.Join(scope.ActiveRoot, "man", "man1", "editor.1"))
		Expect(rerr).NotTo(HaveOccurred())
		Expect(tgt).To(Equal(filepath.Join(altRoot, ".followers", "man", "man1", "editor.1")))
	})

	It("places a bin follower consumer link", func() {
		scope, source, altRoot := newScope()
		res, err := Alternatives(Invocation{Action: "alternatives", PackageName: "neovim",
			Params: map[string]any{"master": "editor", "link": "bin/vi", "source": source}}, scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Path).To(Equal(filepath.Join(scope.ActiveRoot, "bin", "vi")))
		tgt, _ := os.Readlink(filepath.Join(scope.ActiveRoot, "bin", "vi"))
		Expect(tgt).To(Equal(filepath.Join(altRoot, ".followers", "bin", "vi")))
	})

	It("rejects a follower link outside bin/ and man/", func() {
		scope, source, _ := newScope()
		_, err := Alternatives(Invocation{Action: "alternatives",
			Params: map[string]any{"master": "editor", "link": "completions/vi", "source": source}}, scope)
		Expect(err).To(MatchError(ContainSubstring("link")))
	})

	It("rejects a follower link that escapes via ..", func() {
		scope, source, _ := newScope()
		_, err := Alternatives(Invocation{Action: "alternatives",
			Params: map[string]any{"master": "editor", "link": "man/../../etc/passwd", "source": source}}, scope)
		Expect(err).To(MatchError(ContainSubstring("link")))
	})

	It("rejects a single-component follower link", func() {
		scope, source, _ := newScope()
		_, err := Alternatives(Invocation{Action: "alternatives",
			Params: map[string]any{"master": "editor", "link": "bin", "source": source}}, scope)
		Expect(err).To(MatchError(ContainSubstring("link")))
	})

	It("rejects a nested bin follower link (the bridge exposes only flat bin/<name>)", func() {
		scope, source, _ := newScope()
		_, err := Alternatives(Invocation{Action: "alternatives",
			Params: map[string]any{"master": "editor", "link": "bin/sub/vi", "source": source}}, scope)
		Expect(err).To(MatchError(ContainSubstring("link")))
	})

	It("allows a sectioned man follower link (man pages live under man/man<N>/)", func() {
		scope, source, _ := newScope()
		res, err := Alternatives(Invocation{Action: "alternatives", PackageName: "neovim",
			Params: map[string]any{"master": "editor", "link": "man/man5/editor.5", "source": source}}, scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Path).To(Equal(filepath.Join(scope.ActiveRoot, "man", "man5", "editor.5")))
	})

	It("rejects a follower with name supplied", func() {
		scope, source, _ := newScope()
		_, err := Alternatives(Invocation{Action: "alternatives",
			Params: map[string]any{"master": "editor", "link": "bin/vi", "source": source, "name": "editor"}}, scope)
		Expect(err).To(MatchError(ContainSubstring("name")))
	})

	It("rejects a follower with priority supplied", func() {
		scope, source, _ := newScope()
		_, err := Alternatives(Invocation{Action: "alternatives",
			Params: map[string]any{"master": "editor", "link": "bin/vi", "source": source, "priority": 10}}, scope)
		Expect(err).To(MatchError(ContainSubstring("priority")))
	})

	It("rejects a follower source outside the package namespace", func() {
		scope, _, _ := newScope()
		outside := filepath.Join(scope.ActiveRoot, "other", "bin", "nvim")
		_, err := Alternatives(Invocation{Action: "alternatives",
			Params: map[string]any{"master": "editor", "link": "bin/vi", "source": outside}}, scope)
		Expect(err).To(MatchError(ContainSubstring("scope")))
	})

	It("rejects an invalid master", func() {
		scope, source, _ := newScope()
		_, err := Alternatives(Invocation{Action: "alternatives",
			Params: map[string]any{"master": "bad/name", "link": "bin/vi", "source": source}}, scope)
		Expect(err).To(MatchError(ContainSubstring("master")))
	})
})

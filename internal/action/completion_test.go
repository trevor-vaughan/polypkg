package action

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Completion", func() {
	newScope := func() (Scope, string) {
		dir := GinkgoT().TempDir()
		scope := Scope{ActiveRoot: filepath.Join(dir, "active"), PackageName: "ripgrep"}
		source := filepath.Join(scope.ActiveRoot, "ripgrep", "comp", "rg.bash")
		return scope, source
	}

	It("places a bash completion symlink at completions/bash/<name>", func() {
		scope, source := newScope()
		inv := Invocation{Action: "completion", PackageName: "ripgrep", Phase: PhasePostPlace,
			Params: map[string]any{"shell": "bash", "name": "rg", "source": source}}
		res, err := Completion(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(res.Outcome).To(Equal("ok"))
		Expect(res.Path).To(Equal(filepath.Join(scope.ActiveRoot, "completions", "bash", "rg")))
		Expect(res.Expected.FileType).To(Equal("symlink"))
		Expect(res.Expected.Target).To(Equal(source))
		tgt, err := os.Readlink(res.Path)
		Expect(err).NotTo(HaveOccurred())
		Expect(tgt).To(Equal(source))
	})

	It("maps zsh to _<name> and fish to <name>.fish", func() {
		scope, source := newScope()
		zsh, err := Completion(Invocation{Action: "completion", PackageName: "ripgrep",
			Params: map[string]any{"shell": "zsh", "name": "rg", "source": source}}, scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(zsh.Path).To(Equal(filepath.Join(scope.ActiveRoot, "completions", "zsh", "_rg")))
		ztgt, err := os.Readlink(zsh.Path)
		Expect(err).NotTo(HaveOccurred())
		Expect(ztgt).To(Equal(source))
		fish, err := Completion(Invocation{Action: "completion", PackageName: "ripgrep",
			Params: map[string]any{"shell": "fish", "name": "rg", "source": source}}, scope)
		Expect(err).NotTo(HaveOccurred())
		Expect(fish.Path).To(Equal(filepath.Join(scope.ActiveRoot, "completions", "fish", "rg.fish")))
		ftgt, err := os.Readlink(fish.Path)
		Expect(err).NotTo(HaveOccurred())
		Expect(ftgt).To(Equal(source))
	})

	It("is a file-placing action", func() {
		Expect(IsFilePlacing("completion")).To(BeTrue())
	})

	It("rejects an unknown shell", func() {
		scope, source := newScope()
		_, err := Completion(Invocation{Action: "completion", PackageName: "ripgrep",
			Params: map[string]any{"shell": "tcsh", "name": "rg", "source": source}}, scope)
		Expect(err).To(HaveOccurred())
	})

	It("rejects a missing or invalid name", func() {
		scope, source := newScope()
		_, err := Completion(Invocation{Action: "completion", PackageName: "ripgrep",
			Params: map[string]any{"shell": "bash", "source": source}}, scope)
		Expect(err).To(HaveOccurred())
		_, err = Completion(Invocation{Action: "completion", PackageName: "ripgrep",
			Params: map[string]any{"shell": "bash", "name": "a/b", "source": source}}, scope)
		Expect(err).To(HaveOccurred())
	})

	It("rejects a source outside the package scope", func() {
		scope, _ := newScope()
		_, err := Completion(Invocation{Action: "completion", PackageName: "ripgrep",
			Params: map[string]any{"shell": "bash", "name": "rg", "source": "/etc/passwd"}}, scope)
		Expect(err).To(HaveOccurred())
	})

	It("is idempotent on re-apply", func() {
		scope, source := newScope()
		inv := Invocation{Action: "completion", PackageName: "ripgrep",
			Params: map[string]any{"shell": "bash", "name": "rg", "source": source}}
		_, err := Completion(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		res, err := Completion(inv, scope)
		Expect(err).NotTo(HaveOccurred())
		tgt, err := os.Readlink(res.Path)
		Expect(err).NotTo(HaveOccurred())
		Expect(tgt).To(Equal(source))
	})
})

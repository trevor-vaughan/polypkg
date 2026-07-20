package action

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Scope.Allows", func() {
	const activeRoot = "/home/test/.local/share/polypkg/active"

	It("allows paths under the active root for the package", func() {
		scope := Scope{ActiveRoot: activeRoot, PackageName: "hello"}
		Expect(scope.Allows("/home/test/.local/share/polypkg/active/hello/bin/hi")).To(BeTrue())
		Expect(scope.Allows("/home/test/.local/share/polypkg/active/hello/share/data")).To(BeTrue())
	})

	It("rejects paths outside scope", func() {
		scope := Scope{ActiveRoot: activeRoot, PackageName: "hello"}
		Expect(scope.Allows("/usr/bin/hi")).To(BeFalse())
		Expect(scope.Allows("/home/test/.local/share/polypkg/active/other/bin/hi")).To(BeFalse())
	})

	It("rejects traversal", func() {
		scope := Scope{ActiveRoot: activeRoot, PackageName: "hello"}
		Expect(scope.Allows("/home/test/.local/share/polypkg/active/hello/../other/bin/hi")).To(BeFalse())
	})

	It("rejects prefix collision (hello-evil is not inside hello)", func() {
		scope := Scope{ActiveRoot: activeRoot, PackageName: "hello"}
		Expect(scope.Allows("/home/test/.local/share/polypkg/active/hello-evil/bin/hi")).To(BeFalse())
	})
})

var _ = Describe("IsFilePlacing", func() {
	DescribeTable("classifies actions",
		func(action string, want bool) {
			Expect(IsFilePlacing(action)).To(Equal(want))
		},
		Entry("install is file-placing", "install", true),
		Entry("symlink is file-placing", "symlink", true),
		Entry("dir is file-placing", "dir", true),
		Entry("perms is file-placing", "perms", true),
		Entry("service is not file-placing", "service", false),
		Entry("config is file-placing", "config", true),
		Entry("unknown is not file-placing", "unknown", false),
		Entry("empty is not file-placing", "", false),
	)
})

var _ = Describe("IsPreSwapPhase", func() {
	DescribeTable("classifies phases",
		func(phase string, want bool) {
			Expect(IsPreSwapPhase(phase)).To(Equal(want))
		},
		Entry("pre-place is pre-swap", "pre-place", true),
		Entry("post-place is pre-swap", "post-place", true),
		Entry("pre-activate is pre-swap", "pre-activate", true),
		Entry("post-activate is not pre-swap", "post-activate", false),
		Entry("pre-deactivate is not pre-swap", "pre-deactivate", false),
		Entry("post-deactivate is not pre-swap", "post-deactivate", false),
		Entry("bogus is not pre-swap", "bogus", false),
	)
})

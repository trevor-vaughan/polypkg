package paths

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("system host dirs", func() {
	It("returns the /usr/local host-integration paths", func() {
		Expect(SystemBinDir()).To(Equal("/usr/local/bin"))
		Expect(SystemApplicationsDir()).To(Equal("/usr/local/share/applications"))
		Expect(SystemMimePackagesDir()).To(Equal("/usr/local/share/mime/packages"))
		Expect(SystemBashCompletionDir()).To(Equal("/usr/local/share/bash-completion/completions"))
		Expect(SystemZshCompletionDir()).To(Equal("/usr/local/share/zsh/site-functions"))
		Expect(SystemFishCompletionDir()).To(Equal("/usr/local/share/fish/vendor_completions.d"))
	})
})

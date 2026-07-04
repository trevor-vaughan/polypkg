package cli

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("command aliases", func() {
	type aliasCase struct {
		alias   string
		wantCmd string
	}

	cases := []aliasCase{
		{alias: "add", wantCmd: "install"},
		{alias: "rm", wantCmd: "remove"},
		{alias: "uninstall", wantCmd: "remove"},
		{alias: "update", wantCmd: "upgrade"},
		{alias: "ls", wantCmd: "list"},
		{alias: "show", wantCmd: "info"},
	}

	for _, tc := range cases {
		tc := tc
		It("resolves "+tc.alias+" to "+tc.wantCmd, func() {
			root := NewRootCmd()
			found, _, err := root.Find([]string{tc.alias})
			Expect(err).NotTo(HaveOccurred())
			Expect(found).NotTo(BeNil())
			Expect(found.Name()).To(Equal(tc.wantCmd),
				"alias %q should resolve to command %q", tc.alias, tc.wantCmd)
		})
	}
})

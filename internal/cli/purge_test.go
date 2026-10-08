package cli

import (
	"bytes"
	"errors"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("purge command non-interactive error", func() {
	It("returns CLIError when stdin is not a terminal and --yes is absent", func() {
		sandboxUserEnv(GinkgoTB())
		root := NewRootCmd()
		root.SetArgs([]string{"purge", "mypkg"})
		// Use a strings.Reader so isInteractive returns false (not an *os.File).
		root.SetIn(strings.NewReader(""))
		err := root.Execute()
		Expect(err).To(HaveOccurred())
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(cliErr.Msg).To(Equal("purge needs confirmation but stdin is not a terminal"))
		Expect(cliErr.Hint).To(ContainSubstring("--yes"))
	})
})

var _ = Describe("purge", func() {
	It("confirmPurge accepts only y/Y", func() {
		var out bytes.Buffer
		ok, err := confirmPurge(strings.NewReader("y\n"), &out, "hello")
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())
		Expect(out.String()).To(ContainSubstring("hello"))
		ok, _ = confirmPurge(strings.NewReader("n\n"), &bytes.Buffer{}, "hello")
		Expect(ok).To(BeFalse())
	})

	It("refuses to purge a package present in the current generation", func() {
		own := &schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user", Entries: []schema.OwnershipEntry{
			{Path: "hello/var/lib/app", Package: "hello", Action: "state"},
		}}
		err := ensureNotActive(own, "hello")
		Expect(err).To(HaveOccurred())
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError")
		Expect(cliErr.Msg).To(ContainSubstring("still active"))
		Expect(cliErr.Hint).To(ContainSubstring("polypkg apply"))
		Expect(ensureNotActive(own, "other")).To(Succeed())
	})

	It("validPackageName rejects traversal, separators, and empties; accepts normal names", func() {
		for _, ok := range []string{"hello", "my-pkg", "pkg_1", "ABC123"} {
			Expect(validPackageName(ok)).To(BeTrue(), "expected %q to be valid", ok)
		}
		for _, bad := range []string{"", "..", ".", "../x", "a/b", "/etc", "a.b", "a b", "réé"} {
			Expect(validPackageName(bad)).To(BeFalse(), "expected %q to be invalid", bad)
		}
	})
})

package integration

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/cli"
)

var _ = Describe("read-only command on a never-applied substrate", func() {
	polypkgDir := func() string {
		return filepath.Join(os.Getenv("XDG_DATA_HOME"), "polypkg")
	}

	It("does not create any substrate directories", func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		cmd := cli.NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs([]string{"alternatives", "list"})
		// A never-applied substrate must yield exactly the "nothing applied
		// yet" CLIError: any other error means the command failed somewhere
		// else, and the directory checks below would prove nothing.
		var ce *cli.CLIError
		Expect(errors.As(cmd.Execute(), &ce)).To(BeTrue(), "alternatives list: %s", out.String())
		Expect(ce.Msg).To(Equal("no generation has been applied yet"))

		for _, sub := range []string{"store", "generations", "state", "alternatives"} {
			_, statErr := os.Lstat(filepath.Join(polypkgDir(), sub))
			Expect(os.IsNotExist(statErr)).To(BeTrue(),
				"read-only command must not create %s/ on a never-applied substrate (output: %s)", sub, out.String())
		}
	})
})

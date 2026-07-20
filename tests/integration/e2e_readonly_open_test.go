package integration

import (
	"bytes"
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
		// A "no generation has been applied yet" outcome is expected and fine;
		// we assert it did not panic/crash and created no substrate dirs.
		_ = cmd.Execute()

		for _, sub := range []string{"store", "generations", "state", "alternatives"} {
			_, statErr := os.Lstat(filepath.Join(polypkgDir(), sub))
			Expect(os.IsNotExist(statErr)).To(BeTrue(),
				"read-only command must not create %s/ on a never-applied substrate (output: %s)", sub, out.String())
		}
	})
})

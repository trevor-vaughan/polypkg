package cli

import (
	"bytes"
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// runRoot drives the real command tree exactly as cmd/polypkg/main.go does:
// Execute, then RenderError to stderr and ExitCode for the process status.
// Anything cobra itself prints lands in the same two buffers, so the returned
// triple is what a shell would observe.
func runRoot(args ...string) (stdout, stderr string, code int) {
	root := NewRootCmd()
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	root.SetArgs(args)
	err := root.Execute()
	RenderError(&errBuf, err)
	return out.String(), errBuf.String(), ExitCode(err)
}

// commandGroups is every top-level command that exists only to dispatch to
// subcommands. Each must refuse a bare invocation rather than printing help
// and exiting 0.
var commandGroups = []string{
	"alternatives", "attestation", "config", "generation",
	"mirror", "pkg", "repo", "source",
}

var _ = Describe("command groups invoked without a subcommand", func() {
	for _, group := range commandGroups {
		It("exits non-zero with usage on stderr for `polypkg "+group+"`", func() {
			stdout, stderr, code := runRoot(group)

			Expect(code).NotTo(BeZero(), "a bare command group must not report success")
			Expect(stdout).To(BeEmpty(), "help prose must not go to stdout")
			Expect(stderr).NotTo(BeEmpty(), "the failure must be explained on stderr")
			Expect(stderr).To(ContainSubstring("polypkg " + group + " requires a subcommand"))
			Expect(stderr).To(ContainSubstring("polypkg " + group + " --help"))
		})
	}

	It("emits a cli-result error envelope under --format json, not prose", func() {
		stdout, _, code := runRoot("--format", "json", "alternatives")

		Expect(code).NotTo(BeZero())
		var env struct {
			Schema  string `json:"schema"`
			Command string `json:"command"`
			Status  string `json:"status"`
			Error   string `json:"error"`
			Hint    string `json:"hint"`
		}
		Expect(json.Unmarshal([]byte(stdout), &env)).To(Succeed(),
			"stdout must be parseable JSON, got %q", stdout)
		Expect(env.Schema).To(Equal("polypkg.cli-result/v2"))
		Expect(env.Command).To(Equal("alternatives"))
		Expect(env.Status).To(Equal("error"))
		Expect(env.Error).To(Equal("polypkg alternatives requires a subcommand"))
		Expect(env.Hint).NotTo(BeEmpty())
	})

	It("rejects an unknown subcommand of a group instead of printing help", func() {
		stdout, stderr, code := runRoot("repo", "bogus")

		Expect(code).NotTo(BeZero())
		Expect(stdout).To(BeEmpty())
		Expect(stderr).To(ContainSubstring(`unknown repo subcommand "bogus"`))
	})

	It("keeps the group-specific hint for a known group's unknown subcommand", func() {
		_, stderr, code := runRoot("attestation", "zzz")

		Expect(code).NotTo(BeZero())
		Expect(stderr).To(ContainSubstring(`unknown attestation subcommand "zzz"`))
		Expect(stderr).To(ContainSubstring("attestation report"))
	})

	It("leaves an unknown top-level command's behaviour unchanged", func() {
		stdout, stderr, code := runRoot("bogus")

		Expect(code).To(Equal(1))
		Expect(stdout).To(BeEmpty())
		Expect(stderr).To(ContainSubstring(`unknown command "bogus" for "polypkg"`))
	})
})

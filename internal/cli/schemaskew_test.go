package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

var _ = Describe("state written by a newer polypkg", func() {
	var genDir string

	BeforeEach(func() {
		env := sandboxUserEnv(GinkgoTB())
		dataRoot := filepath.Join(env, "data", "polypkg")
		s, err := substrate.New("store", dataRoot)
		Expect(err).NotTo(HaveOccurred())
		Expect(s.BeginTransaction("t1")).To(Succeed())
		_, err = s.CommitGeneration("t1",
			&schema.Manifest{Schema: "polypkg.manifest/v2", Generation: 1, Scope: "user", Entries: []schema.ManifestEntry{}},
			&schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user"}, nil)
		Expect(err).NotTo(HaveOccurred())
		genDir = filepath.Join(dataRoot, "generations", "1")
	})

	run := func(args ...string) (string, error) {
		root := NewRootCmd()
		root.SilenceUsage, root.SilenceErrors = true, true
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&bytes.Buffer{})
		root.SetArgs(args)
		err := root.Execute()
		return out.String(), err
	}

	It("refuses with an upgrade message that names the file", func() {
		ownPath := filepath.Join(genDir, "ownership.json")
		Expect(os.WriteFile(ownPath,
			[]byte(`{"schema":"polypkg.ownership/v2","scope":"user","entries":[],"future":true}`), 0o600)).To(Succeed())

		_, err := run("list")

		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(Equal(ownPath +
			" was written by a newer polypkg (polypkg.ownership/v2; this version reads v1); upgrade polypkg"))
		Expect(ce.Hint).To(ContainSubstring(Version))
		Expect(ce.Hint).To(ContainSubstring("against this state"))
		Expect(ce.Msg).NotTo(ContainSubstring("file://"))
		Expect(ce.Msg).NotTo(ContainSubstring("jsonschema"))
	})

	It("names manifest.json when the manifest is the newer document", func() {
		mPath := filepath.Join(genDir, "manifest.json")
		Expect(os.WriteFile(mPath, []byte(`{"schema":"polypkg.manifest/v3"}`), 0o600)).To(Succeed())

		_, err := run("list")

		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(ce.Msg).To(HavePrefix(mPath + " was written by a newer polypkg (polypkg.manifest/v3; this version reads v2)"))
	})

	It("carries the same message and hint in the JSON error envelope", func() {
		ownPath := filepath.Join(genDir, "ownership.json")
		Expect(os.WriteFile(ownPath, []byte(`{"schema":"polypkg.ownership/v2"}`), 0o600)).To(Succeed())

		out, err := run("--format", "json", "list")

		Expect(err).To(HaveOccurred())
		var env struct {
			Status string `json:"status"`
			Error  string `json:"error"`
			Hint   string `json:"hint"`
		}
		Expect(json.Unmarshal([]byte(out), &env)).To(Succeed(), out)
		Expect(env.Status).To(Equal("error"))
		Expect(env.Error).To(Equal(ownPath +
			" was written by a newer polypkg (polypkg.ownership/v2; this version reads v1); upgrade polypkg"))
		Expect(env.Hint).To(ContainSubstring(Version))
	})

	It("keeps the wrapping context when no file path is known", func() {
		inner := &schema.NewerSchemaError{Found: "polypkg.trust-bundle/v2", Supported: 1}
		cmd := NewRootCmd()
		cmd.SetOut(&bytes.Buffer{})
		err := WrapError(cmd, FormatText, "apply", errors.Join(errors.New(`source "native": fetch trust bundle`), inner))
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Msg).To(ContainSubstring(`source "native": fetch trust bundle`))
		Expect(ce.Msg).To(ContainSubstring("this document was written by a newer polypkg (polypkg.trust-bundle/v2"))
		Expect(ce.Hint).To(ContainSubstring("before using this repository"), "a fetched document is not local state")
		Expect(ce.Hint).NotTo(ContainSubstring("this state"))
	})

	It("names a newer manifest the same way in rollback, pin, gc and the attestation report", func() {
		// These paths wrap manifest read errors themselves; a newer manifest
		// must not come out as a permissions or damage error.
		s, err := substrate.New("store", filepath.Dir(filepath.Dir(genDir)))
		Expect(err).NotTo(HaveOccurred())
		Expect(s.BeginTransaction("t2")).To(Succeed())
		_, err = s.CommitGeneration("t2",
			&schema.Manifest{Schema: "polypkg.manifest/v2", Scope: "user", Entries: []schema.ManifestEntry{}},
			&schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user"}, nil)
		Expect(err).NotTo(HaveOccurred())
		mPath := filepath.Join(genDir, "manifest.json")
		Expect(os.WriteFile(mPath, []byte(`{"schema":"polypkg.manifest/v3"}`), 0o600)).To(Succeed())

		for _, args := range [][]string{
			{"rollback", "--to", "1"},
			{"rollback"},
			{"generation", "pin", "1", "--reason", "keep"},
			{"gc"},
			{"attestation", "report"},
		} {
			_, err := run(args...)
			var ce *CLIError
			Expect(errors.As(err, &ce)).To(BeTrue(), "%v: expected *CLIError, got %T: %v", args, err, err)
			Expect(ce.Msg).To(Equal(mPath+
				" was written by a newer polypkg (polypkg.manifest/v3; this version reads v2); upgrade polypkg"), "%v", args)
			Expect(ce.Hint).To(ContainSubstring(Version), "%v", args)
		}
		Expect(mPath).To(BeAnExistingFile())
	})

	DescribeTable("CLI state readers attach their path",
		func(read func(string) error, name, body string) {
			p := filepath.Join(GinkgoT().TempDir(), name)
			Expect(os.WriteFile(p, []byte(body), 0o600)).To(Succeed())
			var ne *schema.NewerSchemaError
			err := read(p)
			Expect(errors.As(err, &ne)).To(BeTrue(), "got %v", err)
			Expect(ne.Path).To(Equal(p))
		},
		Entry("accepted drift", func(p string) error { _, err := readAcceptedDrift(p); return err },
			"accepted-drift.json", `{"schema":"polypkg.accepted-drift/v2"}`),
		Entry("pending resets", func(p string) error { _, err := readPendingResets(p); return err },
			"pending-resets.json", `{"schema":"polypkg.resets/v2"}`),
	)
})

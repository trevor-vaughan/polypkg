package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// makeConfigGen1State creates minimal generation-1 substrate state with one
// config+notify_preserve entry for package "hello", so tests that need to
// reach past the CurrentOwnership guard can do so without a full apply.
// The ownership entry satisfies the ownership-v1.json schema requirements
// (path, package, version, action, expected, drift_policy, stat are all present).
func makeConfigGen1State(storeRoot string) {
	gen1Dir := filepath.Join(storeRoot, "generations", "1", "active")
	Expect(os.MkdirAll(gen1Dir, 0o700)).To(Succeed())
	activeLink := filepath.Join(storeRoot, "active")
	Expect(os.Symlink(filepath.Join("generations", "1", "active"), activeLink)).To(Succeed())
	own := filepath.Join(storeRoot, "generations", "1", "ownership.json")
	Expect(os.WriteFile(own, []byte(`{
  "schema": "polypkg.ownership/v1",
  "scope": "user",
  "entries": [
    {
      "path": "hello/etc/app.conf",
      "package": "hello",
      "version": "1.0.0",
      "action": "config",
      "expected": {},
      "drift_policy": "notify_preserve",
      "stat": {"size": 0, "mtime_ns": 0, "inode": 0}
    }
  ]
}`), 0o600)).To(Succeed())
}

var _ = Describe("config reset command errors", func() {
	setup := func() {
		dir := GinkgoT().TempDir()
		GinkgoT().Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
		GinkgoT().Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	}

	It("returns CLIError when no path or --package is supplied", func() {
		setup()
		root := NewRootCmd()
		root.SetArgs([]string{"config", "reset"})
		err := root.Execute()
		Expect(err).To(HaveOccurred())
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(cliErr.Msg).To(Equal("config reset needs a target"))
		Expect(cliErr.Hint).To(ContainSubstring("--package"))
	})
})

var _ = Describe("config reset", func() {
	It("confirmReset returns true only for y/Y", func() {
		var out bytes.Buffer
		ok, err := confirmReset(strings.NewReader("y\n"), &out, "/etc/x")
		Expect(err).NotTo(HaveOccurred())
		Expect(ok).To(BeTrue())
		Expect(out.String()).To(ContainSubstring("Reset /etc/x"))

		ok, _ = confirmReset(strings.NewReader("n\n"), &bytes.Buffer{}, "/etc/x")
		Expect(ok).To(BeFalse())
		ok, _ = confirmReset(strings.NewReader("\n"), &bytes.Buffer{}, "/etc/x")
		Expect(ok).To(BeFalse())
	})

	It("validates against a prior ownership index", func() {
		own := &schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user", Entries: []schema.OwnershipEntry{
			{Path: "hello/etc/app.conf", Package: "hello", Action: "config", DriftPolicy: "notify_preserve"},
			{Path: "hello/bin/hi", Package: "hello", Action: "install", DriftPolicy: "notify_heal"},
			{Path: "hello/etc/fixed.conf", Package: "hello", Action: "config", DriftPolicy: "notify_heal"},
		}}
		// config + notify_preserve: ok
		_, err := resolveResetPaths(own, []string{"hello/etc/app.conf"}, "")
		Expect(err).NotTo(HaveOccurred())
		// not a config action
		_, err = resolveResetPaths(own, []string{"hello/bin/hi"}, "")
		Expect(err).To(MatchError(ContainSubstring("not a config action")))
		// config but replace policy (notify_heal)
		_, err = resolveResetPaths(own, []string{"hello/etc/fixed.conf"}, "")
		Expect(err).To(MatchError(ContainSubstring("replace policy")))
		// not found
		_, err = resolveResetPaths(own, []string{"hello/missing"}, "")
		Expect(err).To(MatchError(ContainSubstring("not found")))
		// --package bulk: all config+notify_preserve owned by hello
		paths, err := resolveResetPaths(own, nil, "hello")
		Expect(err).NotTo(HaveOccurred())
		Expect(paths).To(Equal([]string{"hello/etc/app.conf"}))
	})

	It("writePendingResets merges with set semantics and is atomic", func() {
		dir := GinkgoT().TempDir()
		out := filepath.Join(dir, "pending-resets.json")
		Expect(writePendingResets(out, "user", []string{"hello/etc/a.conf"})).To(Succeed())
		Expect(writePendingResets(out, "user", []string{"hello/etc/a.conf", "hello/etc/b.conf"})).To(Succeed())
		f, err := os.Open(out)
		Expect(err).NotTo(HaveOccurred())
		defer f.Close()
		rs, err := schema.ParseResets(f)
		Expect(err).NotTo(HaveOccurred())
		Expect(rs.Paths).To(ConsistOf("hello/etc/a.conf", "hello/etc/b.conf"))
		info, _ := os.Stat(out)
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o600)))
	})
})

var _ = Describe("config reset non-interactive", func() {
	setup := func() (dir, storeRoot string) {
		dir = GinkgoT().TempDir()
		GinkgoT().Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
		GinkgoT().Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
		storeRoot = filepath.Join(dir, "data", "polypkg")
		return dir, storeRoot
	}

	It("returns CLIError when stdin is not a terminal and --yes is absent", func() {
		_, storeRoot := setup()
		makeConfigGen1State(storeRoot)
		root := NewRootCmd()
		root.SetArgs([]string{"config", "reset", "hello/etc/app.conf"})
		// Non-*os.File reader forces isInteractive to return false.
		root.SetIn(strings.NewReader(""))
		err := root.Execute()
		Expect(err).To(HaveOccurred())
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(cliErr.Msg).To(Equal("config reset needs confirmation but stdin is not a terminal"))
		Expect(cliErr.Hint).To(ContainSubstring("--yes"))
	})
})

var _ = Describe("resolveResetPaths CLIErrors", func() {
	It("returns CLIError Msg for a path not in ownership", func() {
		own := &schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user", Entries: []schema.OwnershipEntry{
			{Path: "hello/etc/app.conf", Package: "hello", Action: "config", DriftPolicy: "notify_preserve"},
		}}
		_, err := resolveResetPaths(own, []string{"hello/missing"}, "")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("not found in current generation ownership"))
	})

	It("returns CLIError Msg for a path with a non-config action", func() {
		own := &schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user", Entries: []schema.OwnershipEntry{
			{Path: "hello/bin/hi", Package: "hello", Action: "install", DriftPolicy: "notify_heal"},
		}}
		_, err := resolveResetPaths(own, []string{"hello/bin/hi"}, "")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("not a config action"))
	})
})

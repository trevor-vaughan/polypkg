package integration

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/cli"
)

var _ = Describe("~/.local/bin bridge e2e", func() {
	// binDir returns the isolated bridge target directory, set by IsolatedEnv.
	binDir := func() string { return os.Getenv("XDG_BIN_HOME") }

	// activeBinDir returns the stable active-generation bin dir that bridge
	// symlinks point into (<XDG_DATA_HOME>/polypkg/active/bin).
	activeBinDir := func() string {
		return filepath.Join(os.Getenv("XDG_DATA_HOME"), "polypkg", "active", "bin")
	}

	// All four steps share one IsolatedEnv (same testing.TB → same t.Setenv
	// scope), mirroring the multi-step pattern in e2e_alternatives_select_test.go.
	It("link on apply, prune on removal, foreign-file safety, unlink command", func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		// ----------------------------------------------------------------
		// Build two packages: "tool" exposes command "tool", "other" exposes
		// command "other". We use two distinct packages so the foreign-file
		// collision step (step 3) can pre-create a plain file at binDir/other
		// while "tool" is cleanly linked.
		// ----------------------------------------------------------------
		toolPkg := pkgExposingCmd(t, "tool", "tool")
		otherPkg := pkgExposingCmd(t, "other", "other")

		repoDir := t.TempDir()
		trust1 := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "tool", version: "1.0.0", artifact: toolPkg},
			indexPkg{name: "other", version: "1.0.0", artifact: otherPkg},
		)
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		// ----------------------------------------------------------------
		// Step 1: apply a profile containing "tool". The bridge must create a
		// symlink at binDir/tool -> activeBinDir/tool.
		// ----------------------------------------------------------------
		out, err := applyProfileWith(t, srv.URL, trust1, "tool")
		Expect(err).NotTo(HaveOccurred(), "step1 apply output: %s", out)

		toolLink := filepath.Join(binDir(), "tool")

		// The entry exists and is a symlink.
		fi, statErr := os.Lstat(toolLink)
		Expect(statErr).NotTo(HaveOccurred(), "binDir/tool must exist after apply")
		Expect(fi.Mode()&os.ModeSymlink).To(Equal(os.ModeSymlink), "binDir/tool must be a symlink")

		// The symlink points into the active tree via activeBinDir.
		target, rerr := os.Readlink(toolLink)
		Expect(rerr).NotTo(HaveOccurred())
		Expect(target).To(Equal(filepath.Join(activeBinDir(), "tool")),
			"bridge symlink target must be <activeBinDir>/tool")

		// The full chain resolves end-to-end: binDir/tool → activeBinDir/tool →
		// active/<pkg>/bin/tool → pkg-extract/.../tool. The extract directory
		// lives under XDG_STATE_HOME, not XDG_DATA_HOME, so we assert only that
		// the chain is resolvable and that the final basename is the command name.
		resolved, ferr := filepath.EvalSymlinks(toolLink)
		Expect(ferr).NotTo(HaveOccurred(), "binDir/tool symlink chain must be resolvable")
		Expect(filepath.IsAbs(resolved)).To(BeTrue())
		Expect(filepath.Base(resolved)).To(Equal("tool"),
			"resolved basename must be the command name")

		// ----------------------------------------------------------------
		// Step 2: apply the empty fixture profile so no commands are exposed.
		// The bridge must prune the "tool" link we own; binDir/tool disappears.
		// Using the empty fixture (rather than a profile with "other") ensures
		// no polypkg link is ever created at binDir/other before we plant a
		// foreign file there in step 3. The empty profile has no packages block
		// so the schema validator accepts it; applyProfileWith generates a null
		// user scope when names is empty, which the validator rejects.
		// ----------------------------------------------------------------
		emptyCmd := cli.NewRootCmd()
		emptyCmd.SilenceUsage, emptyCmd.SilenceErrors = true, true
		var emptyOut bytes.Buffer
		emptyCmd.SetOut(&emptyOut)
		emptyCmd.SetErr(&emptyOut)
		emptyCmd.SetArgs([]string{"apply", filepath.Join("..", "fixtures", "profiles", "empty.yaml")})
		err = emptyCmd.Execute()
		out = emptyOut.String()
		Expect(err).NotTo(HaveOccurred(), "step2 apply output: %s", out)

		_, statErr = os.Lstat(toolLink)
		Expect(os.IsNotExist(statErr)).To(BeTrue(),
			"binDir/tool must be pruned after tool is no longer exposed")

		// ----------------------------------------------------------------
		// Step 3: pre-create a FOREIGN plain file at binDir/other, then apply
		// a profile that exposes both "tool" and "other". The bridge must skip
		// (not clobber) the foreign file; apply must still succeed; binDir/tool
		// gets a fresh polypkg link while binDir/other is left untouched.
		// ----------------------------------------------------------------
		otherLink := filepath.Join(binDir(), "other")
		foreignContent := []byte("I am a foreign file, do not touch me\n")

		// Confirm no polypkg symlink exists at binDir/other before we plant the
		// foreign file — os.WriteFile on an existing symlink follows the chain.
		_, preErr := os.Lstat(otherLink)
		Expect(os.IsNotExist(preErr)).To(BeTrue(),
			"binDir/other must not exist yet when we plant the foreign file")
		Expect(os.WriteFile(otherLink, foreignContent, 0o644)).To(Succeed())

		// Re-sign at serial 3 with both packages.
		trust3 := signRepo(t, repoDir, "native", 3,
			indexPkg{name: "tool", version: "1.0.0", artifact: toolPkg},
			indexPkg{name: "other", version: "1.0.0", artifact: otherPkg},
		)
		out, err = applyProfileWith(t, srv.URL, trust3, "tool", "other")
		Expect(err).NotTo(HaveOccurred(), "step3 apply with foreign file must succeed: %s", out)

		// The foreign plain file at binDir/other is completely untouched.
		fi, statErr = os.Lstat(otherLink)
		Expect(statErr).NotTo(HaveOccurred(), "binDir/other must still exist")
		Expect(fi.Mode()&os.ModeSymlink).To(Equal(os.FileMode(0)),
			"binDir/other must remain a plain file, not a symlink")
		got, readErr := os.ReadFile(otherLink)
		Expect(readErr).NotTo(HaveOccurred())
		Expect(got).To(Equal(foreignContent), "foreign file content must be unchanged")

		// The "tool" link (no foreign conflict) was created normally.
		fi, statErr = os.Lstat(toolLink)
		Expect(statErr).NotTo(HaveOccurred(), "binDir/tool must be linked despite foreign conflict on other")
		Expect(fi.Mode() & os.ModeSymlink).To(Equal(os.ModeSymlink))

		// ----------------------------------------------------------------
		// Step 4: run `polypkg unlink`. Our-owned links must be removed; the
		// foreign plain file must survive untouched.
		// ----------------------------------------------------------------
		out, err = runUnlinkInProcess()
		Expect(err).NotTo(HaveOccurred(), "unlink output: %s", out)

		// binDir/tool (our link) is gone.
		_, statErr = os.Lstat(toolLink)
		Expect(os.IsNotExist(statErr)).To(BeTrue(), "binDir/tool must be removed by unlink")

		// binDir/other (foreign plain file) is untouched.
		fi, statErr = os.Lstat(otherLink)
		Expect(statErr).NotTo(HaveOccurred(), "binDir/other must survive unlink")
		Expect(fi.Mode()&os.ModeSymlink).To(Equal(os.FileMode(0)),
			"binDir/other must still be a plain file after unlink")
		got, readErr = os.ReadFile(otherLink)
		Expect(readErr).NotTo(HaveOccurred())
		Expect(got).To(Equal(foreignContent), "foreign file content must be unchanged after unlink")
	})
})

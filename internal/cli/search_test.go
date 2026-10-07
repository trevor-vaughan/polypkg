package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/cobra"

	"github.com/trevor-vaughan/polypkg/internal/lock"
	"github.com/trevor-vaughan/polypkg/internal/planner"
	"github.com/trevor-vaughan/polypkg/internal/repo"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("formatVersionList", func() {
	It("returns single version verbatim", func() {
		Expect(formatVersionList([]string{"1.0.0"})).To(Equal("1.0.0"))
	})

	It("returns up to three versions joined by comma-space", func() {
		Expect(formatVersionList([]string{"1.2.0", "1.1.0", "1.0.0"})).
			To(Equal("1.2.0, 1.1.0, 1.0.0"))
	})

	It("caps at three and appends +N more for five versions", func() {
		versions := []string{"5.0.0", "4.0.0", "3.0.0", "2.0.0", "1.0.0"}
		result := formatVersionList(versions)
		Expect(result).To(Equal("5.0.0, 4.0.0, 3.0.0 (+2 more)"))
	})

	It("caps at three and appends +1 more for four versions", func() {
		versions := []string{"4.0.0", "3.0.0", "2.0.0", "1.0.0"}
		result := formatVersionList(versions)
		Expect(result).To(Equal("4.0.0, 3.0.0, 2.0.0 (+1 more)"))
	})

	It("returns empty string for empty slice", func() {
		Expect(formatVersionList(nil)).To(Equal(""))
	})
})

var _ = Describe("filterNames", func() {
	names := []string{"hello", "world", "help", "go-hello", "HELLO-world"}

	It("returns names containing the term (case-insensitive)", func() {
		result := filterNames(names, "hello")
		Expect(result).To(ConsistOf("hello", "go-hello", "HELLO-world"))
	})

	It("returns all names when term is empty string", func() {
		result := filterNames(names, "")
		Expect(result).To(ConsistOf(names))
	})

	It("returns empty slice when nothing matches", func() {
		result := filterNames(names, "zzz")
		Expect(result).To(BeEmpty())
	})

	It("is case-insensitive for uppercase term", func() {
		result := filterNames(names, "WORLD")
		Expect(result).To(ConsistOf("world", "HELLO-world"))
	})
})

var _ = Describe("search command argument validation", func() {
	setup := func() {
		sandboxUserEnv(GinkgoTB())
	}

	It("returns CLIError when no search term is supplied", func() {
		setup()
		root := NewRootCmd()
		root.SetArgs([]string{"search"})
		err := root.Execute()
		Expect(err).To(HaveOccurred())
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
		Expect(cliErr.Msg).To(ContainSubstring("search"))
		Expect(cliErr.Msg).To(ContainSubstring("<term>"))
	})

	It("returns CLIError when more than one term is supplied", func() {
		setup()
		root := NewRootCmd()
		root.SetArgs([]string{"search", "foo", "bar"})
		err := root.Execute()
		Expect(err).To(HaveOccurred())
		var cliErr *CLIError
		Expect(errors.As(err, &cliErr)).To(BeTrue(), "expected *CLIError, got %T: %v", err, err)
	})
})

var _ = Describe("searchNoMatchText", func() {
	It("produces the friendly no-match line for a given term", func() {
		var sb strings.Builder
		writeNoMatchLine(&sb, "zzz")
		Expect(sb.String()).To(Equal(`no packages matching "zzz"` + "\n"))
	})
})

var _ = Describe("interactiveTTY", func() {
	// interactiveTTY returns false whenever stdin or stdout is a bytes.Buffer
	// (not an *os.File), which is always the case in in-process tests.

	It("returns false when stdout is a buffer (non-TTY)", func() {
		cmd := &cobra.Command{}
		var out bytes.Buffer
		cmd.SetOut(&out)
		// stdin is also a buffer (the cobra default when not set)
		Expect(interactiveTTY(cmd)).To(BeFalse())
	})

	It("returns false when stdin is a buffer (non-TTY)", func() {
		cmd := &cobra.Command{}
		var in bytes.Buffer
		var out bytes.Buffer
		cmd.SetIn(&in)
		cmd.SetOut(&out)
		Expect(interactiveTTY(cmd)).To(BeFalse())
	})
})

var _ = Describe("searchOptionLabel", func() {
	It("formats name with newest version in parens", func() {
		label := searchOptionLabel("hello", []string{"1.1.0", "1.0.0"})
		Expect(label).To(Equal("hello (1.1.0)"))
	})

	It("formats name with single version", func() {
		label := searchOptionLabel("world", []string{"2.0.0"})
		Expect(label).To(Equal("world (2.0.0)"))
	})

	It("formats name with no version as name only", func() {
		label := searchOptionLabel("nover", nil)
		Expect(label).To(Equal("nover"))
	})
})

var _ = Describe("search picker gate", func() {
	// Verify that emitSearchResult skips the picker when stdout is not a TTY
	// (i.e., in-process test environment). The plain table must still appear.

	It("emits the plain table when stdout is a buffer regardless of match count", func() {
		cmd := &cobra.Command{}
		var out bytes.Buffer
		cmd.SetOut(&out)

		rows := []searchMatch{
			{Name: "hello", Versions: []string{"1.1.0", "1.0.0"}},
		}
		err := emitSearchResult(cmd, FormatText, "hello", rows)
		Expect(err).NotTo(HaveOccurred())
		Expect(out.String()).To(ContainSubstring("hello"))
		Expect(out.String()).To(ContainSubstring("1.1.0"))
	})

	It("keeps a row with no unavailable versions byte-identical", func() {
		cmd := &cobra.Command{}
		var out bytes.Buffer
		cmd.SetOut(&out)
		rows := []searchMatch{{Name: "hello", Versions: []string{"1.1.0", "1.0.0"}, Unavailable: []string{}}}
		Expect(emitSearchResult(cmd, FormatText, "hello", rows)).To(Succeed())
		Expect(out.String()).To(Equal("hello  1.1.0, 1.0.0\n"))
	})

	It("aligns the other-platforms column when only some rows have an installed cell", func() {
		cmd := &cobra.Command{}
		var out bytes.Buffer
		cmd.SetOut(&out)
		rows := []searchMatch{
			{Name: "hello", Versions: []string{"1.0.0"}, Unavailable: []string{"2.0.0"}, Installed: "1.0.0"},
			{Name: "rg", Versions: []string{}, Unavailable: []string{"14.1.1"}},
			{Name: "zed", Versions: []string{"0.1.0"}, Unavailable: []string{}},
		}
		Expect(emitSearchResult(cmd, FormatText, "", rows)).To(Succeed())
		Expect(out.String()).To(Equal(
			"hello  1.0.0  [installed: 1.0.0]  [other platforms only: 2.0.0]\n" +
				"rg" + strings.Repeat(" ", 32) + "[other platforms only: 14.1.1]\n" +
				"zed    0.1.0\n"))
	})

	It("marks versions published only for other platforms, including a package with none for this host", func() {
		cmd := &cobra.Command{}
		var out bytes.Buffer
		cmd.SetOut(&out)
		rows := []searchMatch{
			{Name: "hello", Versions: []string{"1.0.0"}, Unavailable: []string{"2.0.0"}},
			{Name: "rg", Versions: []string{}, Unavailable: []string{"14.1.1"}},
		}
		Expect(emitSearchResult(cmd, FormatText, "", rows)).To(Succeed())
		Expect(out.String()).To(Equal(
			"hello  1.0.0  [other platforms only: 2.0.0]\n" +
				"rg" + strings.Repeat(" ", 12) + "[other platforms only: 14.1.1]\n"))
	})

	It("emits no-match line and no picker when rows is empty", func() {
		cmd := &cobra.Command{}
		var out bytes.Buffer
		cmd.SetOut(&out)

		err := emitSearchResult(cmd, FormatText, "zzz", nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(out.String()).To(ContainSubstring(`no packages matching "zzz"`))
	})
})

// searchLockEnv publishes a signed one-package repo, points a profile at it,
// and returns a search command wired to out plus the scope and state home that
// runSearch would resolve.
func searchLockEnv(out *bytes.Buffer) (cmd *cobra.Command, scope, stateHome string) {
	root := GinkgoT().TempDir()
	keyDir := GinkgoT().TempDir()

	pkgDir := filepath.Join(root, "pkgs", "hello")
	Expect(os.MkdirAll(filepath.Join(pkgDir, "content", "bin"), 0o755)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(pkgDir, "polypkg.yaml"),
		[]byte("schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nactions: []\n"), 0o644)).To(Succeed())
	Expect(os.WriteFile(filepath.Join(pkgDir, "content", "bin", "hello"),
		[]byte("#!/bin/sh\necho hi\n"), 0o755)).To(Succeed())

	kp, err := repo.GenerateKeypair()
	Expect(err).NotTo(HaveOccurred())
	keyPath := filepath.Join(keyDir, "repo.key")
	Expect(repo.SaveKey(keyPath, kp, "pw", repo.KDFScrypt)).To(Succeed())

	mPath := filepath.Join(root, "polypkg-repo.yaml")
	Expect(os.WriteFile(mPath, []byte(
		"schema: polypkg.repo/v1\nsource: repo\noutput: ./public\n"+
			"key:\n  path: "+keyPath+"\n  kdf: scrypt\n"+
			"packages:\n  hello:\n    - source: ./pkgs/hello\n"), 0o644)).To(Succeed())

	b, err := repo.NewBuilder(mPath, keyDir, "pw")
	Expect(err).NotTo(HaveOccurred())
	_, err = b.Build(repo.BuildOptions{SkipAttestations: true})
	Expect(err).NotTo(HaveOccurred())
	publicDir := filepath.Join(root, "public")

	env := sandboxUserEnv(GinkgoTB())

	profilePath := filepath.Join(env, "profile.yaml")
	Expect(os.WriteFile(profilePath, []byte(
		"schema: polypkg.spec/v1\nname: searchlock\n"+
			"scopes:\n  user:\n    substrate: store\n"+
			"sources:\n  order: [repo]\n  repo:\n    type: polypkg-native\n"+
			"    url: file://"+publicDir+"\n"+
			"    trust_root: "+filepath.Join(publicDir, "trust_root.pub")+"\n"+
			"packages:\n  user:\n    hello:\n      version: \">=1.0.0\"\n"), 0o644)).To(Succeed())
	GinkgoT().Setenv("POLYPKG_PROFILE", profilePath)

	cmd = newSearchCmd()
	cmd.SetOut(out)
	cmd.SetErr(out)

	scope, _, stateHome, err = resolveListScope(cmd, bestEffortProfile(cmd))
	Expect(err).NotTo(HaveOccurred())
	return cmd, scope, stateHome
}

var _ = Describe("search picker lock scope", func() {
	// The interactive picker installs the ticked packages through runInstall,
	// and runInstall takes the apply lock itself. Anything that reaches the
	// picker therefore has to run after search's own lock is released.
	//
	// It did not. emitSearchResult — which calls the picker — ran inside the
	// withCatalog closure, so every install started from the picker died on
	// "another polypkg command is already running (polypkg search, pid N)".
	//
	// The huh form is not exercised here: interactiveTTY requires stdin and
	// stdout to be character devices, which an in-process test cannot supply,
	// so the form itself needs a pty harness. These pin the boundary it needs.

	It("holds the apply lock for the duration of the catalog fetch", func() {
		// Establishes the hazard the fix works around: anything invoked from
		// inside the closure cannot take the lock.
		var out bytes.Buffer
		cmd, scope, stateHome := searchLockEnv(&out)

		var lockedInside bool
		err := withCatalog(cmd, scope, stateHome, "search", "polypkg search",
			func(_ *schema.Profile, _ string, _ *planner.FetchResult) error {
				_, aerr := lock.Acquire(context.Background(),
					filepath.Join(stateHome, "apply.lock"),
					lock.Options{TxID: "install", Command: "polypkg install"})
				lockedInside = aerr != nil
				return nil
			})
		Expect(err).NotTo(HaveOccurred())
		Expect(lockedInside).To(BeTrue(),
			"the apply lock is expected to be held here; if it is not, the "+
				"reason emitSearchResult must stay outside searchRows is gone")
	})

	It("does not emit from inside the locked catalog fetch", func() {
		// The regression guard. searchRows must collect rows and nothing else:
		// emitting is what reaches the picker, and the picker installs. Moving
		// emitSearchResult back inside the closure puts output here and fails.
		var out bytes.Buffer
		cmd, scope, stateHome := searchLockEnv(&out)

		rows, err := searchRows(cmd, "hello", scope, stateHome, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(rows).To(HaveLen(1))
		Expect(rows[0].Name).To(Equal("hello"))
		Expect(rows[0].Versions).To(ContainElement("1.0.0"))

		Expect(out.String()).To(BeEmpty(),
			"searchRows wrote output, so it is emitting under the apply lock; "+
				"the picker that emitting reaches cannot install from there")
	})
})

var _ = Describe("installableRows", func() {
	It("keeps rows with a version for this host, in order, and drops other-platform-only rows", func() {
		rows := []searchMatch{
			{Name: "greet", Versions: []string{"1.0.0"}, Unavailable: []string{}},
			{Name: "rg", Versions: []string{}, Unavailable: []string{"14.1.1"}},
			{Name: "hello", Versions: []string{"1.0.0"}, Unavailable: []string{"2.0.0"}},
		}
		got := installableRows(rows)
		Expect(got).To(HaveLen(2))
		Expect(got[0].Name).To(Equal("greet"))
		Expect(got[1].Name).To(Equal("hello"))
	})

	It("returns an empty slice when no row is installable here", func() {
		Expect(installableRows([]searchMatch{{Name: "rg", Unavailable: []string{"14.1.1"}}})).To(BeEmpty())
		Expect(installableRows(nil)).To(BeEmpty())
	})
})

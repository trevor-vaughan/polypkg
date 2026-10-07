package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/cobra"

	"github.com/trevor-vaughan/polypkg/internal/schema"
	"github.com/trevor-vaughan/polypkg/internal/substrate"
)

// seedGen writes a committed generation with the given ownership entries under a
// fresh sandboxed user environment, so completion functions reading
// CurrentOwnership have real state. Sets the env for the rest of the spec.
func seedGen(entries []schema.OwnershipEntry) {
	root := filepath.Join(sandboxUserEnv(GinkgoTB()), "data", "polypkg")
	gen1 := filepath.Join(root, "generations", "1")
	Expect(os.MkdirAll(filepath.Join(gen1, "active"), 0o755)).To(Succeed())
	own := schema.Ownership{Schema: "polypkg.ownership/v1", Scope: "user", Entries: entries}
	b, err := json.MarshalIndent(&own, "", "  ")
	Expect(err).NotTo(HaveOccurred())
	Expect(os.WriteFile(filepath.Join(gen1, "ownership.json"), b, 0o600)).To(Succeed())
	m := schema.Manifest{Schema: "polypkg.manifest/v2", Generation: 1, Scope: "user", Entries: []schema.ManifestEntry{}}
	mb, err := json.MarshalIndent(&m, "", "  ")
	Expect(err).NotTo(HaveOccurred())
	Expect(os.WriteFile(filepath.Join(gen1, "manifest.json"), mb, 0o600)).To(Succeed())
	Expect(os.Symlink(filepath.Join("generations", "1", "active"), filepath.Join(root, "active"))).To(Succeed())
}

// complete drives cobra's hidden __complete command and returns its raw output.
func complete(args ...string) string {
	GinkgoHelper()
	root := NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"__complete"}, args...))
	Expect(root.Execute()).To(Succeed(), "__complete %v: %s", args, out.String())
	return out.String()
}

func cobraNoFileComp() cobra.ShellCompDirective { return cobra.ShellCompDirectiveNoFileComp }

var _ = Describe("completeStatic", func() {
	It("filters options by the typed prefix", func() {
		fn := completeStatic("text", "json")
		got, dir := fn(nil, nil, "j")
		Expect(got).To(Equal([]string{"json"}))
		Expect(dir).To(Equal(cobraNoFileComp()))
	})
	It("returns all options for an empty prefix", func() {
		fn := completeStatic("user", "system")
		got, _ := fn(nil, nil, "")
		Expect(got).To(ConsistOf("user", "system"))
	})
})

var _ = Describe("genIDStrings", func() {
	It("renders generation IDs as strings", func() {
		Expect(genIDStrings([]substrate.GenInfo{{ID: 3}, {ID: 1}, {ID: 2}})).
			To(ConsistOf("1", "2", "3"))
	})

	It("omits incomplete generations, which rollback --to refuses", func() {
		Expect(genIDStrings([]substrate.GenInfo{{ID: 1}, {ID: 2, Incomplete: true}, {ID: 3}})).
			To(ConsistOf("1", "3"))
	})

	It("omits damaged generations, which rollback --to refuses", func() {
		Expect(genIDStrings([]substrate.GenInfo{{ID: 1}, {ID: 2, Damaged: true}, {ID: 3}})).
			To(ConsistOf("1", "3"))
	})
})

var _ = Describe("__complete --format", func() {
	It("offers text and json", func() {
		out := complete("--format", "")
		Expect(out).To(ContainSubstring("text"))
		Expect(out).To(ContainSubstring("json"))
	})
})

func altEntryC(name, pkg, src string, prio int) schema.OwnershipEntry {
	return schema.OwnershipEntry{
		Path: "bin/" + name, Package: pkg, Action: "alternatives", Version: "1.0.0",
		Expected:    schema.Expected{FileType: "symlink", Target: src, Priority: prio},
		DriftPolicy: "notify_heal",
	}
}

var _ = Describe("altNames / altProviders", func() {
	entries := []schema.OwnershipEntry{
		altEntryC("editor", "neovim", "/a/neovim/bin/nvim", 30),
		altEntryC("editor", "vim", "/a/vim/bin/vim", 10),
		altEntryC("pager", "less", "/a/less/bin/less", 5),
		{Path: "bin/foo", Package: "p", Action: "path"},
	}
	It("altNames returns sorted unique alternative names", func() {
		Expect(altNames(entries)).To(Equal([]string{"editor", "pager"}))
	})
	It("altProviders returns sorted providers of a name", func() {
		Expect(altProviders(entries, "editor")).To(Equal([]string{"neovim", "vim"}))
		Expect(altProviders(entries, "nope")).To(BeEmpty())
	})
})

var _ = Describe("__complete alternatives", func() {
	It("completes alternative names for set arg 0", func() {
		seedGen([]schema.OwnershipEntry{
			altEntryC("editor", "neovim", "/a/neovim/bin/nvim", 30),
			altEntryC("pager", "less", "/a/less/bin/less", 5),
		})
		out := complete("alternatives", "set", "")
		Expect(out).To(ContainSubstring("editor"))
		Expect(out).To(ContainSubstring("pager"))
	})
	It("completes providers for set arg 1 of the named alternative", func() {
		seedGen([]schema.OwnershipEntry{
			altEntryC("editor", "neovim", "/a/neovim/bin/nvim", 30),
			altEntryC("editor", "vim", "/a/vim/bin/vim", 10),
		})
		out := complete("alternatives", "set", "editor", "")
		Expect(out).To(ContainSubstring("neovim"))
		Expect(out).To(ContainSubstring("vim"))
	})
	It("offers user and system for --scope", func() {
		out := complete("alternatives", "list", "--scope", "")
		Expect(out).To(ContainSubstring("user"))
		Expect(out).To(ContainSubstring("system"))
	})
})

var _ = Describe("config completion helpers", func() {
	entries := []schema.OwnershipEntry{
		{Path: "hello/etc/app.conf", Package: "hello", Action: "config", DriftPolicy: "notify_preserve"},
		{Path: "hello/etc/fixed.conf", Package: "hello", Action: "config", DriftPolicy: "notify_heal"},
		{Path: "hello/bin/hi", Package: "hello", Action: "install", DriftPolicy: "notify_heal"},
		{Path: "bin/rg", Package: "ripgrep", Action: "path"},
	}
	It("resettableConfigPaths returns only config+notify_preserve paths", func() {
		Expect(resettableConfigPaths(entries)).To(Equal([]string{"hello/etc/app.conf"}))
	})
	It("pkgNames returns sorted distinct package names", func() {
		Expect(pkgNames(entries)).To(Equal([]string{"hello", "ripgrep"}))
	})
})

var _ = Describe("__complete config reset", func() {
	It("completes resettable config paths and package names", func() {
		seedGen([]schema.OwnershipEntry{
			{Path: "hello/etc/app.conf", Package: "hello", Action: "config", Version: "1.0.0",
				Expected: schema.Expected{FileType: "regular"}, DriftPolicy: "notify_preserve"},
		})
		Expect(complete("config", "reset", "")).To(ContainSubstring("hello/etc/app.conf"))
		Expect(complete("config", "reset", "--package", "")).To(ContainSubstring("hello"))
	})
})

var _ = Describe("__complete rollback --to", func() {
	It("offers committed generation IDs", func() {
		seedGen([]schema.OwnershipEntry{altEntryC("editor", "neovim", "/a/neovim/bin/nvim", 30)})
		out := complete("rollback", "--to", "")
		Expect(out).To(ContainSubstring("1"))
	})
})

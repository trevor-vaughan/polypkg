package pkglint_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/archive"
	"github.com/trevor-vaughan/polypkg/internal/pkglint"
)

// writePkg writes a package source named "hello" into a fresh temp dir and
// returns the dir. actions is the body of the recipe's actions: sequence,
// already indented. Each files entry is written under content/.
func writePkg(actions string, files map[string][]byte) string {
	GinkgoHelper()
	dir := GinkgoT().TempDir()
	recipe := "schema: polypkg.package/v1\n" +
		"name: hello\n" +
		"version: 1.0.0\n" +
		"actions:\n" + actions
	Expect(os.WriteFile(filepath.Join(dir, "polypkg.yaml"), []byte(recipe), 0o600)).To(Succeed())
	for name, data := range files {
		p := filepath.Join(dir, "content", filepath.FromSlash(name))
		Expect(os.MkdirAll(filepath.Dir(p), 0o750)).To(Succeed())
		Expect(os.WriteFile(p, data, 0o600)).To(Succeed())
	}
	return dir
}

// extractPkg writes a package whose polypkg.yaml declares one post-place
// extract action whose params mapping body is params (YAML flow-mapping
// entries, e.g. `src: "$PKG/content/a.tar.gz", dest: "$ACTIVE/hello/tool"`).
// The params mapping is on line 7 of the recipe.
func extractPkg(params string, files map[string][]byte) string {
	GinkgoHelper()
	return writePkg("  - phase: post-place\n"+
		"    action: extract\n"+
		"    params: {"+params+"}\n", files)
}

// helloTar returns an uncompressed tar holding hello-1.0.0/bin/hello, the
// layout an upstream release archive typically has.
func helloTar() []byte {
	GinkgoHelper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte("#!/bin/sh\necho hello\n")
	Expect(tw.WriteHeader(&tar.Header{
		Name: "hello-1.0.0/bin/hello", Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(body)),
	})).To(Succeed())
	_, err := tw.Write(body)
	Expect(err).ToNot(HaveOccurred())
	Expect(tw.Close()).To(Succeed())
	return buf.Bytes()
}

// helloTarGz returns helloTar gzip-compressed.
func helloTarGz() []byte {
	GinkgoHelper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, err := gz.Write(helloTar())
	Expect(err).ToNot(HaveOccurred())
	Expect(gz.Close()).To(Succeed())
	return buf.Bytes()
}

// countRule returns how many findings carry ruleID.
func countRule(res pkglint.Result, ruleID string) int {
	n := 0
	for _, f := range res.Findings {
		if f.RuleID == ruleID {
			n++
		}
	}
	return n
}

const (
	goodSrc  = `src: "$PKG/content/a.tar.gz"`
	goodDest = `dest: "$ACTIVE/hello/tool"`
)

var _ = Describe("extract action params (PKG010)", func() {
	It("accepts a complete, valid extract action with no findings", func() {
		dir := extractPkg(goodSrc+", "+goodDest+`, strip_components: 1, include: ["bin/*", "doc"]`,
			map[string][]byte{"a.tar.gz": helloTarGz()})
		Expect(pkglintMust(dir).Findings).To(BeEmpty())
	})

	DescribeTable("reports a value apply would refuse, at the parameter's line",
		func(params, param, want string) {
			dir := extractPkg(params, map[string][]byte{"a.tar.gz": helloTarGz()})
			res := pkglintMust(dir)
			f := findRule(res, "PKG010")
			Expect(f.Severity).To(Equal(pkglint.SeverityError))
			Expect(f.Message).To(ContainSubstring(`action "extract" parameter "` + param + `"`))
			Expect(f.Message).To(ContainSubstring(want))
			Expect(f.Loc.Line).To(Equal(7))
			Expect(countRule(res, "PKG010")).To(Equal(1))
		},
		Entry("src under $ACTIVE", `src: "$ACTIVE/hello/a.tar.gz", `+goodDest, "src", "must name a file under $PKG/"),
		Entry("src absolute", `src: "/tmp/a.tar.gz", `+goodDest, "src", "must name a file under $PKG/"),
		Entry("src traversing out of $PKG", `src: "$PKG/../a.tar.gz", `+goodDest, "src", "must name a file under $PKG/"),
		Entry("src naming the package root", `src: "$PKG/", `+goodDest, "src", "must name a file under $PKG/"),
		Entry("src not a string", `src: 5, `+goodDest, "src", "must be a string"),
		Entry("dest under $PKG", goodSrc+`, dest: "$PKG/content/out"`, "dest", "must name a directory below $ACTIVE/hello/"),
		Entry("dest in another package", goodSrc+`, dest: "$ACTIVE/other/tool"`, "dest", "must name a directory below $ACTIVE/hello/"),
		Entry("dest in a prefix sibling", goodSrc+`, dest: "$ACTIVE/hello-evil/tool"`, "dest", "must name a directory below $ACTIVE/hello/"),
		Entry("dest equal to the package directory", goodSrc+`, dest: "$ACTIVE/hello"`, "dest", "must name a directory below $ACTIVE/hello/"),
		Entry("dest cleaning to the package directory", goodSrc+`, dest: "$ACTIVE/hello/tool/.."`, "dest", "must name a directory below $ACTIVE/hello/"),
		Entry("dest traversing out of the package", goodSrc+`, dest: "$ACTIVE/hello/../../etc"`, "dest", "must name a directory below $ACTIVE/hello/"),
		Entry("dest not a string", goodSrc+`, dest: [a]`, "dest", "must be a string"),
		Entry("negative strip_components", goodSrc+", "+goodDest+`, strip_components: -1`, "strip_components", "must be a non-negative integer"),
		Entry("negative numeric-string strip_components", goodSrc+", "+goodDest+`, strip_components: "-2"`, "strip_components", "must be a non-negative integer"),
		Entry("strip_components beyond the member depth cap", goodSrc+", "+goodDest+`, strip_components: 1e300`, "strip_components",
			"must be at most 64, the deepest member path an archive may hold; got 1e+300"),
		Entry("include as an empty list", goodSrc+", "+goodDest+`, include: []`, "include", "is an empty list"),
		Entry("include with a malformed pattern", goodSrc+", "+goodDest+`, include: ["bin/["]`, "include", `pattern "bin/[" is not a valid path.Match pattern`),
		Entry("include with an empty pattern", goodSrc+", "+goodDest+`, include: [""]`, "include", "empty pattern"),
	)

	It("reports every malformed include pattern, not only the first", func() {
		dir := extractPkg(goodSrc+", "+goodDest+`, include: ["[", "ok", "a["]`,
			map[string][]byte{"a.tar.gz": helloTarGz()})
		Expect(countRule(pkglintMust(dir), "PKG010")).To(Equal(2))
	})

	It("accepts strip_components 0, a numeric string and a whole float", func() {
		for _, v := range []string{"0", `"3"`, "2.0"} {
			dir := extractPkg(goodSrc+", "+goodDest+", strip_components: "+v,
				map[string][]byte{"a.tar.gz": helloTarGz()})
			Expect(pkglintMust(dir).Findings).To(BeEmpty(), "strip_components: %s", v)
		}
	})

	It("does not check !starlark values, which are computed at apply time", func() {
		dir := extractPkg(
			`src: !starlark "return '/etc/shadow'", `+
				`dest: !starlark "return '/tmp'", `+
				`strip_components: !starlark "return '-1'"`,
			nil)
		Expect(findRule0(pkglintMust(dir), "PKG010")).To(BeZero())
	})

	It("reports a !starlark include, which computes a string and can never be a list", func() {
		dir := extractPkg(goodSrc+", "+goodDest+`, include: !starlark "return 'bin/*'"`,
			map[string][]byte{"a.tar.gz": helloTarGz()})
		f := findRule(pkglintMust(dir), "PKG010")
		Expect(f.Message).To(Equal("include cannot be computed by !starlark; it must be a literal list"))
		Expect(f.Loc.Line).To(Equal(7))
	})

	It("leaves a missing required param to PKG002", func() {
		dir := extractPkg(goodSrc, map[string][]byte{"a.tar.gz": helloTarGz()})
		res := pkglintMust(dir)
		Expect(findRule(res, "PKG002").Message).To(ContainSubstring(`"dest"`))
		Expect(findRule0(res, "PKG010")).To(BeZero())
	})
})

var _ = Describe("int and string-list parameter kinds (PKG010)", func() {
	// These are the registry-kind checks every action's params get; extract's
	// strip_components (int) and include (string list) exercise them, and the
	// extract-specific check must not report the same defect a second time.
	DescribeTable("reports a value that is not of the parameter's kind, once",
		func(params, want string) {
			dir := extractPkg(goodSrc+", "+goodDest+", "+params, map[string][]byte{"a.tar.gz": helloTarGz()})
			res := pkglintMust(dir)
			Expect(countRule(res, "PKG010")).To(Equal(1))
			f := findRule(res, "PKG010")
			Expect(f.Message).To(ContainSubstring(want))
			Expect(f.Loc.Line).To(Equal(7))
		},
		Entry("a non-numeric string int", `strip_components: "abc"`, `parameter "strip_components" value "abc" is not an integer`),
		Entry("a fractional int", `strip_components: 1.5`, `parameter "strip_components" value 1.5 is not an integer`),
		Entry("a scalar string list", `include: "bin/*"`, `parameter "include" value bin/* is not a list of strings`),
		Entry("a non-string list entry", `include: ["ok", 7]`, `parameter "include" entry 7 is not a string`),
	)

	It("leaves an infinite or NaN int to the structural layer (PKG000)", func() {
		for _, v := range []string{".inf", "-.inf", ".nan"} {
			res := pkglintMust(extractPkg(goodSrc+", "+goodDest+", strip_components: "+v, nil))
			Expect(findRule(res, "PKG000").Message).To(ContainSubstring("unsupported value"), "strip_components: %s", v)
		}
	})

	It("rejects a fractional alternatives priority, which apply would silently truncate", func() {
		dir := writePkg("  - phase: post-place\n"+
			"    action: alternatives\n"+
			"    params: {source: \"$ACTIVE/hello/bin/hello\", name: vi, priority: 10.5}\n", nil)
		f := findRule(pkglintMust(dir), "PKG010")
		Expect(f.Message).To(ContainSubstring(`parameter "priority" value 10.5 is not an integer`))
	})
})

var _ = Describe("extract dest created by an earlier action (PKG010)", func() {
	extract := "  - phase: post-place\n" +
		"    action: extract\n" +
		"    params: {" + goodSrc + ", " + goodDest + "}\n"
	files := map[string][]byte{"a.tar.gz": helloTarGz()}

	DescribeTable("reports a dest that an action running before it creates",
		func(earlier, want string) {
			res := pkglintMust(writePkg(earlier+extract, files))
			Expect(countRule(res, "PKG010")).To(Equal(1))
			f := findRule(res, "PKG010")
			Expect(f.Message).To(ContainSubstring(`action "extract" parameter "dest" value "$ACTIVE/hello/tool" already exists when extract runs`))
			Expect(f.Message).To(ContainSubstring(want))
			Expect(f.Loc.Line).To(Equal(10))
		},
		Entry("a dir at dest",
			"  - phase: post-place\n    action: dir\n    params: {path: \"$ACTIVE/hello/tool\"}\n",
			`the "dir" action at line 5`),
		Entry("an install below dest, in an earlier phase",
			"  - phase: pre-place\n    action: install\n    params: {src: \"$PKG/content/a.tar.gz\", dest: \"$ACTIVE/hello/tool/x\"}\n",
			`the "install" action at line 5`),
		Entry("a symlink at dest, spelled with a trailing slash",
			"  - phase: post-place\n    action: symlink\n    params: {src: \"$ACTIVE/hello/x\", dest: \"$ACTIVE/hello/tool/\"}\n",
			`the "symlink" action at line 5`),
		Entry("another extract into dest",
			"  - phase: post-place\n    action: extract\n    params: {"+goodSrc+", "+goodDest+"}\n",
			`the "extract" action at line 5`),
	)

	DescribeTable("does not report an action that leaves dest absent",
		func(other string, after bool) {
			recipe := other + extract
			if after {
				recipe = extract + other
			}
			Expect(findRule0(pkglintMust(writePkg(recipe, files)), "PKG010")).To(BeZero())
		},
		Entry("a dir that is an ancestor of dest",
			"  - phase: post-place\n    action: dir\n    params: {path: \"$ACTIVE/hello\"}\n", false),
		Entry("a dir at a name that only shares dest's prefix",
			"  - phase: post-place\n    action: dir\n    params: {path: \"$ACTIVE/hello/toolbox\"}\n", false),
		Entry("a dir at dest declared after the extract in the same phase",
			"  - phase: post-place\n    action: dir\n    params: {path: \"$ACTIVE/hello/tool/x\"}\n", true),
		Entry("a dir at dest in a later phase, declared first",
			"  - phase: pre-activate\n    action: dir\n    params: {path: \"$ACTIVE/hello/tool/x\"}\n", false),
		Entry("perms on dest, which changes a mode but creates nothing",
			"  - phase: post-place\n    action: perms\n    params: {path: \"$ACTIVE/hello/tool\", mode: \"0o755\"}\n", false),
	)
})

var _ = Describe("extract dest below a leaf an earlier action places (PKG010)", func() {
	extract := "  - phase: post-place\n" +
		"    action: extract\n" +
		"    params: {" + goodSrc + ", dest: \"$ACTIVE/hello/opt/tool\"}\n"
	files := map[string][]byte{
		"a.tar.gz": helloTarGz(),
		"app.conf": []byte("key = value\n"),
	}

	// apply would fail: a regular file at an ancestor stops extract creating a
	// directory below it, and a link out of the package directory is one the
	// confined apply refuses to traverse.
	DescribeTable("reports a dest below a file or an outward link that an action running before it places",
		func(earlier, want string) {
			res := pkglintMust(writePkg(earlier+extract, files))
			Expect(countRule(res, "PKG010")).To(Equal(1))
			f := findRule(res, "PKG010")
			Expect(f.Message).To(ContainSubstring(`action "extract" parameter "dest" value "$ACTIVE/hello/opt/tool" cannot be created when extract runs`))
			Expect(f.Message).To(ContainSubstring(want))
			Expect(f.Message).To(ContainSubstring("extract cannot create a directory below it"))
			Expect(f.Loc.Line).To(Equal(10))
		},
		Entry("a file an install copies to the parent",
			"  - phase: post-place\n    action: install\n    params: {src: \"$PKG/content/a.tar.gz\", dest: \"$ACTIVE/hello/opt\"}\n",
			`the "install" action at line 5 first places "$ACTIVE/hello/opt"`),
		Entry("an install that links a file to the parent, in an earlier phase",
			"  - phase: pre-place\n    action: install\n    params: {src: \"$PKG/content/a.tar.gz\", dest: \"$ACTIVE/hello/opt\", policy: symlink}\n",
			`the "install" action at line 5 first places "$ACTIVE/hello/opt"`),
		Entry("a config file at the parent",
			"  - phase: post-place\n    action: config\n    params: {src: \"$PKG/content/app.conf\", dest: \"$ACTIVE/hello/opt\"}\n",
			`the "config" action at line 5 first places "$ACTIVE/hello/opt"`),
		Entry("a state link at the parent, spelled with a trailing slash",
			"  - phase: post-place\n    action: state\n    params: {path: \"$ACTIVE/hello/opt/\"}\n",
			`the "state" action at line 5 first places "$ACTIVE/hello/opt/"`),
	)

	DescribeTable("does not report an earlier placement extract can create a directory below",
		func(other string, after bool) {
			recipe := other + extract
			if after {
				recipe = extract + other
			}
			Expect(findRule0(pkglintMust(writePkg(recipe, files)), "PKG010")).To(BeZero())
		},
		Entry("a dir at the parent",
			"  - phase: post-place\n    action: dir\n    params: {path: \"$ACTIVE/hello/opt\"}\n", false),
		Entry("a symlink at the parent, whose target decides where dest lands",
			"  - phase: post-place\n    action: symlink\n    params: {src: \"real\", dest: \"$ACTIVE/hello/opt\"}\n", false),
		Entry("another extract into the parent",
			"  - phase: post-place\n    action: extract\n    params: {"+goodSrc+", dest: \"$ACTIVE/hello/opt\"}\n", false),
		Entry("an install at a name that only shares the parent's prefix",
			"  - phase: post-place\n    action: install\n    params: {src: \"$PKG/content/a.tar.gz\", dest: \"$ACTIVE/hello/op\"}\n", false),
		Entry("an install at the parent declared after the extract in the same phase",
			"  - phase: post-place\n    action: install\n    params: {src: \"$PKG/content/a.tar.gz\", dest: \"$ACTIVE/hello/opt\"}\n", true),
	)

	// Actions run by phase first and declaration order second, so the
	// collision reported as placing "first" is the one that runs first, not
	// the one declared first.
	It("reports the colliding action that runs first, even when another is declared before it", func() {
		recipe := "  - phase: post-place\n    action: install\n    params: {src: \"$PKG/content/a.tar.gz\", dest: \"$ACTIVE/hello/opt\"}\n" +
			"  - phase: pre-place\n    action: dir\n    params: {path: \"$ACTIVE/hello/opt/tool\"}\n" +
			extract
		res := pkglintMust(writePkg(recipe, files))
		Expect(countRule(res, "PKG010")).To(Equal(1))
		Expect(findRule(res, "PKG010").Message).To(ContainSubstring(
			`value "$ACTIVE/hello/opt/tool" already exists when extract runs: the "dir" action at line 8 creates "$ACTIVE/hello/opt/tool" first`))
	})
})

var _ = Describe("extract archive detection (PKG012)", func() {
	params := goodSrc + ", " + goodDest

	// srcPath is where goodSrc points inside a package dir.
	srcPath := func(dir string) string {
		return filepath.Join(dir, "content", "a.tar.gz")
	}

	It("accepts a gzip-compressed tar", func() {
		dir := extractPkg(params, map[string][]byte{"a.tar.gz": helloTarGz()})
		Expect(findRule0(pkglintMust(dir), "PKG012")).To(BeZero())
	})

	It("accepts an uncompressed tar, whose magic sits at offset 257", func() {
		dir := extractPkg(params, map[string][]byte{"a.tar.gz": helloTar()})
		Expect(findRule0(pkglintMust(dir), "PKG012")).To(BeZero())
	})

	DescribeTable("reports file content apply cannot unpack, whatever the file is named",
		func(content []byte) {
			dir := extractPkg(params, map[string][]byte{"a.tar.gz": content})
			f := findRule(pkglintMust(dir), "PKG012")
			Expect(f.Severity).To(Equal(pkglint.SeverityError))
			Expect(f.Message).To(ContainSubstring(`action "extract" parameter "src" references "content/a.tar.gz"`))
			Expect(f.Message).To(ContainSubstring("which apply cannot unpack"))
			Expect(f.Loc.Line).To(Equal(7))
		},
		Entry("a text file", []byte("this is a plain text file, not an archive, padded past the header length "+
			"so the full DetectHeaderLen read succeeds and only the magic check can refuse it .................."+
			"...................................................................................................")),
		Entry("a file shorter than any magic", []byte("hi")),
		Entry("an empty file", []byte{}),
	)

	It("reports a src larger than a package member may be", func() {
		dir := extractPkg(params, map[string][]byte{"a.tar.gz": helloTarGz()})
		// Sparse: Truncate grows the file without writing 1 GiB.
		Expect(os.Truncate(srcPath(dir), archive.DefaultLimits().MaxFileBytes+1)).To(Succeed())
		f := findRule(pkglintMust(dir), "PKG012")
		Expect(f.Message).To(ContainSubstring("package members are limited to 1 GiB"))
		Expect(f.Message).To(ContainSubstring("could never install"))
	})

	It("accepts a src of exactly the member limit", func() {
		dir := extractPkg(params, map[string][]byte{"a.tar.gz": helloTarGz()})
		Expect(os.Truncate(srcPath(dir), archive.DefaultLimits().MaxFileBytes)).To(Succeed())
		Expect(findRule0(pkglintMust(dir), "PKG012")).To(BeZero())
	})

	It("reports a directory at src as not a regular file", func() {
		dir := extractPkg(params, nil)
		Expect(os.MkdirAll(srcPath(dir), 0o750)).To(Succeed())
		f := findRule(pkglintMust(dir), "PKG012")
		Expect(f.Message).To(ContainSubstring("which is not a regular file"))
	})

	It("reports a FIFO at src without blocking on it", func(_ SpecContext) {
		dir := extractPkg(params, nil)
		Expect(os.MkdirAll(filepath.Dir(srcPath(dir)), 0o750)).To(Succeed())
		Expect(syscall.Mkfifo(srcPath(dir), 0o600)).To(Succeed())
		f := findRule(pkglintMust(dir), "PKG012")
		Expect(f.Message).To(ContainSubstring("which is not a regular file"))
	}, SpecTimeout(10*time.Second))

	It("reports a src symlink that leads outside the package, without reading the target", func() {
		outside := GinkgoT().TempDir()
		target := filepath.Join(outside, "real.tar.gz")
		Expect(os.WriteFile(target, helloTarGz(), 0o600)).To(Succeed())
		dir := extractPkg(params, nil)
		Expect(os.MkdirAll(filepath.Dir(srcPath(dir)), 0o750)).To(Succeed())
		Expect(os.Symlink(target, srcPath(dir))).To(Succeed())

		res := pkglintMust(dir)
		f := findRule(res, "PKG012")
		Expect(f.Message).To(ContainSubstring("which is a symlink"))
		Expect(f.Message).NotTo(ContainSubstring("which apply cannot unpack"))
		// The target exists, so the stat-based content-reference rule is silent;
		// only the Lstat notices the link.
		Expect(findRule0(res, "PKG006")).To(BeZero())
	})

	It("reports a src symlink that stays inside the package, since repo build refuses it", func() {
		dir := extractPkg(params, map[string][]byte{"real.tar.gz": helloTarGz()})
		Expect(os.Symlink("real.tar.gz", srcPath(dir))).To(Succeed())
		f := findRule(pkglintMust(dir), "PKG012")
		Expect(f.Message).To(ContainSubstring(`references "content/a.tar.gz", which is a symlink; repo build refuses any symlink in content/`))
	})

	It("reports a src reached through a symlinked directory", func() {
		dir := extractPkg(`src: "$PKG/content/link/a.tar.gz", `+goodDest, map[string][]byte{"real/a.tar.gz": helloTarGz()})
		Expect(os.Symlink("real", filepath.Join(dir, "content", "link"))).To(Succeed())
		f := findRule(pkglintMust(dir), "PKG012")
		Expect(f.Message).To(ContainSubstring(`"content/link" is a symlink`))
	})

	It("leaves a missing src to PKG006", func() {
		res := pkglintMust(extractPkg(params, nil))
		Expect(findRule(res, "PKG006").Message).To(ContainSubstring("content/a.tar.gz"))
		Expect(findRule0(res, "PKG012")).To(BeZero())
	})

	It("does not open a src that is outside $PKG/", func() {
		// Lay out <base>/a.tar.gz (not an archive) beside the package source
		// <base>/pkg, so "$PKG/../a.tar.gz" names a real file that lint must
		// refuse by path without ever inspecting it.
		base := GinkgoT().TempDir()
		Expect(os.WriteFile(filepath.Join(base, "a.tar.gz"), []byte("not an archive"), 0o600)).To(Succeed())
		dir := filepath.Join(base, "pkg")
		Expect(os.Mkdir(dir, 0o750)).To(Succeed())
		recipe, err := os.ReadFile(filepath.Join(extractPkg(`src: "$PKG/../a.tar.gz", `+goodDest, nil), "polypkg.yaml"))
		Expect(err).ToNot(HaveOccurred())
		Expect(os.WriteFile(filepath.Join(dir, "polypkg.yaml"), recipe, 0o600)).To(Succeed())

		res := pkglintMust(dir)
		Expect(findRule(res, "PKG010").Message).To(ContainSubstring("must name a file under $PKG/"))
		Expect(findRule0(res, "PKG012")).To(BeZero())
	})
})

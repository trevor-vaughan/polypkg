package platform

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// goCommand is the go command of the toolchain running this test.
// runtime.GOROOT is deprecated. GOROOT is set when the caller set it;
// otherwise go test puts the GOROOT/bin of the toolchain running it first on
// PATH (Go 1.19+), so either way this is that toolchain's go.
func goCommand() string {
	if root := os.Getenv("GOROOT"); root != "" {
		return filepath.Join(root, "bin", "go")
	}
	return "go"
}

var _ = Describe("Host", func() {
	It("is a platform this polypkg can publish for", func() {
		Expect(ValidateProducer(Host())).To(Succeed())
	})
})

var _ = Describe("ValidateConsumer", func() {
	DescribeTable("accepts any well-formed 2- or 3-segment platform",
		func(p string) { Expect(ValidateConsumer(p)).To(Succeed()) },
		Entry("os/arch", "linux/amd64"),
		Entry("os/arch/variant", "linux/arm/v7"),
		Entry("a port this toolchain lacks", "plan9/mips"),
		Entry("digits in every segment", "os2/x86/v3"),
	)

	DescribeTable("refuses a malformed platform",
		func(p string) {
			err := ValidateConsumer(p)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("%q", p))
		},
		Entry("empty", ""),
		Entry("the reserved agnostic token", Any),
		Entry("one segment", "linux"),
		Entry("four segments", "linux/arm/v7/x"),
		Entry("upper case", "Linux/amd64"),
		Entry("empty segment", "linux//amd64"),
		Entry("leading slash", "/linux/amd64"),
		Entry("trailing slash", "linux/amd64/"),
		Entry("hyphen", "linux/amd-64"),
		Entry("underscore", "linux/amd_64"),
		Entry("dot-dot traversal", "../amd64"),
		Entry("trailing newline", "linux/amd64\n"),
		Entry("whitespace", "linux /amd64"),
		Entry("non-ASCII", "linux/amd64é"),
	)
})

var _ = Describe("ValidateProducer", func() {
	DescribeTable("accepts an <os>/<arch> pair the Go toolchain supports",
		func(p string) { Expect(ValidateProducer(p)).To(Succeed()) },
		Entry("linux/amd64", "linux/amd64"),
		Entry("linux/arm64", "linux/arm64"),
		Entry("darwin/arm64", "darwin/arm64"),
		Entry("freebsd/amd64", "freebsd/amd64"),
	)

	DescribeTable("refuses what a consumer would accept but a publisher must not emit",
		func(p, want string) {
			err := ValidateProducer(p)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring(want))
		},
		Entry("typo in the arch", "linux/amd46", "not a Go port"),
		Entry("typo in the os", "lnux/amd64", "not a Go port"),
		Entry("known os and arch, but not a port together", "darwin/386", "not a Go port"),
		Entry("a variant segment", "linux/arm/v7", "variant"),
		Entry("upper case", "Linux/amd64", "lower-case"),
		Entry("the reserved agnostic token", Any, "lower-case"),
		Entry("empty", "", "lower-case"),
	)
})

var _ = Describe("Ports", func() {
	It("lists exactly the pairs ValidateProducer accepts", func() {
		ports := Ports()
		Expect(ports).To(Equal(knownPorts))
		for _, p := range ports {
			Expect(ValidateProducer(p)).To(Succeed(), p)
		}
	})

	It("returns a copy, so a caller cannot change what ValidateProducer accepts", func() {
		ports := Ports()
		ports[0] = "zz/zz"
		Expect(knownPorts[0]).NotTo(Equal("zz/zz"))
		Expect(ValidateProducer("zz/zz")).NotTo(Succeed())
	})
})

var _ = Describe("knownPorts", func() {
	It("is sorted, so ValidateProducer's binary search is sound", func() {
		Expect(slices.IsSorted(knownPorts)).To(BeTrue())
	})

	It("records the Go release it was generated with as go<major>.<minor>", func() {
		Expect(generatedGoVersion).To(MatchRegexp(`^go[0-9]+\.[0-9]+$`))
	})

	// The drift spec below skips on any other Go release, so without this a
	// go.mod bump that skipped `task generate` would leave CI skipping it.
	It("was generated with the Go release go.mod declares", func() {
		gomod, err := exec.Command(goCommand(), "env", "GOMOD").Output()
		Expect(err).NotTo(HaveOccurred())
		path := strings.TrimSpace(string(gomod))
		Expect(path).NotTo(BeElementOf("", os.DevNull), "go env GOMOD found no go.mod")
		data, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		m := regexp.MustCompile(`(?m)^go[ \t]+([0-9]+\.[0-9]+)`).FindSubmatch(data)
		Expect(m).NotTo(BeNil(), "%s has no go directive", path)
		declared := "go" + string(m[1])
		Expect(generatedGoVersion).To(Equal(declared),
			"zz_generated_known.go was generated with %s but go.mod declares %s: run `task generate` under %s and commit the result",
			generatedGoVersion, declared, declared)
	})

	It("is exactly `go tool dist list` for the Go release it was generated with", func() {
		running := regexp.MustCompile(`^go[0-9]+\.[0-9]+`).FindString(runtime.Version())
		if running != generatedGoVersion {
			Skip("zz_generated_known.go is authoritative only for " + generatedGoVersion +
				", but this test runs on " + runtime.Version() + ": regenerate it with " +
				generatedGoVersion + " via `task generate`")
		}
		out, err := exec.Command(goCommand(), "tool", "dist", "list").Output()
		Expect(err).NotTo(HaveOccurred())
		want := strings.Fields(string(out))
		slices.Sort(want)
		Expect(knownPorts).To(Equal(want),
			"zz_generated_known.go drifted from this Go toolchain: run `task generate` and commit the result")
	})
})

var _ = Describe("Display", func() {
	It("renders a platform-agnostic (empty) platform as the reserved token", func() {
		Expect(Display("")).To(Equal(Any))
	})
	It("renders a concrete platform unchanged", func() {
		Expect(Display("linux/amd64")).To(Equal("linux/amd64"))
		Expect(Display("linux/arm/v7")).To(Equal("linux/arm/v7"))
	})
})

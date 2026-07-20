package cli

import (
	"bytes"
	"errors"
	"sort"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("validateRemoveNames", func() {
	known := map[string]string{
		"hello": ">=1.0.0",
		"world": "=2.0.0",
		"zzz":   ">=3.0.0",
	}

	It("returns nil when all requested names exist in the profile", func() {
		Expect(validateRemoveNames([]string{"hello", "world"}, known, "user")).To(Succeed())
	})

	It("returns CLIError for a missing name with sorted known-packages hint", func() {
		err := validateRemoveNames([]string{"nosuch"}, known, "user")
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Msg).To(ContainSubstring("nosuch"))
		Expect(ce.Msg).To(ContainSubstring("not in the profile"))
		// hint must list sorted known names
		Expect(ce.Hint).To(ContainSubstring("hello"))
		Expect(ce.Hint).To(ContainSubstring("world"))
		Expect(ce.Hint).To(ContainSubstring("zzz"))
	})

	It("caps the hint at 10 packages and appends +N more", func() {
		big := map[string]string{}
		for i := range 15 {
			big[string(rune('a'+i))] = ">=1.0.0"
		}
		err := validateRemoveNames([]string{"nosuch"}, big, "user")
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Hint).To(ContainSubstring("+5 more"))
	})

	It("produces empty-profile hint when no packages exist in scope", func() {
		err := validateRemoveNames([]string{"hello"}, map[string]string{}, "user")
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Hint).To(ContainSubstring("the profile has no packages in scope"))
		Expect(ce.Hint).To(ContainSubstring("user"))
	})

	It("returns the first failing name (all-or-nothing check order)", func() {
		// hello exists; nosuch does not — error names nosuch
		err := validateRemoveNames([]string{"hello", "nosuch"}, known, "user")
		Expect(err).To(HaveOccurred())
		var ce *CLIError
		Expect(errors.As(err, &ce)).To(BeTrue())
		Expect(ce.Msg).To(ContainSubstring("nosuch"))
	})
})

var _ = Describe("knownPackageHint", func() {
	It("lists up to 10 names sorted", func() {
		names := []string{"z", "b", "a", "c"}
		hint := knownPackageHint(names, "user")
		Expect(hint).To(HavePrefix("packages in the profile:"))
		// names should appear in sorted order
		idxA := bytes.Index([]byte(hint), []byte("a"))
		idxB := bytes.Index([]byte(hint), []byte("b"))
		Expect(idxA).To(BeNumerically("<", idxB))
	})

	It("appends +N more for > 10 names", func() {
		names := make([]string, 12)
		for i := range 12 {
			names[i] = string(rune('a' + i))
		}
		sort.Strings(names)
		hint := knownPackageHint(names, "user")
		Expect(hint).To(ContainSubstring("+2 more"))
	})

	It("uses the empty-profile message when no names", func() {
		hint := knownPackageHint(nil, "myScope")
		Expect(hint).To(ContainSubstring("the profile has no packages in scope myScope"))
	})
})

var _ = Describe("renderRemoveEdits", func() {
	It("renders one removing line per package", func() {
		var buf bytes.Buffer
		renderRemoveEdits(&buf, []string{"hello", "world"})
		Expect(buf.String()).To(ContainSubstring("removing hello"))
		Expect(buf.String()).To(ContainSubstring("removing world"))
	})
})

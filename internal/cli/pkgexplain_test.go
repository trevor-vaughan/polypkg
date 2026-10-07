package cli

import (
	"bytes"
	"encoding/json"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/action"
	"github.com/trevor-vaughan/polypkg/internal/platform"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("pkg explain", func() {
	It("labels a list-valued parameter as a list", func() {
		Expect(paramKindName(action.KindStringList)).To(Equal("list"))
	})

	It("renders the phase lifecycle, path vars, and the build-outside model in text mode", func() {
		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"pkg", "explain"})
		Expect(root.Execute()).To(Succeed())

		text := out.String()

		// Every lifecycle phase name is present, in the canonical order.
		phases := []string{
			string(action.PhasePrePlace),
			string(action.PhasePostPlace),
			string(action.PhasePreActivate),
			string(action.PhasePostActivate),
			string(action.PhasePreDeactivate),
			string(action.PhasePostDeactivate),
		}
		last := -1
		for _, ph := range phases {
			idx := strings.Index(text, ph)
			Expect(idx).To(BeNumerically(">", last),
				"phase %q must appear after the previous phase", ph)
			last = idx
		}

		// A couple of representative discovered actions appear by name.
		Expect(text).To(ContainSubstring("install"))
		Expect(text).To(ContainSubstring("path"))

		// The two substitution vars are documented.
		Expect(text).To(ContainSubstring("$PKG"))
		Expect(text).To(ContainSubstring("$ACTIVE"))

		// The build-outside model is stated.
		Expect(text).To(ContainSubstring("content/"))

		// The !starlark/host portability hint is shown.
		Expect(text).To(ContainSubstring("!starlark"))
		Expect(text).To(ContainSubstring("host.os"))
		Expect(text).To(ContainSubstring("host.arch"))
	})

	It("documents every registered action (discovery, not a hardcoded list)", func() {
		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"pkg", "explain"})
		Expect(root.Execute()).To(Succeed())

		text := out.String()
		Expect(action.Registry).ToNot(BeEmpty())
		for name := range action.Registry {
			Expect(text).To(ContainSubstring(name),
				"action %q from the registry must appear in `pkg explain` output", name)
		}
	})

	It("emits a valid cli-result/v2 envelope listing the same actions under --format json", func() {
		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"pkg", "explain", "--format", "json"})
		Expect(root.Execute()).To(Succeed())

		var result schema.CLIResult
		Expect(json.Unmarshal([]byte(strings.TrimSpace(out.String())), &result)).To(Succeed())
		Expect(result.Schema).To(Equal("polypkg.cli-result/v2"))
		Expect(result.Command).To(Equal("pkg explain"))
		Expect(result.Status).To(Equal("ok"))

		actions, ok := result.Data["actions"].([]any)
		Expect(ok).To(BeTrue(), "data.actions must be a JSON array")
		got := map[string]bool{}
		for _, a := range actions {
			m, ok := a.(map[string]any)
			Expect(ok).To(BeTrue())
			name, ok := m["name"].(string)
			Expect(ok).To(BeTrue())
			got[name] = true
		}
		for name := range action.Registry {
			Expect(got).To(HaveKey(name),
				"action %q from the registry must appear in the json envelope", name)
		}

		phases, ok := result.Data["phases"].([]any)
		Expect(ok).To(BeTrue(), "data.phases must be a JSON array")
		Expect(phases).To(HaveLen(6))
	})

	It("documents per-platform artifacts before fat !starlark artifacts", func() {
		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"pkg", "explain"})
		Expect(root.Execute()).To(Succeed())

		text := out.String()
		Expect(text).To(ContainSubstring("Per-platform artifacts"))
		Expect(text).To(ContainSubstring(platformExample))
		Expect(text).To(ContainSubstring(`platform-agnostic ("any")`))
		Expect(text).To(ContainSubstring("Fat artifact"))
		Expect(text).NotTo(ContainSubstring("ships a single artifact by default"))
		Expect(strings.Index(text, platformExample)).To(BeNumerically("<", strings.Index(text, starlarkExample)))
	})

	It("shows a platform example that the producer grammar accepts", func() {
		Expect(platform.ValidateProducer(strings.TrimPrefix(platformExample, "platform: "))).To(Succeed())
	})

	It("adds the platform example to the json envelope without removing existing keys", func() {
		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"pkg", "explain", "--format", "json"})
		Expect(root.Execute()).To(Succeed())

		var result schema.CLIResult
		Expect(json.Unmarshal([]byte(strings.TrimSpace(out.String())), &result)).To(Succeed())
		Expect(result.Data["platform_example"]).To(Equal(platformExample))
		Expect(result.Data["starlark_example"]).To(Equal(starlarkExample))
		notes, ok := result.Data["notes"].([]any)
		Expect(ok).To(BeTrue(), "data.notes must be a JSON array")
		Expect(notes).To(HaveLen(4))
		Expect(notes).To(ContainElement(ContainSubstring("platform: <os>/<arch>")))
	})

	It("lists the extract action with the parameters its registry entry declares", func() {
		spec, ok := action.Registry["extract"]
		Expect(ok).To(BeTrue(), "the extract action must be registered")

		root := NewRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"pkg", "explain"})
		Expect(root.Execute()).To(Succeed())

		var row string
		for _, line := range strings.Split(out.String(), "\n") {
			if f := strings.Fields(line); len(f) > 0 && f[0] == "extract" {
				row = line
			}
		}
		Expect(row).NotTo(BeEmpty(), "pkg explain must print an extract row")
		Expect(row).To(ContainSubstring(formatParams(spec.Params)))
		Expect(row).To(ContainSubstring("src* (path)"))
		Expect(row).To(ContainSubstring("dest* (path)"))
		Expect(row).To(ContainSubstring("strip_components (int)"))
		Expect(row).To(ContainSubstring("include ("))
		// drift is an action-level key, not a parameter.
		Expect(row).NotTo(ContainSubstring("drift"))

		root = NewRootCmd()
		var jout bytes.Buffer
		root.SetOut(&jout)
		root.SetErr(&jout)
		root.SetArgs([]string{"pkg", "explain", "--format", "json"})
		Expect(root.Execute()).To(Succeed())

		var result schema.CLIResult
		Expect(json.Unmarshal([]byte(strings.TrimSpace(jout.String())), &result)).To(Succeed())
		actions, ok := result.Data["actions"].([]any)
		Expect(ok).To(BeTrue(), "data.actions must be a JSON array")
		var params []any
		for _, a := range actions {
			m, ok := a.(map[string]any)
			Expect(ok).To(BeTrue())
			if m["name"] == "extract" {
				params, ok = m["params"].([]any)
				Expect(ok).To(BeTrue(), "extract params must be a JSON array")
			}
		}
		required := map[string]bool{}
		for _, p := range params {
			m, ok := p.(map[string]any)
			Expect(ok).To(BeTrue())
			name, ok := m["name"].(string)
			Expect(ok).To(BeTrue())
			req, ok := m["required"].(bool)
			Expect(ok).To(BeTrue())
			required[name] = req
		}
		Expect(required).To(Equal(map[string]bool{
			"src": true, "dest": true, "strip_components": false, "include": false,
		}))
	})
})

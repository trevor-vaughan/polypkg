package integration

import (
	"archive/tar"
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/klauspost/compress/zstd"

	"github.com/trevor-vaughan/polypkg/internal/cli"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// buildHelloPackageJSONC builds a tar.zst hello package whose recipe is
// polypkg.jsonc (semantically identical to buildHelloPackage's polypkg.yaml).
func buildHelloPackageJSONC(t testing.TB) []byte {
	t.Helper()
	g := NewWithT(t)
	jsonc := `{
  // hello package recipe in JSONC form
  "schema": "polypkg.package/v1",
  "name": "hello",
  "version": "1.0.0",
  "actions": [
    {
      "phase": "post-place",
      "action": "dir",
      "params": {
        "path": "$ACTIVE/hello/bin",
        "mode": "0o755"
      }
    },
    {
      "phase": "post-place",
      "action": "install",
      "params": {
        "src": "$PKG/content/bin/hi",
        "dest": "$ACTIVE/hello/bin/hi",
        "policy": "symlink"
      }
    }
  ]
}
`
	hi := "#!/bin/sh\necho hello from polypkg\n"

	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	files := []struct {
		name    string
		content string
		mode    int64
	}{
		{"polypkg.jsonc", jsonc, 0o644},
		{"content/bin/hi", hi, 0o755},
	}
	for _, f := range files {
		g.Expect(tw.WriteHeader(&tar.Header{
			Name: f.name, Size: int64(len(f.content)), Mode: f.mode,
		})).To(Succeed())
		_, err := tw.Write([]byte(f.content))
		g.Expect(err).NotTo(HaveOccurred())
	}
	g.Expect(tw.Close()).To(Succeed())

	var z bytes.Buffer
	enc, err := zstd.NewWriter(&z)
	g.Expect(err).NotTo(HaveOccurred())
	_, err = enc.Write(raw.Bytes())
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(enc.Close()).To(Succeed())
	return z.Bytes()
}

// installHelloProfileJSONC returns the JSONC equivalent of installHelloProfile's
// YAML body, with the repo URL and trust root substituted in.
func installHelloProfileJSONC(repoURL, trustRoot string) string {
	return `{
  // install-hello profile in JSONC
  "schema": "polypkg.spec/v1",
  "name": "install-hello",
  "scopes": {
    "user": { "substrate": "store", "prefix": "$XDG_DATA_HOME/polypkg" }
  },
  "sources": {
    "order": ["native"],
    "native": {
      "type": "polypkg-native",
      "url": "` + repoURL + `",
      "trust_root": "` + trustRoot + `"
    }
  },
  "packages": {
    "user": {
      "hello": { "version": "=1.0.0" }
    }
  }
}
`
}

// applyProfile writes the given profile body to profilePath and runs
// `polypkg apply <profilePath>`. Returns the command output and the error
// from cmd.Execute().
func applyProfile(t testing.TB, profilePath, profileBody string) (string, error) {
	t.Helper()
	g := NewWithT(t)
	g.Expect(os.WriteFile(profilePath, []byte(profileBody), 0o644)).To(Succeed())
	cmd := cli.NewRootCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"apply", profilePath})
	return out.String(), cmd.Execute()
}

// readManifestForGen1 reads the gen-1 manifest from the current XDG_DATA_HOME.
func readManifestForGen1(t testing.TB) *schema.Manifest {
	t.Helper()
	g := NewWithT(t)
	dataHome := os.Getenv("XDG_DATA_HOME")
	g.Expect(dataHome).NotTo(BeEmpty(), "IsolatedEnv must set XDG_DATA_HOME")
	f, err := os.Open(filepath.Join(dataHome, "polypkg", "generations", "1", "manifest.json"))
	g.Expect(err).NotTo(HaveOccurred())
	defer f.Close()
	m, err := schema.ParseManifest(f)
	g.Expect(err).NotTo(HaveOccurred())
	return m
}

var _ = Describe("apply: JSONC profile + JSONC package equivalence", func() {
	It("produces a manifest equivalent to the YAML-sourced run", func() {
		t := GinkgoTB()

		// Build the YAML package artifact once. Both apply runs will resolve
		// this same artifact so their content_hash fields are identical.
		// The second run additionally exercises a JSONC *profile* and a JSONC
		// *package recipe* (same logical content as the YAML recipe) by
		// replacing the repo's artifact with the JSONC variant between runs.
		pkgYAML := buildHelloPackage(t)

		// Single repo directory and server shared across both apply runs so
		// that source_url in the manifest entries is byte-identical.
		repoDir := t.TempDir()

		// First signing: index + trust chain for the YAML artifact.
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: pkgYAML})
		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		// Run 1: YAML profile + YAML package in an isolated data home.
		IsolatedEnv(t)
		profile1 := filepath.Join(t.TempDir(), "profile.yaml")
		_, errY := applyProfile(t, profile1, installHelloProfile(t, srv.URL, trustRoot))
		Expect(errY).NotTo(HaveOccurred(), "yaml apply must succeed")
		yamlManifest := readManifestForGen1(t)

		// Re-sign the repo with the JSONC artifact (overwrites index + artifact
		// in place so the HTTP server continues to serve from the same repoDir).
		// The trust chain (trust.json + anchor.pub) is reissued at serial 2.
		// We capture the new trust root because a new anchor keypair was generated.
		pkgJSONC := buildHelloPackageJSONC(t)
		trustRoot2 := signRepo(t, repoDir, "native", 2,
			indexPkg{name: "hello", version: "1.0.0", artifact: pkgJSONC})

		// Run 2: JSONC profile + JSONC package in a fresh data home.
		IsolatedEnv(t)
		profile2 := filepath.Join(t.TempDir(), "profile.jsonc")
		_, errJ := applyProfile(t, profile2, installHelloProfileJSONC(srv.URL, trustRoot2))
		Expect(errJ).NotTo(HaveOccurred(), "jsonc apply must succeed")
		jsoncManifest := readManifestForGen1(t)

		// Normalize the only fields that legitimately differ run-to-run:
		// the timestamp records when the command was invoked, and the
		// content_hash reflects the artifact bytes (YAML vs JSONC recipes
		// produce distinct tar.zst blobs). Everything else — schema, scope,
		// generation, package name, version, source_url — must be identical.
		yamlManifest.ProducedBy.Timestamp = jsoncManifest.ProducedBy.Timestamp
		for i := range yamlManifest.Entries {
			if i < len(jsoncManifest.Entries) {
				yamlManifest.Entries[i].ContentHash = jsoncManifest.Entries[i].ContentHash
			}
		}

		Expect(jsoncManifest).To(Equal(yamlManifest),
			"the manifest from a JSONC profile must be structurally identical to the YAML manifest "+
				"(timestamp and content_hash normalized; everything else must match exactly)")
	})
})

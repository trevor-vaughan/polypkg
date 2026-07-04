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
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("resolve", func() {
	It("resolves a transitive dependency from the signed native repo", func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		repoDir := t.TempDir()

		appPkg := buildTarZst(t, map[string]string{
			"polypkg.yaml": "schema: polypkg.package/v1\nname: app\nversion: 1.0.0\n" +
				"depends:\n  - name: lib\n    version: \"^1.0\"\nactions: []\n",
		})
		libPkg := buildTarZst(t, map[string]string{
			"polypkg.yaml": "schema: polypkg.package/v1\nname: lib\nversion: 1.2.0\nactions: []\n",
		})
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "app", version: "1.0.0", artifact: appPkg, depends: []schema.Relation{{Name: "lib", Version: "^1.0"}}},
			indexPkg{name: "lib", version: "1.2.0", artifact: libPkg},
		)

		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		profile := "schema: polypkg.spec/v1\n" +
			"name: app-test\n" +
			"scopes:\n  user:\n    substrate: store\n    prefix: $XDG_DATA_HOME/polypkg\n" +
			"sources:\n  order: [native]\n  native:\n    type: polypkg-native\n" +
			"    url: " + srv.URL + "\n    trust_root: " + trustRoot + "\n" +
			"packages:\n  user:\n    app:\n      version: \"^1.0\"\n"
		profilePath := filepath.Join(t.TempDir(), "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(profile), 0o644)).To(Succeed())

		apply := cli.NewRootCmd()
		var out bytes.Buffer
		apply.SetOut(&out)
		apply.SetArgs([]string{"apply", profilePath})
		Expect(apply.Execute()).To(Succeed())
		Expect(out.String()).To(ContainSubstring("applied generation 1"))

		dataHome := os.Getenv("XDG_DATA_HOME")
		manifest, err := os.ReadFile(filepath.Join(dataHome, "polypkg", "generations", "1", "manifest.json"))
		Expect(err).NotTo(HaveOccurred())
		Expect(string(manifest)).To(ContainSubstring("app"))
		Expect(string(manifest)).To(ContainSubstring("lib"))
	})

	It("fetches an artifact by its index-declared path", func() {
		t := GinkgoTB()
		IsolatedEnv(t)
		repoDir := t.TempDir()

		pkg := buildTarZst(t, map[string]string{
			"polypkg.yaml": "schema: polypkg.package/v1\nname: app\nversion: 1.0.0\nactions: []\n",
		})
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "app", version: "1.0.0", artifact: pkg, artifactName: "blobs/app_v1.tzst"})

		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		profile := "schema: polypkg.spec/v1\nname: app-test\n" +
			"scopes:\n  user:\n    substrate: store\n    prefix: $XDG_DATA_HOME/polypkg\n" +
			"sources:\n  order: [native]\n  native:\n    type: polypkg-native\n" +
			"    url: " + srv.URL + "\n    trust_root: " + trustRoot + "\n" +
			"packages:\n  user:\n    app:\n      version: \"^1.0\"\n"
		profilePath := filepath.Join(t.TempDir(), "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(profile), 0o644)).To(Succeed())

		apply := cli.NewRootCmd()
		var out bytes.Buffer
		apply.SetOut(&out)
		apply.SetArgs([]string{"apply", profilePath})
		Expect(apply.Execute()).To(Succeed())
		Expect(out.String()).To(ContainSubstring("applied generation 1"))
	})

	It("rejects an index hash mismatch even when the comment claim verifies", func() {
		t := GinkgoTB()
		IsolatedEnv(t)

		repoDir := t.TempDir()

		served := buildTarZst(t, map[string]string{
			"polypkg.yaml": "schema: polypkg.package/v1\nname: app\nversion: 1.0.0\nactions: []\n",
		})
		other := buildTarZst(t, map[string]string{
			"polypkg.yaml": "schema: polypkg.package/v1\nname: app\nversion: 1.0.0\nactions: []\n# differ\n",
		})
		anchor := newMinisignKeypair(t)
		signer := newMinisignKeypair(t)
		publishTrustDoc(t, repoDir, "native", anchor, 1,
			[]trustKeySpec{{kp: signer, roles: []string{"index", "artifact"}}}, nil)
		Expect(os.WriteFile(filepath.Join(repoDir, "app-1.0.0.tar.zst"), served, 0o644)).To(Succeed())
		// Sign over the SERVED bytes but claim the index's (other) hash, so the
		// comment-claim check passes and the computed-vs-index hash-binding rejects.
		Expect(os.WriteFile(filepath.Join(repoDir, "app-1.0.0.tar.zst.minisig"),
			[]byte(signer.signWithComment(served, "name=app version=1.0.0 hash="+blakeHash(other))), 0o644)).To(Succeed())
		publishIndex(t, repoDir, signer, 1, indexPkg{name: "app", version: "1.0.0", artifact: other})

		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		defer srv.Close()

		trustRoot := writeTrustRoot(t, anchor)

		profile := "schema: polypkg.spec/v1\nname: app-test\n" +
			"scopes:\n  user:\n    substrate: store\n    prefix: $XDG_DATA_HOME/polypkg\n" +
			"sources:\n  order: [native]\n  native:\n    type: polypkg-native\n" +
			"    url: " + srv.URL + "\n    trust_root: " + trustRoot + "\n" +
			"packages:\n  user:\n    app:\n      version: \"^1.0\"\n"
		profilePath := filepath.Join(t.TempDir(), "profile.yaml")
		Expect(os.WriteFile(profilePath, []byte(profile), 0o644)).To(Succeed())

		cmd := cli.NewRootCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"apply", profilePath})
		err := cmd.Execute()
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("hash mismatch"))
	})
})

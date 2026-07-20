package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/trevor-vaughan/polypkg/internal/lock"
	"github.com/trevor-vaughan/polypkg/internal/planner"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

var _ = Describe("FetchCatalog", func() {
	It("returns a catalog with the fixture's two versions from a signed repo", func() {
		t := GinkgoTB()
		root := IsolatedEnv(t)
		stateHome := filepath.Join(root, "state", "polypkg")
		Expect(os.MkdirAll(stateHome, 0o700)).To(Succeed())

		// Build two hello artifacts at distinct versions.
		artifact100 := buildTarZst(t, map[string]string{
			"polypkg.yaml": "schema: polypkg.package/v1\nname: hello\nversion: 1.0.0\nactions: []\n",
		})
		artifact110 := buildTarZst(t, map[string]string{
			"polypkg.yaml": "schema: polypkg.package/v1\nname: hello\nversion: 1.1.0\nactions: []\n",
		})

		repoDir := t.TempDir()
		trustRoot := signRepo(t, repoDir, "native", 1,
			indexPkg{name: "hello", version: "1.0.0", artifact: artifact100},
			indexPkg{name: "hello", version: "1.1.0", artifact: artifact110},
		)

		srv := httptest.NewServer(http.FileServer(http.Dir(repoDir)))
		DeferCleanup(srv.Close)

		// Build a minimal profile with hello in the user scope so FetchCatalog
		// sees at least one package requirement and performs the full fetch.
		p := &schema.Profile{
			Schema: "polypkg.spec/v1",
			Name:   "fetchcatalog-test",
			Scopes: map[string]schema.ScopeSpec{
				"user": {Substrate: "store"},
			},
			Sources: schema.SourcesSpec{
				Order: []string{"native"},
				Sources: map[string]schema.SourceBackend{
					"native": {
						Type:      "polypkg-native",
						URL:       srv.URL,
						TrustRoot: trustRoot,
					},
				},
			},
			Packages: map[string]map[string]schema.PackageRef{
				"user": {
					"hello": {Version: ""},
				},
			},
		}

		opts := planner.Options{
			StateHome: stateHome,
			Scope:     "user",
		}

		// FetchCatalog requires the caller to hold the apply lock (doc contract).
		lockPath := filepath.Join(stateHome, "apply.lock")
		l, err := lock.Acquire(context.Background(), lockPath, lock.Options{
			TxID:    "fetchcatalog-test",
			Command: "go test",
		})
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = l.Release() }()

		fr, err := planner.FetchCatalog(context.Background(), p, opts)
		Expect(err).NotTo(HaveOccurred())
		Expect(fr).NotTo(BeNil())
		Expect(fr.Catalog).NotTo(BeNil())

		versions := fr.Catalog.Versions("hello")
		Expect(versions).To(ConsistOf("1.0.0", "1.1.0"),
			"catalog must expose both fixture versions")
	})

	It("returns a nil Catalog when the scope requests no packages", func() {
		t := GinkgoTB()
		root := IsolatedEnv(t)
		stateHome := filepath.Join(root, "state", "polypkg")
		Expect(os.MkdirAll(stateHome, 0o700)).To(Succeed())

		p := &schema.Profile{
			Schema: "polypkg.spec/v1",
			Name:   "empty-test",
			Scopes: map[string]schema.ScopeSpec{
				"user": {Substrate: "store"},
			},
			Sources: schema.SourcesSpec{
				Order: []string{"native"},
				Sources: map[string]schema.SourceBackend{
					"native": {
						Type:      "polypkg-native",
						URL:       "http://unreachable.invalid",
						TrustRoot: "/dev/null",
					},
				},
			},
			Packages: map[string]map[string]schema.PackageRef{},
		}

		opts := planner.Options{
			StateHome: stateHome,
			Scope:     "user",
		}

		lockPath := filepath.Join(stateHome, "apply.lock")
		l, err := lock.Acquire(context.Background(), lockPath, lock.Options{
			TxID:    "fetchcatalog-empty-test",
			Command: "go test",
		})
		Expect(err).NotTo(HaveOccurred())
		defer func() { _ = l.Release() }()

		fr, err := planner.FetchCatalog(context.Background(), p, opts)
		Expect(err).NotTo(HaveOccurred())
		Expect(fr).NotTo(BeNil())
		Expect(fr.Catalog).To(BeNil(), "empty scope must return nil Catalog without touching the network")
	})
})

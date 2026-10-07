package integration

import (
	"archive/tar"
	"bytes"
	"cmp"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/onsi/gomega"
	"github.com/trevor-vaughan/polypkg/internal/cli"
	"github.com/trevor-vaughan/polypkg/internal/platform"
	"github.com/trevor-vaughan/polypkg/internal/schema"
	"lukechampine.com/blake3"
)

// IsolatedEnv points HOME and every XDG base directory at a per-test temp
// directory so polypkg state is fully isolated and nothing falls through to
// the invoking user's home. XDG_BIN_HOME matters most: the default-on bridge
// that runs during apply/rollback would otherwise write the real ~/.local/bin.
func IsolatedEnv(t testing.TB) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range []struct {
		env, name string
		mode      os.FileMode
	}{
		{"HOME", "home", 0o755},
		{"XDG_DATA_HOME", "data", 0o755},
		{"XDG_STATE_HOME", "state", 0o755},
		{"XDG_CONFIG_HOME", "config", 0o755},
		{"XDG_CACHE_HOME", "cache", 0o755},
		{"XDG_BIN_HOME", "bin", 0o755},
		// The XDG spec requires the runtime dir to be owner-only.
		{"XDG_RUNTIME_DIR", "runtime", 0o700},
		{"XDG_CONFIG_DIRS", "config-dirs", 0o755},
		{"XDG_DATA_DIRS", "data-dirs", 0o755},
	} {
		dir := filepath.Join(root, d.name)
		if err := os.MkdirAll(dir, d.mode); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		t.Setenv(d.env, dir)
	}
	return root
}

// minisignKeypair is a test-only minisign keypair built on stdlib ed25519. Its
// publicKeyFile and sign outputs use the exact on-disk format that the
// production trust path (github.com/jedisct1/go-minisign) accepts, so apply's
// signature enforcement can be exercised end to end without external tooling.
type minisignKeypair struct {
	pub   ed25519.PublicKey
	priv  ed25519.PrivateKey
	keyID [8]byte
}

func newMinisignKeypair(t testing.TB) minisignKeypair {
	t.Helper()
	g := gomega.NewWithT(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	var keyID [8]byte
	_, err = rand.Read(keyID[:])
	g.Expect(err).NotTo(gomega.HaveOccurred())
	return minisignKeypair{pub: pub, priv: priv, keyID: keyID}
}

// publicKeyFile returns the content of a minisign .pub file for this keypair.
func (k minisignKeypair) publicKeyFile() string {
	bin := append([]byte{'E', 'd'}, k.keyID[:]...)
	bin = append(bin, k.pub...)
	return "untrusted comment: polypkg test public key\n" +
		base64.StdEncoding.EncodeToString(bin) + "\n"
}

// signWithComment returns a .minisig over data with the given trusted comment.
func (k minisignKeypair) signWithComment(data []byte, trustedComment string) string {
	sig := ed25519.Sign(k.priv, data)
	sigBin := append([]byte{'E', 'd'}, k.keyID[:]...)
	sigBin = append(sigBin, sig...)
	globalMsg := append(append([]byte{}, sig...), []byte(trustedComment)...)
	globalSig := ed25519.Sign(k.priv, globalMsg)
	return "untrusted comment: polypkg test signature\n" +
		base64.StdEncoding.EncodeToString(sigBin) + "\n" +
		"trusted comment: " + trustedComment + "\n" +
		base64.StdEncoding.EncodeToString(globalSig) + "\n"
}

// sign signs data with a default comment (used to sign trust documents, whose
// comment polypkg does not constrain).
func (k minisignKeypair) sign(data []byte) string {
	return k.signWithComment(data, "timestamp:0\tfile:doc")
}

// publicKeyBase64 returns just the base64 key line stored in a trust document.
func (k minisignKeypair) publicKeyBase64() string {
	bin := append([]byte{'E', 'd'}, k.keyID[:]...)
	bin = append(bin, k.pub...)
	return base64.StdEncoding.EncodeToString(bin)
}

// keyIDHex returns the 16-hex-char KeyId.
func (k minisignKeypair) keyIDHex() string { return hex.EncodeToString(k.keyID[:]) }

// blakeHash returns the "blake3:<hex>" digest of b.
func blakeHash(b []byte) string {
	h := blake3.New(32, nil)
	_, _ = h.Write(b)
	return "blake3:" + hex.EncodeToString(h.Sum(nil))
}

// signArtifact signs data with the comment apply requires of an artifact.
// plat is the index entry's platform; "" (platform-agnostic) signs the
// reserved token platform.Any, exactly as the producer does.
func (k minisignKeypair) signArtifact(name, version, plat string, data []byte) string {
	return k.signWithComment(data, fmt.Sprintf("name=%s version=%s platform=%s hash=%s",
		name, version, cmp.Or(plat, platform.Any), blakeHash(data)))
}

// signIndex signs index bytes with the comment carrying the monotonic serial.
func (k minisignKeypair) signIndex(serial uint64, data []byte) string {
	return k.signWithComment(data, fmt.Sprintf("serial=%d ts=2026-01-01T00:00:00Z", serial))
}

// trustKeySpec is one key to list in a published trust document.
type trustKeySpec struct {
	kp    minisignKeypair
	roles []string
}

// publishTrustDoc writes an anchor-signed polypkg.trust/v2 document into repoDir.
func publishTrustDoc(t testing.TB, repoDir, source string, anchor minisignKeypair, serial uint64, keys []trustKeySpec, revoked []string) {
	t.Helper()
	g := gomega.NewWithT(t)
	td := schema.TrustDoc{Schema: "polypkg.trust/v2", Source: source, Serial: serial, IssuedAt: "2026-01-01T00:00:00Z", Expires: "2099-01-01T00:00:00Z"}
	for _, k := range keys {
		td.Keys = append(td.Keys, schema.TrustKey{ID: k.kp.keyIDHex(), Pubkey: k.kp.publicKeyBase64(), Roles: k.roles})
	}
	td.Revoked = revoked
	raw, err := json.Marshal(td)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(os.WriteFile(filepath.Join(repoDir, "trust.json"), raw, 0o644)).To(gomega.Succeed())
	g.Expect(os.WriteFile(filepath.Join(repoDir, "trust.json.minisig"), []byte(anchor.sign(raw)), 0o644)).To(gomega.Succeed())
}

// writeArtifact writes an artifact and its name/version/platform/hash-bound
// signature. plat is the platform of the index entry the artifact is
// published under ("" = platform-agnostic).
func writeArtifact(t testing.TB, repoDir string, key minisignKeypair, name, version, plat, artName string, content []byte) {
	t.Helper()
	g := gomega.NewWithT(t)
	if artName == "" {
		artName = fmt.Sprintf("%s-%s.tar.zst", name, version)
	}
	full := filepath.Join(repoDir, artName)
	g.Expect(os.MkdirAll(filepath.Dir(full), 0o755)).To(gomega.Succeed())
	g.Expect(os.WriteFile(full, content, 0o644)).To(gomega.Succeed())
	g.Expect(os.WriteFile(full+".minisig", []byte(key.signArtifact(name, version, plat, content)), 0o644)).To(gomega.Succeed())
}

// writeTrustRoot writes anchor's .pub to a temp file and returns its path.
func writeTrustRoot(t testing.TB, anchor minisignKeypair) string {
	t.Helper()
	g := gomega.NewWithT(t)
	p := filepath.Join(t.TempDir(), "anchor.pub")
	g.Expect(os.WriteFile(p, []byte(anchor.publicKeyFile()), 0o644)).To(gomega.Succeed())
	return p
}

// signRepo sets up a complete trust chain for repoDir: an anchor, one dual-role
// signing key, a published trust document and signed index (both at `serial`),
// and each package's artifact bytes + signature. It returns the trust_root path.
func signRepo(t testing.TB, repoDir, source string, serial uint64, pkgs ...indexPkg) string {
	t.Helper()
	anchor := newMinisignKeypair(t)
	signer := newMinisignKeypair(t)
	publishTrustDoc(t, repoDir, source, anchor, serial,
		[]trustKeySpec{{kp: signer, roles: []string{"index", "artifact"}}}, nil)
	publishIndex(t, repoDir, signer, serial, pkgs...)
	for _, p := range pkgs {
		writeArtifact(t, repoDir, signer, p.name, p.version, p.platform, p.artifactName, p.artifact)
	}
	return writeTrustRoot(t, anchor)
}

// installHelloProfile renders the install-hello fixture with a concrete repo
// URL and trust-root path.
func installHelloProfile(t testing.TB, repoURL, trustRoot string) string {
	t.Helper()
	g := gomega.NewWithT(t)
	tmpl, err := os.ReadFile(filepath.Join("..", "fixtures", "profiles", "install-hello.yaml"))
	g.Expect(err).NotTo(gomega.HaveOccurred())
	p := strings.ReplaceAll(string(tmpl), "FIXTURE_REPO_URL", repoURL)
	return strings.ReplaceAll(p, "FIXTURE_TRUST_ROOT", trustRoot)
}

// buildTarZst creates an in-memory tar.zst archive from the given file map
// (name -> content) and returns the compressed bytes.
func buildTarZst(t testing.TB, files map[string]string) []byte {
	t.Helper()
	g := gomega.NewWithT(t)
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for name, content := range files {
		g.Expect(tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(content)), Mode: 0o644})).To(gomega.Succeed())
		_, err := io.WriteString(tw, content)
		g.Expect(err).NotTo(gomega.HaveOccurred())
	}
	g.Expect(tw.Close()).To(gomega.Succeed())
	var z bytes.Buffer
	enc, err := zstd.NewWriter(&z)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	_, err = enc.Write(raw.Bytes())
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(enc.Close()).To(gomega.Succeed())
	return z.Bytes()
}

// buildPkg builds a minimal tar.zst package that places content/bin/<name> as a
// symlink, parameterized by name/version/script.
func buildPkg(t testing.TB, name, version, script string) []byte {
	t.Helper()
	manifest := fmt.Sprintf(`schema: polypkg.package/v1
name: %s
version: %s
actions:
  - phase: post-place
    action: dir
    params:
      path: $ACTIVE/%s/bin
      mode: "0o755"
  - phase: post-place
    action: install
    params:
      src: $PKG/content/bin/%s
      dest: $ACTIVE/%s/bin/%s
      policy: symlink
`, name, version, name, name, name, name)
	return buildTarZst(t, map[string]string{
		"polypkg.yaml":                     manifest,
		filepath.Join("content/bin", name): script,
	})
}

// buildHelloMissingSource builds a hello package at version whose install
// action names a source file the artifact does not contain. The package is
// valid to publish and to resolve; only its apply fails, after any profile
// edit is written, and the failure needs no permission trick, so it fires
// under root too. Specs use it to drive the restore-on-failure paths.
func buildHelloMissingSource(t testing.TB, version string) []byte {
	t.Helper()
	manifest := fmt.Sprintf(`schema: polypkg.package/v1
name: hello
version: %s
actions:
  - phase: post-place
    action: install
    params:
      src: $PKG/content/bin/missing
      dest: $ACTIVE/hello/bin/hi
      policy: symlink
`, version)
	return buildTarZst(t, map[string]string{"polypkg.yaml": manifest})
}

// indexPkg describes one package to publish into a signed test index.
type indexPkg struct {
	name     string
	version  string
	artifact []byte
	// platform is the entry's platform ("" = platform-agnostic). publishIndex
	// writes it to the entry and signRepo signs it into the artifact claim.
	platform string
	// artifactName overrides the published Artifact path. When empty, it
	// defaults to the conventional "<name>-<version>.tar.zst".
	artifactName string
	attestations []schema.AttestationRef
	depends      []schema.Relation
	recommends   []schema.Relation
	suggests     []schema.Relation
	provides     []schema.Relation
	conflicts    []schema.Relation
	obsoletes    []schema.Relation
}

// publishTrustDocToPath writes an anchor-signed trust document to an explicit
// file path (plus "<path>.minisig"), for the out-of-band trust_doc path.
func publishTrustDocToPath(t testing.TB, path, source string, anchor minisignKeypair, serial uint64, keys []trustKeySpec, revoked []string) {
	t.Helper()
	g := gomega.NewWithT(t)
	td := schema.TrustDoc{Schema: "polypkg.trust/v2", Source: source, Serial: serial, IssuedAt: "2026-01-01T00:00:00Z", Expires: "2099-01-01T00:00:00Z"}
	for _, k := range keys {
		td.Keys = append(td.Keys, schema.TrustKey{ID: k.kp.keyIDHex(), Pubkey: k.kp.publicKeyBase64(), Roles: k.roles})
	}
	td.Revoked = revoked
	raw, err := json.Marshal(td)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(os.WriteFile(path, raw, 0o644)).To(gomega.Succeed())
	g.Expect(os.WriteFile(path+".minisig", []byte(anchor.sign(raw)), 0o644)).To(gomega.Succeed())
}

// runUnlinkInProcess runs `polypkg unlink` in-process via a fresh root command
// under the current IsolatedEnv, returning combined stdout+stderr and the
// execute error.
func runUnlinkInProcess() (string, error) {
	root := cli.NewRootCmd()
	root.SilenceUsage, root.SilenceErrors = true, true
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"unlink"})
	return out.String(), root.Execute()
}

// publishIndex writes a signed index.json (+ .minisig) into repoDir describing
// pkgs, signed by indexKey with the monotonic serial in the trusted comment.
// content_hash is computed over each artifact's bytes. Callers still publish the
// artifact files and their .minisig separately (see writeArtifact).
func publishIndex(t testing.TB, repoDir string, indexKey minisignKeypair, serial uint64, pkgs ...indexPkg) {
	t.Helper()
	g := gomega.NewWithT(t)
	idx := schema.Index{Schema: "polypkg.index/v3", Expires: "2099-01-01T00:00:00Z", Packages: map[string][]schema.IndexEntry{}}
	for _, p := range pkgs {
		artifact := p.artifactName
		if artifact == "" {
			artifact = fmt.Sprintf("%s-%s.tar.zst", p.name, p.version)
		}
		idx.Packages[p.name] = append(idx.Packages[p.name], schema.IndexEntry{
			Version:      p.version,
			ContentHash:  blakeHash(p.artifact),
			Artifact:     artifact,
			Platform:     p.platform,
			Attestations: p.attestations,
			Depends:      p.depends,
			Recommends:   p.recommends,
			Suggests:     p.suggests,
			Provides:     p.provides,
			Conflicts:    p.conflicts,
			Obsoletes:    p.obsoletes,
		})
	}
	raw, err := json.Marshal(idx)
	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(os.WriteFile(filepath.Join(repoDir, "index.json"), raw, 0o644)).To(gomega.Succeed())
	g.Expect(os.WriteFile(filepath.Join(repoDir, "index.json.minisig"), []byte(indexKey.signIndex(serial, raw)), 0o644)).To(gomega.Succeed())
}

package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trevor-vaughan/polypkg/internal/repo"
	"github.com/trevor-vaughan/polypkg/internal/schema"
)

// sourceProbeProfile sandboxes HOME and the XDG directories, creates a
// profile whose one source is "initial" through `polypkg init`, points
// POLYPKG_PROFILE at it, and returns the profile path and its config dir.
func sourceProbeProfile(t *testing.T) (profilePath, cfgDir string) {
	t.Helper()
	root := sandboxUserEnv(t)
	t.Setenv("POLYPKG_PROFILE", "")
	kp, err := repo.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, "initial.pub")
	if err := os.WriteFile(keyPath, []byte(kp.PublicKeyFile("initial test key")), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := runRepo(t, nil, "init", "--source-url", "file:///srv/initial",
		"--trust-root", keyPath, "--source-name", "initial"); err != nil {
		t.Fatalf("init: %v (out=%s)", err, out)
	}
	cfgDir = filepath.Join(root, "config", "polypkg")
	profilePath = filepath.Join(cfgDir, "profile.yaml")
	t.Setenv("POLYPKG_PROFILE", profilePath)
	return profilePath, cfgDir
}

// profileSources parses the profile at path and returns its sources.
func profileSources(t *testing.T, path string) map[string]schema.SourceBackend {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p, err := schema.ParseProfile(f, path)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return p.Sources.Sources
}

func TestSourceAddVerifiesTheSourceAgainstItsTrustRoot(t *testing.T) {
	profilePath, _ := sourceProbeProfile(t)
	upstream, upTrust := buildUpstreamRepo(t) // publishes source "example"

	out, err := runRepo(t, nil, "--format", "json", "source", "add", "example",
		"--url", "file://"+upstream, "--trust-root", upTrust)
	if err != nil {
		t.Fatalf("source add: %v (out=%s)", err, out)
	}
	if strings.Contains(out, "warning:") {
		t.Fatalf("a source that verifies drew a warning:\n%s", out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	res, err := schema.ParseCLIResult(strings.NewReader(lines[len(lines)-1]))
	if err != nil {
		t.Fatalf("parse result: %v (out=%s)", err, out)
	}
	if res.Data["verified"] != true {
		t.Fatalf("data.verified = %v, want true", res.Data["verified"])
	}
	if w, ok := res.Data["warning"]; ok {
		t.Fatalf("a source that verifies carries data.warning %q", w)
	}
	if _, ok := profileSources(t, profilePath)["example"]; !ok {
		t.Fatal("source example was not added")
	}
}

func TestSourceAddRefusesASourcePublishedUnderAnotherName(t *testing.T) {
	profilePath, cfgDir := sourceProbeProfile(t)
	upstream, upTrust := buildUpstreamRepo(t) // publishes source "example"

	_, err := runRepo(t, nil, "source", "add", "other", "--url", "file://"+upstream, "--trust-root", upTrust)
	var ce *CLIError
	if !errors.As(err, &ce) {
		t.Fatalf("want a *CLIError, got %T: %v", err, err)
	}
	if !strings.Contains(ce.Msg, `publishes source "example"`) {
		t.Fatalf("Msg = %q, want it to name the published source", ce.Msg)
	}
	if !strings.Contains(ce.Hint, "polypkg source add example") {
		t.Fatalf("Hint = %q, want it to suggest the published name", ce.Hint)
	}
	if _, ok := profileSources(t, profilePath)["other"]; ok {
		t.Fatal("a refused source was written to the profile")
	}
	if _, serr := os.Stat(managedTrustRootPath(cfgDir, "other")); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("the refused source's pinned trust root was left behind (stat err %v)", serr)
	}
}

func TestSourceAddPointsAtTheExistingSourceWhenThePublishedNameIsTaken(t *testing.T) {
	sourceProbeProfile(t)
	upstream, upTrust := buildUpstreamRepo(t) // publishes source "example"
	if out, err := runRepo(t, nil, "source", "add", "example", "--url", "file://"+upstream, "--trust-root", upTrust); err != nil {
		t.Fatalf("source add example: %v (out=%s)", err, out)
	}

	_, err := runRepo(t, nil, "source", "add", "again", "--url", "file://"+upstream, "--trust-root", upTrust)
	var ce *CLIError
	if !errors.As(err, &ce) {
		t.Fatalf("want a *CLIError, got %T: %v", err, err)
	}
	if !strings.Contains(ce.Hint, `already has a source named "example"`) {
		t.Fatalf("Hint = %q, want it to point at the existing source", ce.Hint)
	}
}

func TestSourceAddRefusesATrustRootThatDidNotSignTheSource(t *testing.T) {
	_, cfgDir := sourceProbeProfile(t)
	upstream, _ := buildUpstreamRepo(t)
	kp, err := repo.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	wrong := filepath.Join(t.TempDir(), "wrong.pub")
	if err := os.WriteFile(wrong, []byte(kp.PublicKeyFile("unrelated key")), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = runRepo(t, nil, "source", "add", "example", "--url", "file://"+upstream, "--trust-root", wrong)
	var ce *CLIError
	if !errors.As(err, &ce) {
		t.Fatalf("want a *CLIError, got %T: %v", err, err)
	}
	if !strings.Contains(ce.Msg, "is not signed by the trust root you gave") {
		t.Fatalf("Msg = %q", ce.Msg)
	}
	if _, serr := os.Stat(managedTrustRootPath(cfgDir, "example")); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("the refused source's pinned trust root was left behind (stat err %v)", serr)
	}
}

func TestSourceAddWarnsButAddsASourceItCannotCheck(t *testing.T) {
	profilePath, _ := sourceProbeProfile(t)
	kp, err := repo.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(t.TempDir(), "late.pub")
	if err := os.WriteFile(pub, []byte(kp.PublicKeyFile("late key")), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "not-published-yet")

	out, err := runRepo(t, nil, "source", "add", "late", "--url", missing, "--trust-root", pub)
	if err != nil {
		t.Fatalf("source add of an unpublished source: %v (out=%s)", err, out)
	}
	// The url is named as a refusal names it: the file:// form the profile
	// records, once.
	if !strings.Contains(out, "warning: could not check source late at file://"+missing+" now (it does not serve trust.json)") {
		t.Fatalf("want a warning naming the source, its url and what is missing, got:\n%s", out)
	}
	if strings.Count(out, missing) != 1 {
		t.Fatalf("the warning names the url more than once:\n%s", out)
	}
	if _, ok := profileSources(t, profilePath)["late"]; !ok {
		t.Fatal("an uncheckable source must still be added")
	}
}

func TestSourceAddRefusesAnUnsupportedSourceType(t *testing.T) {
	sourceProbeProfile(t)
	upstream, upTrust := buildUpstreamRepo(t)

	_, err := runRepo(t, nil, "source", "add", "example", "--url", "file://"+upstream,
		"--trust-root", upTrust, "--type", "nope")
	var ce *CLIError
	if !errors.As(err, &ce) {
		t.Fatalf("want a *CLIError, got %T: %v", err, err)
	}
	if ce.Msg != `source type "nope" is not supported` {
		t.Fatalf("Msg = %q", ce.Msg)
	}
}

func TestSourceAddWarningNamesAnUnreachableHTTPSourceOnce(t *testing.T) {
	sourceProbeProfile(t)
	kp, err := repo.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(t.TempDir(), "down.pub")
	if err := os.WriteFile(pub, []byte(kp.PublicKeyFile("down key")), 0o600); err != nil {
		t.Fatal(err)
	}
	// Port 9 (discard) refuses connections.
	out, err := runRepo(t, nil, "source", "add", "down", "--url", "http://127.0.0.1:9/repo", "--trust-root", pub)
	if err != nil {
		t.Fatalf("source add of an unreachable source: %v (out=%s)", err, out)
	}
	if !strings.Contains(out, "warning: could not check source down at http://127.0.0.1:9/repo now (cannot reach it: ") {
		t.Fatalf("want a warning naming the url once and the network reason, got:\n%s", out)
	}
	if strings.Count(out, "127.0.0.1:9") != 1 {
		t.Fatalf("the warning names the url more than once:\n%s", out)
	}
}

// Under --format json the reason a source could not be checked is in the
// result too, not only on stderr.
func TestSourceAddJSONCarriesTheWarningOfAnUncheckedSource(t *testing.T) {
	sourceProbeProfile(t)
	kp, err := repo.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(t.TempDir(), "late.pub")
	if err := os.WriteFile(pub, []byte(kp.PublicKeyFile("late key")), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "not-published-yet")

	out, err := runRepo(t, nil, "--format", "json", "source", "add", "late", "--url", missing, "--trust-root", pub)
	if err != nil {
		t.Fatalf("source add: %v (out=%s)", err, out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	res, err := schema.ParseCLIResult(strings.NewReader(lines[len(lines)-1]))
	if err != nil {
		t.Fatalf("parse result: %v (out=%s)", err, out)
	}
	if res.Data["verified"] != false {
		t.Fatalf("data.verified = %v, want false", res.Data["verified"])
	}
	warning, _ := res.Data["warning"].(string)
	if !strings.Contains(warning, "it does not serve trust.json") {
		t.Fatalf("data.warning = %q, want the reason the check could not complete", warning)
	}
	if !strings.Contains(out, "warning: "+warning+"\n") {
		t.Fatalf("data.warning %q differs from the stderr warning:\n%s", warning, out)
	}
}

// Expired trust metadata is something the publisher fixes by re-signing, not
// a sign of the wrong key or name, so source add warns and adds the source.
func TestSourceAddWarnsButAddsASourceWhoseTrustMetadataHasExpired(t *testing.T) {
	profilePath, _ := sourceProbeProfile(t)
	upstream, upTrust, kp := buildUpstreamRepoReturningKey(t) // publishes source "example"
	trustPath := filepath.Join(upstream, "trust.json")
	raw, err := os.ReadFile(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	serial, ok := doc["serial"].(float64)
	if !ok {
		t.Fatalf("trust.json has no numeric serial: %s", raw)
	}
	doc["expires"] = "2000-01-01T00:00:00Z"
	expired, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustPath, expired, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustPath+".minisig", []byte(kp.SignTrust(uint64(serial), expired)), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := runRepo(t, nil, "--format", "json", "source", "add", "example", "--url", "file://"+upstream, "--trust-root", upTrust)
	if err != nil {
		t.Fatalf("source add of a source with expired metadata was refused: %v (out=%s)", err, out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	res, err := schema.ParseCLIResult(strings.NewReader(lines[len(lines)-1]))
	if err != nil {
		t.Fatalf("parse result: %v (out=%s)", err, out)
	}
	if res.Data["verified"] != false {
		t.Fatalf("data.verified = %v, want false", res.Data["verified"])
	}
	warning, _ := res.Data["warning"].(string)
	if !strings.Contains(warning, "trust document expired at 2000-01-01T00:00:00Z") {
		t.Fatalf("data.warning = %q, want it to say the trust document expired", warning)
	}
	if _, ok := profileSources(t, profilePath)["example"]; !ok {
		t.Fatal("a source with expired metadata must still be added")
	}
}

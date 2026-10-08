// Command ghfake serves a fake GitHub release for the container e2e suite
// (venom/user/59-github-import): acme/hello v1.2.0 with attested linux/amd64
// and linux/arm64 archives and a Windows asset the importer skips. It mints
// the attestations at start and writes the trusted root that verifies them
// to -trusted-root-out, after its listener is bound, so the file's presence
// means the server accepts connections.
//
// Usage:
//
//	ghfake -addr :8080 -trusted-root-out /ghfake/trusted_root.json
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/trevor-vaughan/polypkg/internal/ghrelease/ghreleasetest"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	rootOut := flag.String("trusted-root-out", "", "file to write the trusted_root.json that verifies the served attestations (required)")
	flag.Parse()
	if *rootOut == "" {
		fmt.Fprintln(os.Stderr, "ghfake: -trusted-root-out is required")
		os.Exit(2)
	}
	if err := run(*addr, *rootOut); err != nil {
		fmt.Fprintln(os.Stderr, "ghfake:", err)
		os.Exit(1)
	}
}

func run(addr, rootOut string) error {
	if err := os.Remove(rootOut); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove stale trusted root: %w", err)
	}
	rel, err := release()
	if err != nil {
		return err
	}
	fake, err := ghreleasetest.New(rel)
	if err != nil {
		return fmt.Errorf("mint release: %w", err)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	tmp := rootOut + ".tmp"
	if err := os.WriteFile(tmp, fake.TrustedRoot(), 0o600); err != nil {
		return fmt.Errorf("write trusted root: %w", err)
	}
	if err := os.Rename(tmp, rootOut); err != nil {
		return fmt.Errorf("publish trusted root: %w", err)
	}
	srv := &http.Server{Handler: fake, ReadHeaderTimeout: 10 * time.Second}
	return srv.Serve(ln)
}

// release is the upstream the suite imports. Each archive holds one
// executable shell script under a per-platform top directory, as Go and Rust
// release tooling lays them out.
func release() (ghreleasetest.Release, error) {
	rel := ghreleasetest.Release{
		Owner: "acme", Repo: "hello", Tag: "v1.2.0",
		Description: "Says hello from a fake GitHub release.",
	}
	for _, arch := range []string{"amd64", "arm64"} {
		top := "hello_1.2.0_linux_" + arch
		data, err := ghreleasetest.TarGz(ghreleasetest.TarEntry{
			Name: top + "/hello", Mode: 0o755,
			Body: []byte("#!/bin/sh\necho \"hello from a GitHub release\"\n"),
		})
		if err != nil {
			return ghreleasetest.Release{}, fmt.Errorf("build %s archive: %w", arch, err)
		}
		rel.Assets = append(rel.Assets, ghreleasetest.Asset{Name: top + ".tar.gz", Data: data, Attest: true})
	}
	rel.Assets = append(rel.Assets, ghreleasetest.Asset{
		Name: "hello_1.2.0_windows_amd64.zip", Data: []byte("never downloaded: Windows assets are skipped"),
	})
	return rel, nil
}

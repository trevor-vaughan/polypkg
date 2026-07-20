// Command polypkg is a declarative package manager for Linux, macOS, and
// FreeBSD. A profile file declares what should be installed; `polypkg apply`
// makes the system match it, recording each change as an immutable generation
// that can be rolled back.
//
// Install:
//
//	go install github.com/trevor-vaughan/polypkg/cmd/polypkg@latest
//
// Usage:
//
//	polypkg init      # create a profile (scope, source URL, trust key)
//	polypkg install   # add packages to the profile and apply
//	polypkg apply     # make the system match the profile
//	polypkg rollback  # return to the previous generation
//
// See the project README for the full command reference and the declarative
// profile format.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/trevor-vaughan/polypkg/internal/cli"
)

func main() {
	err := run()
	cli.RenderError(os.Stderr, err)
	os.Exit(cli.ExitCode(err))
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return cli.NewRootCmd().ExecuteContext(ctx)
}

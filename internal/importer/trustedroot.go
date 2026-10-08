package importer

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/sigstore/sigstore-go/pkg/tuf"

	"github.com/trevor-vaughan/polypkg/internal/paths"
)

// trustedRootTarget is the TUF target that holds Sigstore's trusted root.
const trustedRootTarget = "trusted_root.json"

// TUFTrustedRoot returns an Options.TrustedRoot that fetches Sigstore's
// trusted_root.json through sigstore-go's TUF client configured by opts,
// which verifies the TUF metadata chain from its embedded root before
// trusting the target. sigstore-go's TUF client takes no context, so ctx is
// checked only before the fetch starts.
func TUFTrustedRoot(opts *tuf.Options) func(ctx context.Context) ([]byte, error) {
	return func(ctx context.Context) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c, err := tuf.New(opts)
		if err != nil {
			return nil, fmt.Errorf("sigstore TUF: %w", err)
		}
		b, err := c.GetTarget(trustedRootTarget)
		if err != nil {
			return nil, fmt.Errorf("sigstore TUF: fetch %s: %w", trustedRootTarget, err)
		}
		return b, nil
	}
}

// DefaultTrustedRoot returns the Options.TrustedRoot `pkg import` uses:
// TUFTrustedRoot over the Sigstore public-good TUF repository, caching its
// metadata under polypkg's user cache directory (sigstore-tuf/).
func DefaultTrustedRoot() (func(ctx context.Context) ([]byte, error), error) {
	cache, err := paths.UserCacheHome()
	if err != nil {
		return nil, fmt.Errorf("locate the sigstore TUF cache: %w", err)
	}
	return TUFTrustedRoot(tuf.DefaultOptions().WithCachePath(filepath.Join(cache, "sigstore-tuf"))), nil
}

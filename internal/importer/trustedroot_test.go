package importer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/tuf"
)

func TestTUFTrustedRootUsesTheConfiguredMirrorAndCache(t *testing.T) {
	sandboxHome(t)
	var hits atomic.Int32
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
	defer mirror.Close()
	cache := t.TempDir()

	fetch := TUFTrustedRoot(tuf.DefaultOptions().WithCachePath(cache).WithRepositoryBaseURL(mirror.URL))
	_, err := fetch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "sigstore TUF") {
		t.Fatalf("error = %v, want a sigstore TUF failure from a mirror that serves nothing", err)
	}
	if hits.Load() == 0 {
		t.Fatal("the TUF client never contacted the configured mirror")
	}
	if entries, err := os.ReadDir(cache); err != nil || len(entries) == 0 {
		t.Fatalf("cache dir holds %v (err %v), want the TUF client's metadata", entries, err)
	}
}

func TestTUFTrustedRootHonoursACancelledContext(t *testing.T) {
	sandboxHome(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fetch := TUFTrustedRoot(tuf.DefaultOptions().WithCachePath(t.TempDir()).WithRepositoryBaseURL("http://127.0.0.1:1"))
	if _, err := fetch(ctx); err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("error = %v, want the context's cancellation", err)
	}
}

func TestDefaultTrustedRootNeedsAUserCacheDirectory(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	if _, err := DefaultTrustedRoot(); err == nil {
		t.Fatal("DefaultTrustedRoot succeeded with neither HOME nor XDG_CACHE_HOME")
	}
}

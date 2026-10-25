package tools

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/config"
)

// bundleBytes builds a src.tar.gz the way the backend stores it.
func bundleBytes(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		tw.WriteHeader(&tar.Header{Name: "./" + name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))})
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

type cacheBackend struct {
	client    *api.Client
	etag      atomic.Value
	downloads atomic.Int32
	apiReads  atomic.Int32 // /files, /file, /search, /manifest, /symbols — must stay 0 once cached
	down      atomic.Bool
}

func newCacheBackend(t *testing.T) *cacheBackend {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	b := &cacheBackend{}
	b.etag.Store(`"v1"`)
	bundle := bundleBytes(t, map[string]string{
		"sources/com/evil/a.java":       "package com.evil;\npublic class a {\n    String c2 = \"https://c2.evil\";\n    void b() { a.b(); }\n}\n",
		"resources/AndroidManifest.xml": `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.evil"><application android:name=".a"/></manifest>`,
	})
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/api/projects/p1/source-bundle", func(w http.ResponseWriter, r *http.Request) {
		if b.down.Load() {
			http.Error(w, "down", 502)
			return
		}
		json.NewEncoder(w).Encode(api.SourceBundle{URL: srv.URL + "/s3/src.tar.gz", CompressedBytes: int64(len(bundle)), ETag: b.etag.Load().(string)})
	})
	mux.HandleFunc("/s3/src.tar.gz", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("presigned download must not carry the bearer token")
		}
		b.downloads.Add(1)
		w.Write(bundle)
	})
	mux.HandleFunc("/api/projects/p1/renames", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]api.Rename{
			{Original: "a", Suggested: "C2Client", Status: "APPLIED"},
			{Original: "b", Suggested: "neverApplied", Status: "SUGGESTED"},
		})
	})
	for _, path := range []string{"/api/projects/p1/files", "/api/projects/p1/file", "/api/projects/p1/search", "/api/projects/p1/manifest", "/api/projects/p1/symbols/usages", "/api/projects/p1/symbols/definition"} {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			b.apiReads.Add(1)
			http.Error(w, "should be served from the cache", 500)
		})
	}
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	b.client = api.New(config.Endpoints{APIBase: srv.URL}, staticToken{})
	return b
}

func (b *cacheBackend) registry() *Registry {
	reg := NewRegistry()
	NewToolbox(b.client, &api.Project{ID: "p1", Kind: api.KindAPK, Name: "evil.apk", Status: "READY"}).RegisterRead(reg)
	return reg
}

func TestBackendAPKReadsServedFromCache(t *testing.T) {
	b := newCacheBackend(t)
	reg := b.registry()

	if out := run(t, reg, "read_file", map[string]any{"path": "sources/com/evil/a.java"}); !strings.Contains(out, "public class C2Client") || !strings.Contains(out, "void b()") {
		t.Errorf("applied rename should be substituted (and only applied ones):\n%s", out)
	}
	if out := run(t, reg, "search", map[string]any{"regex": "c2\\.evil"}); !strings.Contains(out, "a.java:3") {
		t.Errorf("search: %s", out)
	}
	if out := run(t, reg, "get_metadata", nil); !strings.Contains(out, "application class: com.evil.a") {
		t.Errorf("get_metadata: %s", out)
	}
	run(t, reg, "list_files", nil)
	run(t, reg, "find_usages", map[string]any{"name": "b"})

	if n := b.downloads.Load(); n != 1 {
		t.Errorf("bundle downloads = %d, want 1", n)
	}
	if n := b.apiReads.Load(); n != 0 {
		t.Errorf("%d read calls hit the backend; all reads should be local", n)
	}
}

func TestCacheReusedUntilBundleChanges(t *testing.T) {
	b := newCacheBackend(t)
	run(t, b.registry(), "list_files", nil)
	run(t, b.registry(), "list_files", nil) // new session, same ETag
	if n := b.downloads.Load(); n != 1 {
		t.Fatalf("same ETag re-downloaded: %d downloads", n)
	}

	b.etag.Store(`"v2"`) // project re-ingested
	run(t, b.registry(), "list_files", nil)
	if n := b.downloads.Load(); n != 2 {
		t.Fatalf("changed ETag not re-downloaded: %d downloads", n)
	}

	b.down.Store(true) // backend unreachable: keep working off the cache
	if out := run(t, b.registry(), "read_file", map[string]any{"path": "sources/com/evil/a.java"}); !strings.Contains(out, "c2.evil") {
		t.Errorf("offline read: %s", out)
	}
	if n := b.apiReads.Load(); n != 0 {
		t.Errorf("%d reads hit the backend", n)
	}
}

package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"openbin.ai/binny/internal/config"
)

type staticToken struct{}

func (staticToken) Token() (string, error) { return "tok", nil }

// The upload must look exactly like `openbin apk`'s: kind=APK, the APK as
// `file`, the JADX tarball as `decompiledTree` — that's what lets it past the
// backend's cloud-decompile sunset gate.
func TestUploadAPKProjectMatchesCLI(t *testing.T) {
	dir := t.TempDir()
	apk := filepath.Join(dir, "evil.apk")
	tree := filepath.Join(dir, "tree.tar.gz")
	os.WriteFile(apk, []byte("APKBYTES"), 0o644)
	os.WriteFile(tree, []byte("TREEBYTES"), 0o644)

	got := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/projects" || r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("unexpected request %s %s auth=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		mr, err := r.MultipartReader()
		if err != nil {
			t.Fatal(err)
		}
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			b, _ := io.ReadAll(p)
			got[p.FormName()] = p.FileName() + "=" + string(b)
		}
		json.NewEncoder(w).Encode(Project{ID: "new-id", Kind: KindAPK, Status: "DECOMPILING"})
	}))
	defer srv.Close()

	p, err := New(config.Endpoints{APIBase: srv.URL}, staticToken{}).UploadAPKProject(apk, tree)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "new-id" {
		t.Errorf("project = %+v", p)
	}
	want := map[string]string{"kind": "=APK", "file": "evil.apk=APKBYTES", "decompiledTree": "decompiled-tree.tar.gz=TREEBYTES"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("part %s = %q, want %q", k, got[k], v)
		}
	}
}

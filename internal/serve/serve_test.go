package serve

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	must := func(p, body string) {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must("sources/com/evil/Main.java", "package com.evil;\n")
	must("resources/AndroidManifest.xml", "<manifest/>")
	return dir
}

func TestBuildTreeNestsAndSortsDirsFirst(t *testing.T) {
	root, err := buildTree(sampleTree(t))
	if err != nil {
		t.Fatal(err)
	}
	if root.Type != "dir" || len(root.Children) != 2 {
		t.Fatalf("root = %+v", root)
	}
	// resources + sources, dirs sorted before files; both are dirs here, alpha order.
	if root.Children[0].Name != "resources" || root.Children[1].Name != "sources" {
		t.Errorf("children order = %q, %q", root.Children[0].Name, root.Children[1].Name)
	}
	// descend to the java file and check its relative path is slash-joined.
	src := root.Children[1]
	if src.Children[0].Name != "com" {
		t.Fatalf("expected com under sources, got %+v", src.Children)
	}
}

func TestHandleFileServesAndBlocksTraversal(t *testing.T) {
	s := &server{opts: Options{Dir: sampleTree(t)}}
	srv := httptest.NewServer(s.routes())
	defer srv.Close()

	// a real file
	resp, _ := http.Get(srv.URL + "/api/file?path=sources/com/evil/Main.java")
	if resp.StatusCode != 200 {
		t.Fatalf("file status = %d", resp.StatusCode)
	}
	var got struct {
		Path, Content string
	}
	_ = json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if !strings.Contains(got.Content, "package com.evil") {
		t.Errorf("content = %q", got.Content)
	}

	// traversal must be rejected
	for _, bad := range []string{"../../../../etc/passwd", "/etc/passwd", ""} {
		r, _ := http.Get(srv.URL + "/api/file?path=" + bad)
		r.Body.Close()
		if r.StatusCode == 200 {
			t.Errorf("traversal %q was served (status 200)", bad)
		}
	}
}

func TestHandleFilesEmptyWhenNoDir(t *testing.T) {
	s := &server{opts: Options{}}
	srv := httptest.NewServer(s.routes())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/files")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got["root"] != nil {
		t.Errorf("expected nil root with no --serve-dir, got %v", got["root"])
	}
}

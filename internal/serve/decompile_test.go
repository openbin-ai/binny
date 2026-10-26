package serve

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"openbin.ai/binny/internal/worker"
)

func TestHandleDecompileSwapsServedTree(t *testing.T) {
	// Fake the (Docker-backed) pipeline: write a tiny tree and return it.
	treeDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(treeDir, "Main.java"), []byte("package x;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := decompileAPK
	decompileAPK = func(ctx context.Context, apkPath, name string, size int64, logf worker.Logf) (decompileResult, error) {
		logf("decompiling %s…", name)
		return decompileResult{SrcDir: treeDir, Name: name, Package: "com.x"}, nil
	}
	defer func() { decompileAPK = orig }()

	s := &server{opts: Options{}} // no --serve-dir; the upload provides the tree
	srv := httptest.NewServer(s.routes())
	defer srv.Close()

	// multipart upload
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("apk", "evil.apk")
	fw.Write([]byte("PK\x03\x04 not a real apk"))
	mw.Close()

	resp, err := http.Post(srv.URL+"/api/decompile", mw.FormDataContentType(), &body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var sawProgress, sawReady bool
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		var ev map[string]any
		if json.Unmarshal([]byte(strings.TrimSpace(line[5:])), &ev) != nil {
			continue
		}
		switch ev["type"] {
		case "progress":
			sawProgress = true
		case "ready":
			sawReady = true
			if ev["package"] != "com.x" {
				t.Errorf("ready package = %v", ev["package"])
			}
		case "error":
			t.Fatalf("decompile error: %v", ev["error"])
		}
	}
	if !sawProgress || !sawReady {
		t.Fatalf("expected progress+ready events (progress=%v ready=%v)", sawProgress, sawReady)
	}

	// The served tree must now be the decompiled one.
	if s.dir() != treeDir {
		t.Errorf("served dir = %q, want %q", s.dir(), treeDir)
	}
	fr, err := http.Get(srv.URL + "/api/file?path=Main.java")
	if err != nil {
		t.Fatal(err)
	}
	defer fr.Body.Close()
	if fr.StatusCode != 200 {
		t.Errorf("file from swapped tree: status %d", fr.StatusCode)
	}
}

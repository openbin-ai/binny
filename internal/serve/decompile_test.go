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
	"strconv"
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

// A decompile must survive its stream being cut (Firefox aborts in-flight
// requests when Docker adds a network interface) and be resumable from
// /api/job at the event the client had reached.
func TestDecompileJobSurvivesDroppedStream(t *testing.T) {
	treeDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(treeDir, "Main.java"), []byte("package x;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	ctxErr := make(chan error, 1)
	orig := decompileAPK
	decompileAPK = func(ctx context.Context, apkPath, name string, size int64, logf worker.Logf) (decompileResult, error) {
		logf("working on %s…", name)
		<-release // the client drops the stream while we're here
		ctxErr <- ctx.Err()
		if _, err := os.Stat(apkPath); err != nil {
			return decompileResult{}, err // the upload must outlive the request
		}
		return decompileResult{SrcDir: treeDir, Name: name, Package: "com.x"}, nil
	}
	defer func() { decompileAPK = orig }()

	s := &server{opts: Options{}}
	srv := httptest.NewServer(s.routes())
	defer srv.Close()

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("apk", "app.apk")
	fw.Write([]byte("PK\x03\x04"))
	mw.Close()

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "POST", srv.URL+"/api/decompile", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	// Read up to the fake's progress line, then drop the connection.
	var jobID string
	seen := 0
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(line[5:])), &ev); err != nil {
			t.Fatal(err)
		}
		seen++
		if ev["type"] == "job" {
			jobID, _ = ev["id"].(string)
		}
		if text, _ := ev["text"].(string); strings.HasPrefix(text, "working on") {
			break
		}
	}
	cancel()
	resp.Body.Close()
	if jobID == "" {
		t.Fatal("stream never announced a job id")
	}
	close(release)
	if err := <-ctxErr; err != nil {
		t.Fatalf("job context was cancelled by the dropped stream: %v", err)
	}

	// Re-attach where we left off: only the remaining events, ending in ready.
	r2, err := http.Get(srv.URL + "/api/job?id=" + jobID + "&from=" + strconv.Itoa(seen))
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Body.Close()
	var types []string
	sc = bufio.NewScanner(r2.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(line[5:])), &ev); err != nil {
			t.Fatal(err)
		}
		types = append(types, ev["type"].(string))
	}
	if len(types) != 1 || types[0] != "ready" {
		t.Fatalf("resumed stream = %v, want just [ready]", types)
	}
	if s.dir() != treeDir {
		t.Errorf("served dir = %q, want %q", s.dir(), treeDir)
	}

	if r3, err := http.Get(srv.URL + "/api/job?id=nope"); err != nil {
		t.Fatal(err)
	} else {
		r3.Body.Close()
		if r3.StatusCode != http.StatusNotFound {
			t.Errorf("unknown job: status %d, want 404", r3.StatusCode)
		}
	}
}

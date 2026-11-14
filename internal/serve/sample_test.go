package serve

import (
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

	"openbin.ai/binny/internal/store"
	"openbin.ai/binny/internal/tools"
	"openbin.ai/binny/internal/worker"
)

func toolNames(s *server) map[string]bool {
	out := map[string]bool{}
	for _, d := range s.agentTools() {
		out[d.Name] = true
	}
	return out
}

func postSample(t *testing.T, url, body string) (*http.Response, map[string]any) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

// With nothing open there is nothing to attach to, and no sandbox tools.
func TestSampleNeedsTarget(t *testing.T) {
	s := &server{opts: Options{}}
	srv := httptest.NewServer(s.routes())
	defer srv.Close()

	if toolNames(s)["run"] {
		t.Error("no target open: sandbox tools should not be offered")
	}
	resp, _ := postSample(t, srv.URL+"/api/sample", `{"path":"/etc/hostname"}`)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
}

// /sample <path>: attach in place, the agent gets told, and a new target
// starts clean.
func TestSampleAttachByPath(t *testing.T) {
	s := &server{opts: Options{}}
	s.setBinaryProject("proj-1", tools.NewRegistry(), nil)
	srv := httptest.NewServer(s.routes())
	defer srv.Close()

	names := toolNames(s)
	for _, n := range []string{"run", "write_file", "read_artifact"} {
		if !names[n] {
			t.Errorf("binary mode should offer %s even before a sample is attached", n)
		}
	}
	if ctx := s.chatContext(); !strings.Contains(ctx, "NOT attached") || !strings.Contains(ctx, "Attach sample") {
		t.Errorf("context should say how to attach a sample:\n%s", ctx)
	}
	// Unattached, the tool fails with something the model can act on.
	if out, isErr := s.runTool(context.Background(), "run", json.RawMessage(`{"cmd":"file /sample"}`)); !isErr || !strings.Contains(out, "no local sample attached") {
		t.Errorf("run without a sample = (%q, %v)", out, isErr)
	}

	dir := t.TempDir()
	if resp, _ := postSample(t, srv.URL+"/api/sample", `{"path":"`+dir+`"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("directory: status = %d, want 400", resp.StatusCode)
	}
	if resp, _ := postSample(t, srv.URL+"/api/sample", `{"path":"`+filepath.Join(dir, "nope")+`"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("missing file: status = %d, want 400", resp.StatusCode)
	}

	bin := filepath.Join(dir, "evil.elf")
	if err := os.WriteFile(bin, []byte("\x7fELF"), 0o600); err != nil {
		t.Fatal(err)
	}
	resp, out := postSample(t, srv.URL+"/api/sample", `{"path":"`+bin+`"}`)
	if resp.StatusCode != http.StatusOK || out["attached"] != true || out["name"] != "evil.elf" {
		t.Fatalf("attach = %d %v", resp.StatusCode, out)
	}
	if got := s.samplePath(); got != bin {
		t.Errorf("samplePath = %q, want %q (attached in place, not copied)", got, bin)
	}
	if ctx := s.chatContext(); !strings.Contains(ctx, "attached (evil.elf)") {
		t.Errorf("context should say the sample is attached:\n%s", ctx)
	}

	s.setDir("/tmp/other/tree")
	if s.samplePath() != "" {
		t.Error("opening another target must drop the previous sample")
	}
}

// The Attach button uploads: the bytes are copied into the store.
func TestSampleAttachByUpload(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	s := &server{opts: Options{}}
	s.setBinaryProject("proj-1", tools.NewRegistry(), nil)
	srv := httptest.NewServer(s.routes())
	defer srv.Close()

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "payload.bin")
	fw.Write([]byte("raw bytes"))
	mw.Close()
	resp, err := http.Post(srv.URL+"/api/sample", mw.FormDataContentType(), &body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	got, err := os.ReadFile(s.samplePath())
	if err != nil || string(got) != "raw bytes" {
		t.Errorf("stored sample = %q, %v", got, err)
	}
}

// Opening a binary keeps the uploaded file: it used to live only in a temp dir
// deleted when the request ended, leaving the session with no raw sample.
func TestAnalyzeKeepsSample(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	const sha = "bb11bb22cc33dd44ee55ff6677889900aabbccddeeff00112233445566778899"
	orig := analyzeBinary
	analyzeBinary = func(_ context.Context, _, name, _ string, _ int64, _ worker.Logf) (store.Meta, error) {
		meta := store.Meta{Sha256: sha, Name: name, Format: "ELF"}
		return meta, store.Save(meta, []byte(`{"metadata":{"executable_format":"ELF"}}`))
	}
	defer func() { analyzeBinary = orig }()

	s := &server{opts: Options{}}
	srv := httptest.NewServer(s.routes())
	defer srv.Close()

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "evil.elf")
	fw.Write([]byte("\x7fELF not really"))
	mw.Close()
	resp, err := http.Post(srv.URL+"/api/analyze", mw.FormDataContentType(), &body)
	if err != nil {
		t.Fatal(err)
	}
	var sink bytes.Buffer
	sink.ReadFrom(resp.Body)
	resp.Body.Close()

	p := s.samplePath()
	if p == "" {
		t.Fatalf("no sample attached after analyze:\n%s", sink.String())
	}
	if got, err := os.ReadFile(p); err != nil || string(got) != "\x7fELF not really" {
		t.Errorf("kept sample = %q, %v", got, err)
	}
	if meta, err := store.Load(sha); err != nil || meta.SamplePath != p {
		t.Errorf("meta.SamplePath not updated: %+v, %v", meta, err)
	}
	if !toolNames(s)["decompile_sample"] {
		t.Error("a local binary with its toolbox should offer decompile_sample")
	}
}

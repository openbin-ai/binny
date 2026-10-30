package serve

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"openbin.ai/binny/internal/store"
	"openbin.ai/binny/internal/worker"
)

// Drop a binary → Ghidra (faked) → the server enters binary chat mode. Verifies
// the handler wires the analysis into the real toolbox without needing Docker.
func TestHandleAnalyzeEntersBinaryMode(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir()) // isolate the local store

	const sha = "aa11bb22cc33dd44ee55ff6677889900aabbccddeeff00112233445566778899"
	blob := []byte(`{"metadata":{"language":"x86:LE:32","executable_format":"ELF","function_count":3,"string_count":10,"import_count":2}}`)

	orig := analyzeBinary
	analyzeBinary = func(_ context.Context, _, name string, _ int64, logf worker.Logf) (store.Meta, error) {
		logf("faking Ghidra on %s…", name)
		meta := store.Meta{Sha256: sha, Name: name, Format: "ELF", Language: "x86:LE:32"}
		if err := store.Save(meta, blob); err != nil { // the real pipeline caches here too
			return store.Meta{}, err
		}
		return meta, nil
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
	defer resp.Body.Close()

	var sawProgress bool
	var summary string
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
			if ev["kind"] != "BIN" {
				t.Errorf("ready kind = %v, want BIN", ev["kind"])
			}
			summary, _ = ev["summary"].(string)
		case "error":
			t.Fatalf("analyze error: %v", ev["error"])
		}
	}
	if !sawProgress {
		t.Error("expected progress events")
	}
	// The summary comes from the REAL get_metadata tool reading the stored blob.
	if !strings.Contains(summary, "ELF") || !strings.Contains(summary, "3 functions") {
		t.Errorf("summary didn't reflect the analysis blob:\n%s", summary)
	}

	// Server is now in binary mode, backed by the local project.
	if s.reg() == nil {
		t.Error("expected binary registry to be set")
	}
	if got, want := s.projectID(), store.LocalID(sha); got != want {
		t.Errorf("projectID = %q, want %q", got, want)
	}
	if s.dir() != "" {
		t.Errorf("binary mode should serve no tree, dir = %q", s.dir())
	}
}

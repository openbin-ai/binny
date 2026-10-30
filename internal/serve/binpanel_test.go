package serve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"openbin.ai/binny/internal/store"
	"openbin.ai/binny/internal/tools"
)

func TestBinaryPanelEndpoints(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	const sha = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
	blob := []byte(`{"metadata":{"language":"x86:LE:32","executable_format":"ELF","function_count":2,"string_count":2},
		"functions":[
		  {"name":"main","address":"0x1000","size":10,"signature":"int main(void)","decompiled":"int main(void){return 0;}"},
		  {"name":"imp","address":"0x0","external":true}],
		"strings":["hello","world"],
		"imports":["printf"]}`)
	if err := store.Save(store.Meta{Sha256: sha, Name: "t.elf", Format: "ELF", Language: "x86:LE:32"}, blob); err != nil {
		t.Fatal(err)
	}

	project := localBinaryProject(store.Meta{Sha256: sha, Name: "t.elf", Format: "ELF", Language: "x86:LE:32"})
	reg := tools.NewRegistry()
	tb := tools.NewToolbox(nil, project)
	tb.RegisterRead(reg)
	if _, isErr := reg.Run(context.Background(), "get_metadata", []byte(`{}`)); isErr { // load the blob
		t.Fatal("get_metadata failed to load the analysis")
	}

	s := &server{opts: Options{}}
	s.setBinaryProject(project.ID, reg, tb)
	srv := httptest.NewServer(s.routes())
	defer srv.Close()

	// /api/bin/analysis
	var an struct {
		Binary         bool     `json:"binary"`
		FunctionsTotal int      `json:"functionsTotal"`
		StringsTotal   int      `json:"stringsTotal"`
		Imports        []string `json:"imports"`
		Functions      []struct {
			Name    string `json:"name"`
			HasCode bool   `json:"hasCode"`
		} `json:"functions"`
	}
	getJSON(t, srv.URL+"/api/bin/analysis", &an)
	if !an.Binary || an.FunctionsTotal != 2 || an.StringsTotal != 2 || len(an.Imports) != 1 {
		t.Fatalf("analysis overview wrong: %+v", an)
	}
	if an.Functions[0].Name != "main" || !an.Functions[0].HasCode {
		t.Errorf("functions[0] = %+v", an.Functions[0])
	}

	// /api/bin/function
	var fn struct{ Name, Decompiled string }
	getJSON(t, srv.URL+"/api/bin/function?name=main", &fn)
	if fn.Name != "main" || !strings.Contains(fn.Decompiled, "return 0") {
		t.Errorf("function = %+v", fn)
	}

	// no such function → 404
	resp, _ := http.Get(srv.URL + "/api/bin/function?name=nope")
	if resp != nil {
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Errorf("unknown function status = %d, want 404", resp.StatusCode)
		}
	}

	// with no binary open, analysis reports binary:false (not a crash)
	s2 := &server{opts: Options{}}
	srv2 := httptest.NewServer(s2.routes())
	defer srv2.Close()
	var off struct{ Binary bool }
	getJSON(t, srv2.URL+"/api/bin/analysis", &off)
	if off.Binary {
		t.Error("expected binary:false with nothing open")
	}
}

func getJSON(t *testing.T, url string, v any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
}

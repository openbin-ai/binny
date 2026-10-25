package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/config"
)

type staticToken struct{}

func (staticToken) Token() (string, error) { return "t", nil }

// fakeBackend serves the APK endpoints the source-tree tools call, and records
// the query of the last request so tests can assert what was sent.
func fakeBackend(t *testing.T) (*api.Client, *string) {
	t.Helper()
	t.Setenv("XDG_DATA_HOME", t.TempDir()) // no source bundle here → API fallback, never the real cache
	var lastQuery string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/projects/p1/manifest", func(w http.ResponseWriter, _ *http.Request) {
		line := 12
		json.NewEncoder(w).Encode(api.Manifest{
			PackageName: "com.evil.app",
			Permissions: []string{"android.permission.INTERNET", "android.permission.READ_SMS"},
			Application: &api.ManifestComponent{Kind: "application", ClassName: "com.evil.App", File: "sources/com/evil/App.java", Line: &line},
			Activities: []api.ManifestComponent{{
				Kind: "activity", ClassName: "com.evil.Main", Exported: true, Enabled: true,
				IntentFilters: []api.IntentFilter{{Actions: []string{"android.intent.action.MAIN"}, Categories: []string{"android.intent.category.LAUNCHER"}}},
				File:          "sources/com/evil/Main.java",
			}},
			Receivers: []api.ManifestComponent{{Kind: "receiver", ClassName: "com.evil.SmsRx", Exported: false, Enabled: true}},
		})
	})
	mux.HandleFunc("/api/projects/p1/search", func(w http.ResponseWriter, r *http.Request) {
		lastQuery = r.URL.RawQuery
		json.NewEncoder(w).Encode([]api.SearchHit{{File: "sources/com/evil/C2.java", Line: 7, Snippet: `  String u = "https://c2.evil";`}})
	})
	mux.HandleFunc("/api/projects/p1/symbols/usages", func(w http.ResponseWriter, r *http.Request) {
		lastQuery = r.URL.RawQuery
		json.NewEncoder(w).Encode([]api.SymbolUsage{{File: "sources/com/evil/Main.java", Line: 30, Snippet: "Crypto.decrypt(x)"}})
	})
	mux.HandleFunc("/api/projects/p1/symbols/definition", func(w http.ResponseWriter, r *http.Request) {
		lastQuery = r.URL.RawQuery
		json.NewEncoder(w).Encode([]api.JavaSymbol{{Kind: "METHOD", Name: "decrypt", ClassName: "com.evil.Crypto", File: "sources/com/evil/Crypto.java", Line: 9, Signature: "(String)", Modifiers: "public static"}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return api.New(config.Endpoints{APIBase: srv.URL}, staticToken{}), &lastQuery
}

func apkToolbox(client *api.Client) *Toolbox {
	return NewToolbox(client, &api.Project{ID: "p1", Kind: api.KindAPK, Name: "evil.apk", Status: "READY"})
}

func run(t *testing.T, reg *Registry, name string, args map[string]any) string {
	t.Helper()
	raw, _ := json.Marshal(args)
	out, isErr := reg.Run(context.Background(), name, raw)
	if isErr {
		t.Fatalf("%s returned error: %s", name, out)
	}
	return out
}

func TestRegisterReadIsKindAware(t *testing.T) {
	apk := NewRegistry()
	apkToolbox(nil).RegisterRead(apk)
	for _, want := range []string{"get_metadata", "get_manifest", "list_files", "read_file", "search", "find_definition", "find_usages"} {
		if !apk.Has(want) {
			t.Errorf("APK registry missing %s", want)
		}
	}
	for _, native := range []string{"get_strings", "get_imports", "list_functions", "xrefs", "reachability", "read_data"} {
		if apk.Has(native) {
			t.Errorf("APK registry offers native-only tool %s", native)
		}
	}

	bin := NewRegistry()
	NewToolbox(nil, &api.Project{ID: "b1", Kind: api.KindBIN}).RegisterRead(bin)
	for _, want := range []string{"get_strings", "get_imports", "xrefs", "reachability", "search"} {
		if !bin.Has(want) {
			t.Errorf("BIN registry missing %s", want)
		}
	}
	if bin.Has("get_manifest") || bin.Has("find_usages") {
		t.Error("BIN registry offers APK-only tools")
	}
}

func TestAPKMetadataSummarizesManifest(t *testing.T) {
	client, _ := fakeBackend(t)
	reg := NewRegistry()
	apkToolbox(client).RegisterRead(reg)
	out := run(t, reg, "get_metadata", nil)
	for _, want := range []string{
		"Android APK", "package: com.evil.app",
		"application class: com.evil.App", "sources/com/evil/App.java:12",
		"launcher activity: com.evil.Main",
		"high-signal: READ_SMS",
		"1 activities, 0 services, 1 receivers, 0 providers (1 exported)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("get_metadata missing %q\n%s", want, out)
		}
	}
}

func TestGetManifestExportedOnly(t *testing.T) {
	client, _ := fakeBackend(t)
	reg := NewRegistry()
	apkToolbox(client).RegisterRead(reg)
	out := run(t, reg, "get_manifest", map[string]any{"exported_only": true})
	if !strings.Contains(out, "com.evil.Main  [EXPORTED]") {
		t.Errorf("exported activity missing:\n%s", out)
	}
	if strings.Contains(out, "com.evil.SmsRx") {
		t.Errorf("non-exported receiver listed with exported_only:\n%s", out)
	}
	if !strings.Contains(out, "intent-filter: actions=android.intent.action.MAIN categories=android.intent.category.LAUNCHER") {
		t.Errorf("intent filter not rendered:\n%s", out)
	}
}

func TestAPKSearchHitsBackend(t *testing.T) {
	client, q := fakeBackend(t)
	reg := NewRegistry()
	apkToolbox(client).RegisterRead(reg)
	out := run(t, reg, "search", map[string]any{"regex": "https?://"})
	if out != `sources/com/evil/C2.java:7: String u = "https://c2.evil";` {
		t.Errorf("unexpected search output: %q", out)
	}
	if !strings.Contains(*q, "regex=true") || !strings.Contains(*q, "includeSdks=false") {
		t.Errorf("search query = %q, want regex=true and includeSdks=false", *q)
	}
}

func TestFindUsagesAndDefinition(t *testing.T) {
	client, q := fakeBackend(t)
	reg := NewRegistry()
	apkToolbox(client).RegisterRead(reg)

	out := run(t, reg, "find_usages", map[string]any{"name": "decrypt", "class": "com.evil.Crypto"})
	if out != "sources/com/evil/Main.java:30: Crypto.decrypt(x)" {
		t.Errorf("find_usages output: %q", out)
	}
	if !strings.Contains(*q, "class=com.evil.Crypto") {
		t.Errorf("find_usages query %q missing class", *q)
	}

	out = run(t, reg, "find_definition", map[string]any{"name": "decrypt"})
	if out != "method decrypt in com.evil.Crypto  sources/com/evil/Crypto.java:9  public static (String)" {
		t.Errorf("find_definition output: %q", out)
	}
}

func TestIsSdkPath(t *testing.T) {
	for _, p := range []string{"sources/androidx/core/A.java", "kotlin/io/B.java", "sources/com/google/gson/C.java", "okhttp3/D.java"} {
		if !isSdkPath(p) {
			t.Errorf("isSdkPath(%q) = false", p)
		}
	}
	for _, p := range []string{"sources/com/evil/Main.java", "resources/AndroidManifest.xml", "sources/a/b/c.java"} {
		if isSdkPath(p) {
			t.Errorf("isSdkPath(%q) = true", p)
		}
	}
}

func treeOf(paths ...string) *api.FileNode {
	root := &api.FileNode{Name: "/", Type: "dir"}
	for _, p := range paths {
		root.Children = append(root.Children, api.FileNode{Name: p, Path: p, Type: "file"})
	}
	return root
}

func TestListTreeFiltersAndHidesSdks(t *testing.T) {
	root := treeOf("sources/com/evil/Main.java", "sources/com/evil/Crypto.java", "sources/androidx/core/X.java", "resources/AndroidManifest.xml")

	out := listTree(root, "", "", false)
	if strings.Contains(out, "androidx") {
		t.Errorf("SDK file listed by default:\n%s", out)
	}
	if !strings.Contains(out, "1 library/SDK files hidden") {
		t.Errorf("hidden-SDK note missing:\n%s", out)
	}

	if out := listTree(root, "sources/com/evil", "crypto", false); out != "sources/com/evil/Crypto.java" {
		t.Errorf("dir+filter = %q", out)
	}
	if out := listTree(root, "", "", true); !strings.Contains(out, "sources/androidx/core/X.java") {
		t.Errorf("include_sdks didn't list SDK file:\n%s", out)
	}
}

func TestListTreeSummarizesLargeTrees(t *testing.T) {
	var paths []string
	for i := 0; i < 300; i++ {
		paths = append(paths, fmt.Sprintf("sources/com/big/F%03d.java", i))
	}
	for i := 0; i < 20; i++ {
		paths = append(paths, fmt.Sprintf("sources/com/small/G%02d.java", i))
	}
	out := listTree(treeOf(paths...), "sources/com", "", false)
	if !strings.Contains(out, "320 files — too many to list") {
		t.Fatalf("expected a summary, got:\n%s", out)
	}
	big := strings.Index(out, "sources/com/big/ (300)")
	small := strings.Index(out, "sources/com/small/ (20)")
	if big < 0 || small < 0 || big > small {
		t.Errorf("subdirectories missing or not sorted by count:\n%s", out)
	}
}

func TestSliceLines(t *testing.T) {
	text := "a\nb\nc\nd"
	out, next := sliceLines(text, 2, 1000)
	if next != 0 || !strings.HasPrefix(out, "     2  b\n") || !strings.Contains(out, "     4  d\n") {
		t.Errorf("sliceLines(2) = %q, next=%d", out, next)
	}
	// Tight cap: one line fits, continue from the next.
	out, next = sliceLines(text, 1, 12)
	if out != "     1  a\n" || next != 2 {
		t.Errorf("capped sliceLines = %q, next=%d", out, next)
	}
	if out, _ := sliceLines(text, 9, 100); !strings.Contains(out, "only 4 lines") {
		t.Errorf("past-end sliceLines = %q", out)
	}
}

func TestFilterXMLNamespaceNoise(t *testing.T) {
	hits := []api.SearchHit{
		{File: "resources/res/anim/x.xml", Line: 2, Snippet: `<set xmlns:android="http://schemas.android.com/apk/res/android">`},
		{File: "resources/AndroidManifest.xml", Line: 2, Snippet: `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.evil">`},
		{File: "sources/com/evil/C2.java", Line: 7, Snippet: `String u = "https://c2.evil/beacon";`},
		{File: "resources/res/values/strings.xml", Line: 5, Snippet: `<string name="api">https://api.evil.example/v1</string>`},
	}
	kept, dropped := filterXMLNamespaceNoise(hits, `https?://`)
	if dropped != 2 {
		t.Errorf("dropped = %d, want 2 (the two xmlns-only lines)", dropped)
	}
	var files []string
	for _, h := range kept {
		files = append(files, h.File)
	}
	if strings.Join(files, ",") != "sources/com/evil/C2.java,resources/res/values/strings.xml" {
		t.Errorf("kept the wrong hits: %v", files)
	}

	// A search aimed AT namespaces keeps them.
	if _, d := filterXMLNamespaceNoise(hits, `schemas\.android\.com`); d != 0 {
		t.Errorf("searching for schema text should drop nothing, dropped %d", d)
	}
	// The manifest's package= attribute still matches after stripping xmlns
	// (the xmlns strip must not remove the rest of the line).
	xmlHits := []api.SearchHit{{File: "resources/AndroidManifest.xml", Line: 2, Snippet: `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.evil">`}}
	kept2, d2 := filterXMLNamespaceNoise(xmlHits, `package=`)
	if len(kept2) != 1 || d2 != 0 {
		t.Errorf("package= hit should survive the xmlns strip: kept=%+v dropped=%d", kept2, d2)
	}
}

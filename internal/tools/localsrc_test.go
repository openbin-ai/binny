package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/store"
)

const testManifest = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="7" android:versionName="1.2" package="com.evil.app">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.READ_SMS"/>
    <permission android:name="com.evil.app.C2D"/>
    <application android:name=".App">
        <activity android:name=".Main">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <receiver android:name="com.evil.app.SmsRx" android:exported="false">
            <intent-filter android:priority="999">
                <action android:name="android.provider.Telephony.SMS_RECEIVED"/>
            </intent-filter>
        </receiver>
        <service android:name="Beacon" android:enabled="false"/>
        <provider android:name=".Files" android:authorities="com.evil.files;com.evil.alt" android:exported="true"/>
        <activity android:name=".Deep">
            <intent-filter>
                <data android:scheme="evil" android:host="open"/>
            </intent-filter>
        </activity>
    </application>
</manifest>`

// writeJadxTree lays out a tiny JADX-shaped tree: sources/ + resources/.
func writeJadxTree(t *testing.T, root string) {
	t.Helper()
	files := map[string]string{
		"resources/AndroidManifest.xml":    testManifest,
		"sources/com/evil/app/App.java":    "package com.evil.app;\n\npublic class App extends Application {\n    public void onCreate() {\n        Crypto.decrypt(\"x\");\n    }\n}\n",
		"sources/com/evil/app/Main.java":   "package com.evil.app;\n\npublic class Main extends Activity {\n}\n",
		"sources/com/evil/app/Crypto.java": "package com.evil.app;\n\npublic final class Crypto {\n    private static final String KEY = \"k3y\";\n\n    public static String decrypt(String s) {\n        return s;\n    }\n}\n",
		"sources/androidx/core/Util.java":  "package androidx.core;\n\npublic class Util {\n    public static void decrypt() {}\n}\n",
		"resources/assets/payload.bin":     "\x00\x01binary",
	}
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLocalManifestMatchesBackendRules(t *testing.T) {
	root := t.TempDir()
	writeJadxTree(t, root)
	m, err := newLocalSource(root).Manifest()
	if err != nil {
		t.Fatal(err)
	}
	if m.PackageName != "com.evil.app" || *m.VersionCode != 7 || m.VersionName != "1.2" || *m.MinSdk != 21 || *m.TargetSdk != 30 {
		t.Errorf("header = %+v", m)
	}
	if len(m.Permissions) != 2 || m.DefinedPermissions[0] != "com.evil.app.C2D" {
		t.Errorf("permissions = %v / %v", m.Permissions, m.DefinedPermissions)
	}
	if m.Application.ClassName != "com.evil.app.App" || m.Application.File != "sources/com/evil/app/App.java" || *m.Application.Line != 3 {
		t.Errorf("application = %+v", m.Application)
	}
	main := m.Activities[0]
	if main.ClassName != "com.evil.app.Main" || !main.Exported || !isLauncher(main) {
		t.Errorf("launcher activity = %+v (exported should be implied by its intent filter)", main)
	}
	rx := m.Receivers[0]
	if rx.Exported || *rx.IntentFilters[0].Priority != 999 {
		t.Errorf("receiver = %+v (explicit exported=false must win)", rx)
	}
	svc := m.Services[0]
	if svc.ClassName != "com.evil.app.Beacon" || svc.Enabled || svc.Exported || svc.File != "" {
		t.Errorf("service = %+v", svc)
	}
	prov := m.Providers[0]
	if !prov.Exported || strings.Join(prov.Authorities, ",") != "com.evil.files,com.evil.alt" {
		t.Errorf("provider = %+v", prov)
	}
	if got := m.Activities[1].IntentFilters[0].DataSchemes; len(got) != 1 || got[0] != "evil://open" {
		t.Errorf("deep link schemes = %v", got)
	}
}

func TestLocalSymbolsAndUsages(t *testing.T) {
	root := t.TempDir()
	writeJadxTree(t, root)
	src := newLocalSource(root)

	defs, _ := src.Definitions("decrypt", false)
	if len(defs) != 1 || defs[0].ClassName != "Crypto" || defs[0].Line != 6 || defs[0].Kind != "METHOD" {
		t.Errorf("app-only definitions = %+v", defs)
	}
	if all, _ := src.Definitions("decrypt", true); len(all) != 2 {
		t.Errorf("include_sdks definitions = %+v", all)
	}
	if f, _ := src.Definitions("KEY", false); len(f) != 1 || f[0].Kind != "FIELD" {
		t.Errorf("field definition = %+v", f)
	}

	uses, _ := src.Usages("decrypt", "com.evil.app.Crypto", false)
	if len(uses) != 1 || uses[0].File != "sources/com/evil/app/App.java" || uses[0].Line != 5 {
		t.Errorf("qualified usages = %+v", uses)
	}
}

func TestLocalSearchAndFiles(t *testing.T) {
	root := t.TempDir()
	writeJadxTree(t, root)
	src := newLocalSource(root)

	hits, err := src.Search(`static .*decrypt`, false, 10)
	if err != nil || len(hits) != 1 || hits[0].File != "sources/com/evil/app/Crypto.java" {
		t.Errorf("search = %+v, %v", hits, err)
	}
	if _, err := src.Search(`(?<=x)`, false, 10); err == nil || !strings.Contains(err.Error(), "RE2") {
		t.Errorf("bad regex error = %v", err)
	}

	fc, err := src.File("sources/com/evil/app/Main.java")
	if err != nil || !strings.Contains(fc.Content, "class Main") || fc.Encoding != "utf-8" {
		t.Errorf("File = %+v, %v", fc, err)
	}
	if fc, _ := src.File("resources/assets/payload.bin"); fc.Encoding != "binary" {
		t.Errorf("binary file encoding = %q", fc.Encoding)
	}
	for _, bad := range []string{"../escape", "/etc/passwd", "sources/../../x"} {
		if _, err := src.File(bad); err == nil {
			t.Errorf("File(%q) escaped the tree", bad)
		}
	}

	tree, err := src.Tree()
	if err != nil {
		t.Fatal(err)
	}
	out := listTree(tree, "sources/com/evil/app", "", false)
	if out != "sources/com/evil/app/App.java\nsources/com/evil/app/Crypto.java\nsources/com/evil/app/Main.java" {
		t.Errorf("listTree over local tree = %q", out)
	}
}

// A local APK project (no backend) gets the full APK toolset served from disk.
func TestLocalAPKProjectToolsEndToEnd(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	sha := strings.Repeat("ab", 32)
	dir, _ := store.SrcDir(sha)
	writeJadxTree(t, dir)

	tb := NewToolbox(nil, &api.Project{ID: store.LocalID(sha), Kind: api.KindAPK, Name: "evil.apk", Sha256: sha, Status: "READY"})
	reg := NewRegistry()
	tb.RegisterRead(reg)

	if out := run(t, reg, "get_metadata", nil); !strings.Contains(out, "launcher activity: com.evil.app.Main") {
		t.Errorf("get_metadata:\n%s", out)
	}
	if out := run(t, reg, "find_usages", map[string]any{"name": "decrypt", "class": "Crypto"}); !strings.Contains(out, "App.java:5") {
		t.Errorf("find_usages: %s", out)
	}
	if out := run(t, reg, "read_file", map[string]any{"path": "sources/com/evil/app/Crypto.java", "start_line": 6}); !strings.HasPrefix(out, "     6      public static String decrypt") {
		t.Errorf("read_file start_line: %q", out)
	}
	if out := run(t, reg, "search", map[string]any{"regex": "k3y"}); !strings.Contains(out, "Crypto.java:4") {
		t.Errorf("search: %s", out)
	}
}

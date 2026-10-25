package tui

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/store"
	"openbin.ai/binny/internal/worker"
)

func writeZip(t *testing.T, path string, names ...string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, n := range names {
		w, _ := zw.Create(n)
		w.Write([]byte("x"))
	}
	zw.Close()
	f.Close()
}

func TestIsAndroidPackage(t *testing.T) {
	dir := t.TempDir()
	renamed := filepath.Join(dir, "sample.bin")
	writeZip(t, renamed, "AndroidManifest.xml", "classes.dex")
	plainZip := filepath.Join(dir, "firmware.zip")
	writeZip(t, plainZip, "rootfs.img")
	elf := filepath.Join(dir, "a.out")
	os.WriteFile(elf, []byte("\x7fELF"), 0o644)

	cases := map[string]bool{
		renamed:                      true,
		filepath.Join(dir, "x.apk"):  true, // by extension, even if unreadable
		filepath.Join(dir, "x.XAPK"): true,
		plainZip:                     false,
		elf:                          false,
	}
	for p, want := range cases {
		if got := isAndroidPackage(p); got != want {
			t.Errorf("isAndroidPackage(%s) = %v, want %v", filepath.Base(p), got, want)
		}
	}
}

// fakeJADX stands in for the jadx-worker: it writes the tarball a real run
// would return (sources/ + a decoded manifest).
func fakeJADX(calls *int) func(context.Context, string, string, worker.Logf) error {
	return func(_ context.Context, _ string, out string, _ worker.Logf) error {
		*calls++
		f, err := os.Create(out)
		if err != nil {
			return err
		}
		gz := gzip.NewWriter(f)
		tw := tar.NewWriter(gz)
		for name, body := range map[string]string{
			"./sources/com/evil/Main.java":    "package com.evil;\npublic class Main {}\n",
			"./resources/AndroidManifest.xml": `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.evil"/>`,
		} {
			tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))})
			tw.Write([]byte(body))
		}
		tw.Close()
		gz.Close()
		return f.Close()
	}
}

func TestDecompileLocallyRoutesAPKToJADX(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	calls := 0
	orig := runJADX
	runJADX = fakeJADX(&calls)
	defer func() { runJADX = orig }()

	apk := filepath.Join(t.TempDir(), "evil.apk")
	writeZip(t, apk, "AndroidManifest.xml", "classes.dex")

	meta, _, err := decompileLocally(context.Background(), apk, "", func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	if meta.Kind != store.KindAPK || meta.PackageName != "com.evil" || calls != 1 {
		t.Fatalf("meta = %+v, jadx calls = %d", meta, calls)
	}
	if !store.HasTree(meta.Sha256) {
		t.Fatal("tree not extracted into the store")
	}
	p := localProject(meta)
	if p.Kind != api.KindAPK || !p.IsLocal() || p.PackageName != "com.evil" {
		t.Errorf("local project = %+v", p)
	}

	// Second run is a store hit — no JADX.
	if _, _, err := decompileLocally(context.Background(), apk, "", func(string, ...any) {}); err != nil || calls != 1 {
		t.Errorf("re-decompile: err=%v calls=%d (want a store hit)", err, calls)
	}
}

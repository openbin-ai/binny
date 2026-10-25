package jadx

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type entry struct {
	name     string
	typeflag byte
	body     string
	link     string
}

func writeTarGz(t *testing.T, entries ...entry) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tree.tar.gz")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typeflag, Mode: 0o644, Size: int64(len(e.body)), Linkname: e.link}
		if e.typeflag == tar.TypeDir {
			hdr.Mode, hdr.Size = 0o755, 0
		}
		if e.typeflag == tar.TypeSymlink {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.typeflag == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	gz.Close()
	f.Close()
	return p
}

func TestExtractJADXTree(t *testing.T) {
	tgz := writeTarGz(t,
		entry{name: "./", typeflag: tar.TypeDir},
		entry{name: "./sources/com/evil/Main.java", typeflag: tar.TypeReg, body: "package com.evil;"},
		entry{name: "./resources/AndroidManifest.xml", typeflag: tar.TypeReg, body: "<manifest/>"},
	)
	dir := filepath.Join(t.TempDir(), "src")
	n, err := Extract(tgz, dir)
	if err != nil || n != 2 {
		t.Fatalf("Extract = %d, %v", n, err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "sources", "com", "evil", "Main.java"))
	if err != nil || string(b) != "package com.evil;" {
		t.Fatalf("Main.java = %q, %v", b, err)
	}
}

func TestExtractRejectsHostileMembers(t *testing.T) {
	cases := map[string]entry{
		"traversal": {name: "../escape.txt", typeflag: tar.TypeReg, body: "x"},
		"nested":    {name: "sources/../../escape.txt", typeflag: tar.TypeReg, body: "x"},
		"symlink":   {name: "sources/link", typeflag: tar.TypeSymlink, link: "/etc/passwd"},
	}
	for label, e := range cases {
		parent := t.TempDir()
		_, err := Extract(writeTarGz(t, e), filepath.Join(parent, "src"))
		if err == nil || !strings.Contains(err.Error(), "rejected") {
			t.Errorf("%s: expected rejection, got %v", label, err)
		}
		if _, statErr := os.Stat(filepath.Join(parent, "escape.txt")); statErr == nil {
			t.Errorf("%s: file escaped the extraction dir", label)
		}
	}
}

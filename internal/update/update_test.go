package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"runtime"
	"testing"
)

func makeTarGz(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	tw.Write(content)
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func makeZip(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(content)
	zw.Close()
	return buf.Bytes()
}

func TestExtractTarGz(t *testing.T) {
	// The real tarball nests the binary under binny-<os>-<arch>/binny.
	arc := makeTarGz(t, "binny-linux-amd64/binny", []byte("ELFBINARY"))
	got, err := extractBinary(arc, "binny-linux-amd64.tar.gz", "binny")
	if err != nil || string(got) != "ELFBINARY" {
		t.Fatalf("tar.gz extract = %q, %v", got, err)
	}
}

func TestExtractZip(t *testing.T) {
	arc := makeZip(t, "binny-windows-amd64/binny.exe", []byte("PEBINARY"))
	got, err := extractBinary(arc, "binny-windows-amd64.zip", "binny.exe")
	if err != nil || string(got) != "PEBINARY" {
		t.Fatalf("zip extract = %q, %v", got, err)
	}
}

func TestExtractMissing(t *testing.T) {
	arc := makeTarGz(t, "binny-linux-amd64/README.md", []byte("nope"))
	if _, err := extractBinary(arc, "binny-linux-amd64.tar.gz", "binny"); err == nil {
		t.Fatal("expected an error when the binary isn't in the archive")
	}
}

func TestNormalize(t *testing.T) {
	for _, c := range []struct{ a, b string }{
		{"v0.1.0-beta.5", "0.1.0-beta.5"},
		{"binny v0.1.0", "0.1.0"},
		{" 0.1.0 ", "v0.1.0"},
	} {
		if normalize(c.a) != normalize(c.b) {
			t.Errorf("normalize(%q)=%q != normalize(%q)=%q", c.a, normalize(c.a), c.b, normalize(c.b))
		}
	}
}

func TestAssetName(t *testing.T) {
	got, err := assetName()
	if err != nil {
		t.Skipf("no build for this platform: %v", err)
	}
	want := "binny-" + runtime.GOOS + "-" + runtime.GOARCH + ".tar.gz"
	if runtime.GOOS == "windows" {
		want = "binny-windows-amd64.zip"
	}
	if got != want {
		t.Errorf("assetName() = %q, want %q", got, want)
	}
}

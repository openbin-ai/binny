package archdetect

import (
	"debug/elf"
	"os"
	"path/filepath"
	"testing"
)

// TestDetectRaw: headerless bytes must come back as raw with no processor —
// that's the signal that forces the firmware flow.
func TestDetectRaw(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fw.bin")
	if err := os.WriteFile(p, []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33}, 0o644); err != nil {
		t.Fatal(err)
	}
	g := Detect(p)
	if g.Format != "raw" || g.Processor != "" || g.Known() {
		t.Fatalf("want raw/no-processor, got %+v", g)
	}
}

// TestDetectELF: the host's own /bin/sh (or any ELF found) must map to a
// non-empty Ghidra language ID.
func TestDetectELF(t *testing.T) {
	candidate := "/bin/sh"
	if _, err := elf.Open(candidate); err != nil {
		t.Skipf("no ELF at %s on this platform", candidate)
	}
	g := Detect(candidate)
	if g.Format != "elf" {
		t.Fatalf("want elf, got %+v", g)
	}
	if g.Processor == "" {
		t.Fatalf("expected a processor mapping for the host ELF, got %+v", g)
	}
}

// TestDetectMissing: a nonexistent path is raw (callers stat before calling,
// but Detect must not panic).
func TestDetectMissing(t *testing.T) {
	g := Detect(filepath.Join(t.TempDir(), "nope"))
	if g.Format != "raw" {
		t.Fatalf("want raw for missing file, got %+v", g)
	}
}

// TestDetectZeroPaddedRaw: a raw kernel that starts with zero padding must not
// be mistaken for PE (debug/pe parses a magic-less file as a bare COFF header
// with machine=0x0), or the firmware/processor flow is skipped entirely.
func TestDetectZeroPaddedRaw(t *testing.T) {
	p := filepath.Join(t.TempDir(), "kernel.bin")
	if err := os.WriteFile(p, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	if g := Detect(p); g.Format != "raw" {
		t.Fatalf("want raw, got %+v", g)
	}
}

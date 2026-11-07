package archdetect

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// synthImage builds a raw-image-like blob linked at base: a run of strings in a
// "rodata" region, plus a "code" region full of absolute pointers to those
// strings (base + stringOffset). This is exactly the shape DetectBase keys on.
func synthImage(base uint64, nStrings int) []byte {
	const size = 1 << 20 // 1 MiB
	buf := make([]byte, size)
	rodata := 0x40000 // where strings live
	var strOffs []uint64
	off := rodata
	for i := 0; i < nStrings && off+24 < size; i++ {
		s := []byte("config_param_label_")
		s = append(s, byte('A'+i%26), byte('a'+i%26), 0)
		copy(buf[off:], s)
		strOffs = append(strOffs, uint64(off))
		off += len(s) + 1
	}
	// Code region: scatter LE32 pointers = base + stringOffset.
	code := 0x1000
	ci := code
	for _, so := range strOffs {
		if ci+4 > rodata {
			break
		}
		binary.LittleEndian.PutUint32(buf[ci:], uint32(base+so))
		ci += 8 // leave gaps, like real code between pointer loads
	}
	return buf
}

func writeTmp(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "img.bin")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDetectBaseFindsKSEG0(t *testing.T) {
	p := writeTmp(t, synthImage(0x80000000, 2000))
	g := DetectBase(p, "MIPS:LE:32:default")
	if g.Base != 0x80000000 {
		t.Fatalf("want base 0x80000000, got %#x (score=%d)", g.Base, g.Score)
	}
	if g.Hex != "0x80000000" {
		t.Fatalf("want hex 0x80000000, got %q", g.Hex)
	}
}

func TestDetectBaseArmHigh(t *testing.T) {
	p := writeTmp(t, synthImage(0xC0000000, 1500))
	if g := DetectBase(p, "ARM:LE:32:v7"); g.Base != 0xC0000000 {
		t.Fatalf("want base 0xC0000000, got %#x", g.Base)
	}
}

// Zero/garbage image: no consistent string-pointer alignment ⇒ no base (load at
// offset 0), so we never rebase a plain image that's fine as-is.
func TestDetectBaseNoFalsePositive(t *testing.T) {
	buf := make([]byte, 1<<20) // all zeros
	if g := DetectBase(writeTmp(t, buf), "MIPS:LE:32:default"); g.Base != 0 {
		t.Fatalf("zero image should yield no base, got %#x", g.Base)
	}
	// An image whose pointers already resolve at base 0 (values < file size)
	// must not be rebased either.
	low := make([]byte, 1<<20)
	for i := 0; i+4 <= 0x1000; i += 4 {
		binary.LittleEndian.PutUint32(low[i:], uint32(0x40000+i)) // in-range offsets
	}
	copy(low[0x40000:], []byte("config_param_label_Aa\x00"))
	if g := DetectBase(writeTmp(t, low), "MIPS:LE:32:default"); g.Base != 0 {
		t.Fatalf("in-range-pointer image should yield no base, got %#x", g.Base)
	}
}

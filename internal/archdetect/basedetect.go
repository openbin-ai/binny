package archdetect

// Load-base detection for RAW images.
//
// A raw firmware image loaded at file offset 0 is wrong whenever the code was
// linked to run at a non-zero virtual address (the common case for a kernel:
// MIPS KSEG0 at 0x80000000, many ARM kernels at 0x80000000/0xC0000000). Every
// absolute pointer in the code — a format string, a jump table, a global — then
// points far past the end of the mapped image, so Ghidra can resolve none of
// them: no string xrefs, no data xrefs, and the decompiler prints bare
// address constants instead of the string text.
//
// We recover the base without Ghidra, the way basefind/rbasefind do: at the
// true base B, a pointer word W that points at a string satisfies W-B ==
// (that string's file offset). So every string-pointer in the image votes for
// the same B = W - stringOffset, and B wins by a landslide over random
// coincidences. We collect string start offsets and pointer-like words, let a
// bounded sample vote to nominate candidate bases, then score each candidate
// against all pointers and return the best — if it clears a confidence floor.

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strings"
)

// baseScanCap bounds how much of the image we scan. 64MB covers the code+rodata
// of any realistic single-file kernel image while keeping the scan quick.
const baseScanCap = 64 << 20

const (
	baseMinStrLen    = 6     // min printable run counted as a string start
	baseVoteSample   = 4000  // pointers/strings sampled for candidate nomination
	baseMinScore     = 200   // min string-pointer matches to trust a base
	baseMaxStrings   = 40000 // cap on tracked string starts
	baseMaxPtrs      = 400000
	baseMinPtrValue  = 0x1000 // below this a word is a small int, not a pointer
	baseScoreCandTop = 64     // nominated candidates to fully score
)

// BaseGuess is the outcome of load-base detection.
type BaseGuess struct {
	Base     uint64 // detected load base; 0 == load at file offset 0 (no rebase)
	Hex      string // "0x80000000"; "" when Base==0
	Score    int    // string-pointer matches at Base (confidence)
	Evidence string // human-readable; "" when nothing detected
}

// DetectBase inspects a raw image and returns the load base its code was linked
// for, or a zero BaseGuess when offset-0 is fine (or nothing conclusive). It is
// meaningful only for raw/headerless images; processor supplies endianness and
// word size. 64-bit is handled, but the dominant real-world case is 32-bit.
func DetectBase(path, processor string) BaseGuess {
	fi, err := os.Stat(path)
	if err != nil || fi.Size() < 4096 {
		return BaseGuess{}
	}
	fileSize := uint64(fi.Size())
	buf, err := readCapped(path, baseScanCap)
	if err != nil || len(buf) < 4096 {
		return BaseGuess{}
	}

	be := strings.Contains(processor, ":BE:")
	w64 := strings.Contains(processor, ":64:")

	strOff := stringStartOffsets(buf)
	if len(strOff) < 32 {
		return BaseGuess{}
	}
	ptrs := pointerWords(buf, fileSize, be, w64)
	if len(ptrs) < 64 {
		return BaseGuess{}
	}

	// Nominate candidate bases: a bounded sample of (pointer, stringOffset)
	// pairs each vote B = W - S. True string-pointers pile onto one B.
	sp, so := ptrs, offsetsSlice(strOff)
	if len(sp) > baseVoteSample {
		sp = sampleStride(sp, baseVoteSample)
	}
	if len(so) > baseVoteSample {
		so = so[:baseVoteSample]
	}
	votes := map[uint64]int{}
	for _, w := range sp {
		for _, s := range so {
			if w > s {
				votes[w-s]++
			}
		}
	}

	// Keep the strongest nominations, then score each over ALL pointers.
	type cand struct {
		base  uint64
		votes int
	}
	var cands []cand
	for b, n := range votes {
		if n >= 8 && b > fileSize {
			cands = append(cands, cand{b, n})
		}
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].votes > cands[j].votes })
	if len(cands) > baseScoreCandTop {
		cands = cands[:baseScoreCandTop]
	}

	bestBase, bestScore := uint64(0), 0
	for _, c := range cands {
		score := 0
		for _, w := range ptrs {
			if w >= c.base && strOff[w-c.base] {
				score++
			}
		}
		if score > bestScore {
			bestScore, bestBase = score, c.base
		}
	}

	if bestScore < baseMinScore || bestBase == 0 || bestBase <= fileSize {
		return BaseGuess{}
	}
	ev := fmt.Sprintf("load base %#x: %d pointer words land exactly on string starts (image is linked high, not at offset 0 — without this Ghidra resolves no string/data xrefs)",
		bestBase, bestScore)
	return BaseGuess{Base: bestBase, Hex: fmt.Sprintf("%#x", bestBase), Score: bestScore, Evidence: ev}
}

// stringStartOffsets returns file offsets where a printable run of at least
// baseMinStrLen begins (preceded by a non-printable byte or at offset 0).
func stringStartOffsets(buf []byte) map[uint64]bool {
	out := map[uint64]bool{}
	i, n := 0, len(buf)
	for i < n {
		if isPrintable(buf[i]) && (i == 0 || !isPrintable(buf[i-1])) {
			j := i
			for j < n && isPrintable(buf[j]) {
				j++
			}
			if j-i >= baseMinStrLen {
				out[uint64(i)] = true
				if len(out) >= baseMaxStrings {
					return out
				}
			}
			i = j
		} else {
			i++
		}
	}
	return out
}

// pointerWords returns the distinct word-aligned values that look like absolute
// pointers: at least baseMinPtrValue and >= fileSize (so they cannot already be
// a valid file offset at base 0 — those are the words that reveal a link base).
func pointerWords(buf []byte, fileSize uint64, be, w64 bool) []uint64 {
	seen := map[uint64]bool{}
	step := 4
	read := func(b []byte) uint64 {
		if be {
			return uint64(binary.BigEndian.Uint32(b))
		}
		return uint64(binary.LittleEndian.Uint32(b))
	}
	if w64 {
		step = 8
		read = func(b []byte) uint64 {
			if be {
				return binary.BigEndian.Uint64(b)
			}
			return binary.LittleEndian.Uint64(b)
		}
	}
	for i := 0; i+step <= len(buf); i += step {
		w := read(buf[i : i+step])
		if w < baseMinPtrValue || w < fileSize {
			continue
		}
		if !seen[w] {
			seen[w] = true
			if len(seen) >= baseMaxPtrs {
				break
			}
		}
	}
	out := make([]uint64, 0, len(seen))
	for w := range seen {
		out = append(out, w)
	}
	return out
}

func offsetsSlice(m map[uint64]bool) []uint64 {
	out := make([]uint64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// sampleStride down-samples s to n elements spread across the slice.
func sampleStride(s []uint64, n int) []uint64 {
	if len(s) <= n {
		return s
	}
	out := make([]uint64, 0, n)
	stride := len(s) / n
	for i := 0; i < len(s) && len(out) < n; i += stride {
		out = append(out, s[i])
	}
	return out
}

func isPrintable(c byte) bool { return c >= 0x20 && c < 0x7f }

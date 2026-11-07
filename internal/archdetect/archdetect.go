// Package archdetect maps a binary's headers to a Ghidra processor/language ID
// so local decompiles can force -processor when Ghidra's own autodetect would
// fail (the classic raw-firmware problem). ELF/PE/Mach-O are parsed with the
// stdlib; anything headerless is reported as raw with candidate processors for
// the analyst (or BINNY, via binwalk in the sandbox) to choose from.
package archdetect

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// Guess is the detection outcome.
type Guess struct {
	Format    string // "elf" | "pe" | "macho" | "raw"
	Processor string // Ghidra language ID, "" when unknown
	Detail    string // human-readable summary
}

// Known reports whether the file has a recognized executable format (in which
// case Ghidra's own autodetect is trusted and no -processor force is needed).
func (g Guess) Known() bool { return g.Format != "raw" }

// RawCandidates are the processors worth trying on headerless firmware, most
// common first. Shown as suggestions; binwalk/strings evidence picks one.
var RawCandidates = []string{
	"ARM:LE:32:v7", "ARM:LE:32:v8", "ARM:BE:32:v7",
	"AARCH64:LE:64:v8A",
	"MIPS:BE:32:default", "MIPS:LE:32:default",
	"x86:LE:32:default", "x86:LE:64:default",
	"PowerPC:BE:32:default",
	"RISCV:LE:32:RV32GC", "RISCV:LE:64:RV64GC",
	"Xtensa:LE:32:default", "ARM:LE:32:Cortex",
	"sparc:BE:32:default", "SuperH4:LE:32:default",
	"AVR8:LE:16:extended", "8051:BE:16:default",
}

// Detect inspects the file's header and returns the best guess.
func Detect(path string) Guess {
	if g, ok := detectELF(path); ok {
		return g
	}
	if g, ok := detectPE(path); ok {
		return g
	}
	if g, ok := detectMachO(path); ok {
		return g
	}
	return Guess{Format: "raw", Detail: "no ELF/PE/Mach-O header — raw image (firmware?); Ghidra cannot autodetect, a processor ID must be forced"}
}

func detectELF(path string) (Guess, bool) {
	f, err := elf.Open(path)
	if err != nil {
		return Guess{}, false
	}
	defer f.Close()
	le := f.Data == elf.ELFDATA2LSB
	end, sz := "LE", "32"
	if !le {
		end = "BE"
	}
	if f.Class == elf.ELFCLASS64 {
		sz = "64"
	}
	proc := ""
	switch f.Machine {
	case elf.EM_X86_64:
		proc = "x86:LE:64:default"
	case elf.EM_386:
		proc = "x86:LE:32:default"
	case elf.EM_AARCH64:
		proc = "AARCH64:" + end + ":64:v8A"
	case elf.EM_ARM:
		proc = "ARM:" + end + ":32:v7"
	case elf.EM_MIPS:
		proc = "MIPS:" + end + ":" + sz + ":default"
	case elf.EM_PPC:
		proc = "PowerPC:" + end + ":32:default"
	case elf.EM_PPC64:
		proc = "PowerPC:" + end + ":64:default"
	case elf.EM_RISCV:
		if sz == "64" {
			proc = "RISCV:LE:64:RV64GC"
		} else {
			proc = "RISCV:LE:32:RV32GC"
		}
	case elf.EM_SPARC, elf.EM_SPARCV9:
		proc = "sparc:BE:" + sz + ":default"
	case elf.EM_SH:
		proc = "SuperH4:" + end + ":32:default"
	}
	return Guess{
		Format:    "elf",
		Processor: proc,
		Detail:    fmt.Sprintf("ELF %s-bit %s, machine=%s", sz, end, f.Machine),
	}, true
}

// hasPEMagic reports whether path starts with "MZ" and e_lfanew points at a
// "PE\0\0" signature. debug/pe doesn't require either: without "MZ" it parses
// offset 0 as a bare COFF header, so any headerless image (e.g. a raw kernel
// starting with zero padding) "opens" as PE with machine=0x0 and would skip
// the raw-firmware path — Ghidra then fails to import it.
func hasPEMagic(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var dos [0x40]byte
	if _, err := io.ReadFull(f, dos[:]); err != nil || dos[0] != 'M' || dos[1] != 'Z' {
		return false
	}
	off := int64(binary.LittleEndian.Uint32(dos[0x3c:]))
	var sig [4]byte
	if _, err := f.ReadAt(sig[:], off); err != nil {
		return false
	}
	return sig == [4]byte{'P', 'E', 0, 0}
}

func detectPE(path string) (Guess, bool) {
	if !hasPEMagic(path) {
		return Guess{}, false
	}
	f, err := pe.Open(path)
	if err != nil {
		return Guess{}, false
	}
	defer f.Close()
	proc, name := "", fmt.Sprintf("0x%x", f.Machine)
	switch f.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		proc, name = "x86:LE:64:default", "amd64"
	case pe.IMAGE_FILE_MACHINE_I386:
		proc, name = "x86:LE:32:default", "i386"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		proc, name = "AARCH64:LE:64:v8A", "arm64"
	case pe.IMAGE_FILE_MACHINE_ARMNT:
		proc, name = "ARM:LE:32:v7", "armnt"
	}
	return Guess{Format: "pe", Processor: proc, Detail: "PE, machine=" + name}, true
}

func detectMachO(path string) (Guess, bool) {
	proc, detail := "", ""
	if f, err := macho.Open(path); err == nil {
		defer f.Close()
		proc, detail = machoCPU(f.Cpu)
	} else if ff, err := macho.OpenFat(path); err == nil {
		defer ff.Close()
		if len(ff.Arches) > 0 {
			proc, detail = machoCPU(ff.Arches[0].Cpu)
			detail += fmt.Sprintf(" (fat, %d arches — first slice used)", len(ff.Arches))
		}
	} else {
		return Guess{}, false
	}
	return Guess{Format: "macho", Processor: proc, Detail: "Mach-O, " + detail}, true
}

func machoCPU(c macho.Cpu) (string, string) {
	switch c {
	case macho.CpuAmd64:
		return "x86:LE:64:default", "x86_64"
	case macho.Cpu386:
		return "x86:LE:32:default", "i386"
	case macho.CpuArm64:
		return "AARCH64:LE:64:v8A", "arm64"
	case macho.CpuArm:
		return "ARM:LE:32:v7", "arm"
	default:
		return "", fmt.Sprintf("cpu=0x%x", uint32(c))
	}
}

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/archdetect"
	"openbin.ai/binny/internal/ghidra"
	"openbin.ai/binny/internal/store"
	"openbin.ai/binny/internal/tools"
)

// processorIDRe loosely validates a Ghidra language ID (family:endian:size:variant).
var processorIDRe = regexp.MustCompile(`^[A-Za-z0-9_.+-]+:[LB]E:[0-9]+:[A-Za-z0-9_.+-]+$`)

// registerDecompileTool adds decompile_sample: a local Ghidra headless run over
// the attached sample, with an optional FORCED processor/loader for raw
// firmware Ghidra can't autodetect. The result is stored in the local analysis
// store (no backend, no AWS) and hot-swapped into the toolbox so every read
// tool reflects the new decompile immediately.
func registerDecompileTool(reg *tools.Registry, sess *app.Session, tb *tools.Toolbox, logf ghidra.Logf) {
	reg.Add(&tools.Tool{
		Def: tools.Def("decompile_sample",
			"Decompile the attached sample LOCALLY with Ghidra headless (Docker; takes minutes — the analyst sees progress). Use when the project has no usable analysis, or the architecture was misdetected — the classic raw-firmware case. For a raw/headerless image, FIRST identify the architecture (run `binwalk /sample`, `file /sample`, opcode/endianness heuristics in the sandbox), THEN call this with `processor` set to the Ghidra language ID (e.g. ARM:LE:32:v7, MIPS:BE:32:default, AARCH64:LE:64:v8A) and loader=binary. Results are cached on disk — the same processor choice never re-decompiles. On success every read tool (get_metadata, list_functions, get_function, …) serves the NEW analysis.",
			tools.Obj(map[string]any{
				"processor": tools.StrProp("Ghidra language ID to force, e.g. ARM:LE:32:v7 or MIPS:BE:32:default. Omit for a normal ELF/PE/Mach-O where Ghidra autodetects."),
				"loader":    tools.StrProp("'binary' for a raw/headerless image (requires processor); omit for files with a real executable header"),
			})),
		Handler: func(ctx context.Context, input json.RawMessage) (string, error) {
			var a struct{ Processor, Loader string }
			if err := json.Unmarshal(input, &a); err != nil {
				return "", err
			}
			path := strings.TrimSpace(sess.SamplePath)
			if path == "" {
				return "", fmt.Errorf("no local sample attached — ask the analyst to attach the binary with /sample <path> first")
			}
			a.Processor = strings.TrimSpace(a.Processor)
			a.Loader = strings.ToLower(strings.TrimSpace(a.Loader))
			if a.Processor != "" && !processorIDRe.MatchString(a.Processor) {
				return "", fmt.Errorf("%q doesn't look like a Ghidra language ID (family:endianness:size:variant, e.g. ARM:LE:32:v7)", a.Processor)
			}
			if a.Loader != "" && a.Loader != "binary" {
				return "", fmt.Errorf("loader must be omitted or 'binary'")
			}

			guess := archdetect.Detect(path)
			detectedNote := ""
			if guess.Format == "raw" && a.Processor == "" {
				// Built-in firmware detection first (uImage header / embedded
				// ELF / opcode census) — only push the work back to the model
				// when every detector fails.
				firm := archdetect.DetectFirmware(path)
				if firm.Processor == "" {
					return "", fmt.Errorf("this is a raw image (%s) and automatic detection failed (tried uImage header, embedded ELF objects, opcode signatures). Identify the architecture yourself — run binwalk/file/byte heuristics against /sample in the sandbox — then call again with processor set. Common candidates: %s",
						guess.Detail, strings.Join(archdetect.RawCandidates[:8], ", "))
				}
				a.Processor = firm.Processor
				detectedNote = fmt.Sprintf(" (processor %s auto-detected, %s confidence: %s)",
					firm.Processor, firm.Confidence, strings.Join(firm.Evidence, "; "))
				logf("Raw image — detected %s (%s confidence)", firm.Processor, firm.Confidence)
			}
			if guess.Format == "raw" && a.Loader == "" {
				a.Loader = "binary" // headerless + forced processor ⇒ raw loader
			}

			sha, err := sha256File(path)
			if err != nil {
				return "", err
			}

			var blob []byte
			cacheKey := sha
			cached := false
			if meta, err := store.Load(cacheKey); err == nil && store.Has(cacheKey) && meta.Processor == a.Processor {
				if b, err := store.Blob(cacheKey); err == nil {
					blob, cached = b, true
				}
			}
			if blob == nil {
				// Raw images linked high (e.g. a MIPS KSEG0 kernel at
				// 0x80000000) must load at that base or Ghidra resolves no
				// string/data xrefs; recover it from string-pointer alignment.
				imageBase := ""
				if a.Loader == "binary" {
					if bg := archdetect.DetectBase(path, a.Processor); bg.Base != 0 {
						imageBase = bg.Hex
						logf("Load base %s detected (%s)", bg.Hex, bg.Evidence)
					}
				}
				blob, err = ghidra.Analyze(ctx, ghidra.Request{
					BinaryPath: path,
					Arch:       guess.Detail,
					Processor:  a.Processor,
					Loader:     a.Loader,
					ImageBase:  imageBase,
				}, logf)
				if err != nil {
					return "", fmt.Errorf("local decompile failed: %w", err)
				}
			}

			if err := tb.SetAnalysisRaw(blob); err != nil {
				return "", fmt.Errorf("worker returned an unusable analysis: %w", err)
			}
			a2, _ := tb.Analysis()
			meta := store.Meta{
				Sha256: sha, Name: filepath.Base(path), SamplePath: path,
				Processor: a.Processor,
			}
			if a2 != nil {
				meta.Language = a2.Metadata.Language
				meta.Format = a2.Metadata.ExecutableFormat
			}
			if err := store.Save(meta, blob); err != nil {
				logf("warning: analysis produced but local save failed: %v", err)
			}

			src := "decompiled locally"
			if cached {
				src = "loaded from the local store (already decompiled with this processor)"
			}
			if a2 != nil {
				return fmt.Sprintf("%s%s: language=%s format=%s — %d functions, %d strings, %d imports. All read tools now serve this analysis.",
					src, detectedNote, orUnknown(a2.Metadata.Language), orUnknown(a2.Metadata.ExecutableFormat),
					a2.Metadata.FunctionCount, a2.Metadata.StringCount, a2.Metadata.ImportCount), nil
			}
			return src + detectedNote + " — analysis loaded.", nil
		},
	})
}

// sha256File streams a file's sha256 (firmware images can be hundreds of MB).
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

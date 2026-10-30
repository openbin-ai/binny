package serve

// GUI-driven binary analysis: drop a binary (.exe/.elf/Mach-O/…) into the window
// and BINNY runs the same local Ghidra worker the CLI uses, caches the analysis
// by sha256, and enters binary chat mode — the agent answers over the Ghidra
// toolbox (functions/strings/imports/xrefs/…). The sibling of handleDecompile
// (APK/JADX), mirroring the TUI's decompileLocally binary branch. Fully local:
// no login, nothing leaves the machine.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/archdetect"
	"openbin.ai/binny/internal/ghidra"
	"openbin.ai/binny/internal/store"
	"openbin.ai/binny/internal/tools"
	"openbin.ai/binny/internal/worker"
)

// errNeedProcessor signals a raw/headerless image whose architecture couldn't be
// auto-detected: the GUI must ask the user to pick a processor and resubmit.
var errNeedProcessor = errors.New("need processor")

// analyzeBinary is the real local pipeline, swappable in tests (which can't run
// Docker) — mirrors decompileAPK. processor is "" for auto-detect, or a forced
// Ghidra language id (raw/firmware images).
var analyzeBinary = realAnalyzeBinary

func realAnalyzeBinary(ctx context.Context, binPath, name, processor string, size int64, logf worker.Logf) (store.Meta, error) {
	var zero store.Meta
	sha, err := fileSHA(binPath)
	if err != nil {
		return zero, err
	}
	// Reuse a cached analysis for this exact binary + processor choice (a store
	// hit with the same processor is a free re-attach, no Ghidra run).
	if store.Has(sha) {
		if meta, err := store.Load(sha); err == nil && meta.Processor == processor {
			logf("Already analyzed — using the cached analysis (%s).", store.LocalID(sha))
			meta.SamplePath = binPath
			return *meta, nil
		}
	}

	guess := archdetect.Detect(binPath)
	logf("Format: %s", guess.Detail)
	loader := ""
	if guess.Format == "raw" {
		loader = "binary"
		if processor == "" {
			// Try to identify firmware automatically (uImage/embedded ELF/opcodes)
			// before asking the analyst to pick — same ladder the TUI uses.
			logf("Raw image — scanning for architecture evidence…")
			firm := archdetect.DetectFirmware(binPath)
			if firm.Processor == "" {
				return zero, errNeedProcessor // GUI will prompt for a processor
			}
			processor = firm.Processor
			logf("Detected %s (%s confidence):", firm.Processor, firm.Confidence)
			for _, ev := range firm.Evidence {
				logf("  · %s", ev)
			}
		}
	}
	if processor != "" {
		logf("Using processor %s.", processor)
	}

	logf("Running Ghidra on %s…", name)
	blob, err := ghidra.Analyze(ctx, ghidra.Request{BinaryPath: binPath, Arch: guess.Detail, Processor: processor, Loader: loader}, logf)
	if err != nil {
		return zero, err
	}
	a, err := api.ParseAnalysis(blob)
	if err != nil {
		return zero, fmt.Errorf("worker returned an unusable analysis: %w", err)
	}
	meta := store.Meta{
		Sha256:     sha,
		Name:       name,
		SamplePath: binPath,
		SizeBytes:  size,
		Language:   a.Metadata.Language,
		Format:     a.Metadata.ExecutableFormat,
		Processor:  processor,
	}
	if err := store.Save(meta, blob); err != nil {
		return zero, fmt.Errorf("analysis succeeded but saving locally failed: %w", err)
	}
	logf("Done: %s — %d functions, %d strings, %d imports. Stored locally (%s).",
		a.Metadata.Language, a.Metadata.FunctionCount, a.Metadata.StringCount, a.Metadata.ImportCount, store.LocalID(sha))
	return meta, nil
}

// localBinaryProject synthesizes the api.Project a local analysis stands in for,
// so the toolbox treats it as a (local) BIN project. Mirrors tui.localProject.
func localBinaryProject(meta store.Meta) *api.Project {
	arch := meta.Processor
	if arch == "" {
		arch = meta.Language
	}
	return &api.Project{
		ID:               store.LocalID(meta.Sha256),
		Kind:             api.KindBIN,
		Name:             meta.Name,
		OriginalFilename: meta.Name,
		SizeBytes:        meta.SizeBytes,
		Sha256:           meta.Sha256,
		Status:           "READY",
		AnalysisMode:     "MALWARE",
		Arch:             arch,
		ExecutableFormat: meta.Format,
		LanguageID:       meta.Language,
		CreatedAt:        meta.CreatedAt,
	}
}

// handleAnalyze accepts an uploaded binary (multipart field "file"), runs Ghidra
// locally, and enters binary chat mode, streaming progress over SSE:
//
//	{type:progress,text}  {type:ready,kind:"BIN",name,summary}  {type:error,error}
func (s *server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	file, hdr, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "expected a 'file' upload: "+err.Error())
		return
	}
	defer file.Close()

	// Preserve the original basename so archdetect/Ghidra see a sensible name.
	tmpDir, err := os.MkdirTemp("", "binny-bin-*")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer os.RemoveAll(tmpDir)
	tmpPath := filepath.Join(tmpDir, filepath.Base(hdr.Filename))
	tmp, err := os.Create(tmpPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	size, err := io.Copy(tmp, file)
	tmp.Close()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "saving upload: "+err.Error())
		return
	}

	send, ok := sseSender(w)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	logf := func(format string, args ...any) {
		send(map[string]any{"type": "progress", "text": fmt.Sprintf(format, args...)})
	}

	processor := r.FormValue("processor") // "" = auto-detect; set for raw/firmware

	send(map[string]any{"type": "progress", "text": fmt.Sprintf("Analyzing %s (%d bytes) with Ghidra…", hdr.Filename, size)})
	meta, err := analyzeBinary(r.Context(), tmpPath, hdr.Filename, processor, size, logf)
	if errors.Is(err, errNeedProcessor) {
		send(map[string]any{
			"type":       "need_processor",
			"name":       hdr.Filename,
			"candidates": archdetect.RawCandidates,
			"note":       "This looks like a raw/headerless image (firmware). Pick the CPU architecture to analyze it as.",
		})
		return
	}
	if err != nil {
		send(map[string]any{"type": "error", "error": err.Error()})
		return
	}

	project := localBinaryProject(meta)
	reg := tools.NewRegistry()
	tb := tools.NewToolbox(nil, project) // local blob read needs no backend client
	tb.RegisterRead(reg)
	summary, isErr := reg.Run(r.Context(), "get_metadata", []byte(`{}`))
	if isErr {
		send(map[string]any{"type": "error", "error": summary})
		return
	}
	s.setBinaryProject(project.ID, reg, tb)
	send(map[string]any{"type": "ready", "kind": "BIN", "name": meta.Name, "projectId": project.ID, "summary": summary})
}

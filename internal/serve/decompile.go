package serve

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"openbin.ai/binny/internal/jadx"
	"openbin.ai/binny/internal/store"
	"openbin.ai/binny/internal/worker"
)

// GUI-driven decompile: drop an APK into the window and binny decompiles it
// locally (the same JADX Docker worker the CLI uses), then serves the tree — so
// the desktop app is self-sufficient without --serve-dir. The decompiled source
// is cached in the local store by sha256, so re-dropping the same APK is instant.

type decompileResult struct {
	SrcDir  string
	Package string
	Name    string
	Sha     string
}

// decompileAPK is the real local pipeline, swappable in tests (which can't run
// Docker) — mirrors the TUI's runJADX seam.
var decompileAPK = realDecompileAPK

func realDecompileAPK(ctx context.Context, apkPath, name string, size int64, logf worker.Logf) (decompileResult, error) {
	sha, err := fileSHA(apkPath)
	if err != nil {
		return decompileResult{}, err
	}
	// Reuse a cached tree for this exact APK.
	if store.HasTree(sha) {
		if meta, err := store.Load(sha); err == nil && meta.Kind == store.KindAPK {
			if src, err := store.SrcDir(sha); err == nil {
				logf("Already decompiled — using the cached tree (%s).", store.LocalID(sha))
				return decompileResult{SrcDir: src, Package: meta.PackageName, Name: meta.Name, Sha: sha}, nil
			}
		}
	}
	tar, err := store.TreeTarball(sha)
	if err != nil {
		return decompileResult{}, err
	}
	if err := jadx.Decompile(ctx, apkPath, tar, logf); err != nil {
		return decompileResult{}, err
	}
	src, err := store.SrcDir(sha)
	if err != nil {
		return decompileResult{}, err
	}
	n, err := jadx.Extract(tar, src)
	if err != nil {
		return decompileResult{}, err
	}
	logf("Done: %d files decompiled. Stored locally (%s).", n, store.LocalID(sha))
	meta := store.Meta{Sha256: sha, Kind: store.KindAPK, Name: name, SizeBytes: size, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	_ = store.SaveMeta(meta)
	return decompileResult{SrcDir: src, Package: meta.PackageName, Name: name, Sha: sha}, nil
}

func fileSHA(path string) (string, error) {
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

const maxUploadBytes = 512 << 20 // 512 MB APK cap

// handleDecompile accepts an uploaded APK (multipart field "apk"), decompiles it
// locally, swaps the served tree to the result, and streams progress over SSE:
//
//	{type:progress,text}  {type:ready,root,package,name}  {type:error,error}
func (s *server) handleDecompile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	file, hdr, err := r.FormFile("apk")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "expected an 'apk' file upload: "+err.Error())
		return
	}
	defer file.Close()

	// Stash the upload in a temp file for the worker to mount.
	tmp, err := os.CreateTemp("", "binny-upload-*.apk")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	size, err := io.Copy(tmp, file)
	tmp.Close()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "saving upload: "+err.Error())
		return
	}

	// SSE from here on.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	send := func(ev map[string]any) {
		b, _ := json.Marshal(ev)
		fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
	}
	logf := func(format string, args ...any) { send(map[string]any{"type": "progress", "text": fmt.Sprintf(format, args...)}) }

	send(map[string]any{"type": "progress", "text": fmt.Sprintf("Decompiling %s (%d bytes) with JADX…", hdr.Filename, size)})
	res, err := decompileAPK(r.Context(), tmpPath, hdr.Filename, size, logf)
	if err != nil {
		send(map[string]any{"type": "error", "error": err.Error()})
		return
	}
	s.setDir(res.SrcDir)
	root, err := buildTree(res.SrcDir)
	if err != nil {
		send(map[string]any{"type": "error", "error": err.Error()})
		return
	}
	send(map[string]any{"type": "ready", "root": root, "package": res.Package, "name": res.Name})
}

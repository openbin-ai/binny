package serve

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
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
//	{type:job,id}  {type:progress,text}  {type:ready,root,package,name}  {type:error,error}
//
// The decompile is a job (jobs.go): it keeps running if this response is cut
// off, and the client resumes the stream from /api/job.
func (s *server) handleDecompile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	file, hdr, err := r.FormFile("apk")
	if err != nil {
		status, msg := uploadErr("apk", err)
		log.Printf("decompile: rejected upload: %s", msg)
		writeErr(w, status, msg)
		return
	}
	defer file.Close()

	// Stash the upload in a temp file for the worker to mount. The job owns it
	// from here: it must outlive this request.
	tmp, err := os.CreateTemp("", "binny-upload-*.apk")
	if err != nil {
		log.Printf("decompile: %s: %v", hdr.Filename, err)
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	tmpPath := tmp.Name()
	size, err := io.Copy(tmp, file)
	tmp.Close()
	if err != nil {
		os.Remove(tmpPath)
		log.Printf("decompile: %s: saving upload: %v", hdr.Filename, err)
		writeErr(w, http.StatusInternalServerError, "saving upload: "+err.Error())
		return
	}
	name := hdr.Filename

	j := s.startJob("decompile", func(ctx context.Context, emit func(map[string]any)) {
		defer os.Remove(tmpPath)
		// Everything the UI is told is mirrored to the log: the sidecar's stderr
		// is the only record once the window is gone, and a silent failure is
		// undebuggable.
		logf := func(format string, args ...any) {
			line := fmt.Sprintf(format, args...)
			log.Printf("decompile: %s", line)
			emit(map[string]any{"type": "progress", "text": line})
		}
		fail := func(err error) {
			log.Printf("decompile: %s FAILED: %v", name, err)
			emit(map[string]any{"type": "error", "error": err.Error()})
		}

		logf("Decompiling %s (%d bytes) with JADX…", name, size)
		res, err := decompileAPK(ctx, tmpPath, name, size, logf)
		if err != nil {
			fail(err)
			return
		}
		s.setDir(res.SrcDir)
		// Keep the APK itself: the sandbox unzips it for assets/, res/raw/, lib/.
		if _, err := s.keepSample(res.Sha, name, tmpPath); err != nil {
			logf("Couldn't keep the APK for extraction (%v) — attach it later with Attach sample.", err)
		}
		root, err := buildTree(res.SrcDir)
		if err != nil {
			fail(err)
			return
		}
		emit(map[string]any{"type": "ready", "root": root, "package": res.Package, "name": res.Name})
	})
	streamJob(w, r, j, 0)
}

// uploadErr turns a failed multipart read into a status and a message a person
// can act on. The size check matches on text because *http.MaxBytesError needs
// Go 1.19 and go.mod targets 1.18.
func uploadErr(field string, err error) (int, string) {
	if strings.Contains(err.Error(), "request body too large") {
		return http.StatusRequestEntityTooLarge,
			fmt.Sprintf("file is larger than the %d MB upload limit", maxUploadBytes>>20)
	}
	return http.StatusBadRequest, fmt.Sprintf("expected a '%s' file upload: %v", field, err)
}

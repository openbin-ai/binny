// Package ghidra runs the openbin ghidra-worker Docker image locally so BINNY
// can create and decompile projects without the backend (and without any AWS
// cost). It is a port of the openbin CLI's local-worker orchestration
// (cli/ghidra.go) with two deliberate differences:
//
//   - Output goes through a Logf callback, never straight to stderr — BINNY
//     is a fullscreen TUI and raw stderr writes would corrupt the display.
//   - The multipart request carries `processor` and `loader` fields so a
//     forced Ghidra language ID (firmware whose arch Ghidra can't autodetect)
//     reaches analyzeHeadless. Requires ghidra-worker:7+.
//
// Docker plumbing (image cache shared with the CLI, container lifecycle) lives
// in package worker; this package is the Ghidra-specific request/response.
package ghidra

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"openbin.ai/binny/internal/worker"
)

// DefaultImage is the worker tag BINNY runs. The tag is the cache key — keep it
// in lockstep with the openbin CLI's ghidraWorkerImage (cli/config.go) and the
// --tag in .github/workflows/release-cli.yml. :7 adds -processor/-loader
// passthrough for firmware whose arch Ghidra can't autodetect; :8 adds raw-image
// string xrefs (image_base → -loader-baseAddr, string_refs output), streaming
// serialize, and a runtime-tunable heap (MAXMEM, default 2G — see workerHeap).
const DefaultImage = "openbin/ghidra-worker:8"

// ImageTarball is the release asset / cache filename (version-less on purpose;
// the tag inside is the version).
const ImageTarball = "ghidra-worker.tar.gz"

// Image resolves the worker image: OPENBIN_GHIDRA_IMAGE env wins, else default.
func Image() string {
	if v := os.Getenv("OPENBIN_GHIDRA_IMAGE"); v != "" {
		return v
	}
	return DefaultImage
}

// Logf receives human-readable progress lines (no trailing newline).
type Logf = worker.Logf

// Request is one local decompile job.
type Request struct {
	BinaryPath string
	Arch       string // display label, round-tripped into metadata ("" → auto)
	Processor  string // Ghidra language ID to FORCE (e.g. ARM:LE:32:v7); "" → autodetect
	Loader     string // "" (autodetect) or "binary" (headerless/raw firmware; needs Processor)
	ImageBase  string // raw-image load base, hex (e.g. "0x80000000"); "" → 0. Only honored with Loader=="binary"; needs the binny worker image.
	Image      string // "" → Image()

	// Optional wall-clock overrides in seconds (0 = worker defaults:
	// 1500s whole-run / 1200s auto-analysis / 150s reserved for extract).
	// Large stripped firmware (e.g. a multi-MB vendor-driver kernel with
	// 10k+ functions) needs all three raised: auto-analysis + decompile can
	// run 40+ minutes, and the post-decompile listing/serialize phase needs
	// a bigger tail than 150s or extract.py is killed before it writes
	// result.json (surfacing as the worker's "exited 0 but no result.json").
	AnalyzeTimeoutSec    int
	PerFileTimeoutSec    int
	ExtractTailMarginSec int
}

// Analyze runs the full local pipeline: ensure the image, start a container on
// a loopback port, POST the binary, tear down. Returns the raw worker JSON —
// the exact bytes the cloud pipeline used to produce, ready to store locally
// or forward to ingest. ctx cancellation (Esc in the TUI) aborts the run.
func Analyze(ctx context.Context, req Request, logf Logf) ([]byte, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	image := req.Image
	if image == "" {
		image = Image()
	}
	req.applyBudgetDefaults()
	if req.Loader == "binary" && req.Processor == "" {
		return nil, fmt.Errorf("loader=binary (raw image) requires a processor ID — Ghidra has no headers to autodetect from")
	}

	if err := EnsureImage(image, logf); err != nil {
		return nil, err
	}
	c, err := worker.Start(image, "ghidra-worker", req.env()...)
	if err != nil {
		return nil, err
	}
	defer c.Stop()

	if err := c.WaitHealthy(ctx, 60*time.Second); err != nil {
		c.LogTail(logf)
		return nil, err
	}

	logf("Ghidra analyzing %s… (this can take minutes; Esc cancels)", filepath.Base(req.BinaryPath))
	body, err := postBinary(ctx, c, req)
	if err != nil {
		c.LogTail(logf)
		return nil, err
	}
	return body, nil
}

// applyBudgetDefaults fills any unset timeout with BINNY's large-firmware
// budget so every caller (TUI, desktop GUI, agent tool) gets the same headroom.
// The worker's stock 1500s/150s budget kills extract.py on big stripped
// kernels before it writes result.json ("exited 0 but no result.json").
// Each value is overridable via env for the rare binary that needs more.
func (r *Request) applyBudgetDefaults() {
	if r.AnalyzeTimeoutSec <= 0 {
		r.AnalyzeTimeoutSec = envInt("BINNY_ANALYZE_TIMEOUT", 3600) // whole-run hard kill
	}
	if r.PerFileTimeoutSec <= 0 {
		r.PerFileTimeoutSec = envInt("BINNY_PER_FILE_TIMEOUT", 1200) // auto-analysis cap
	}
	if r.ExtractTailMarginSec <= 0 {
		// Reserved out of the total budget for extract.py's post-decompile tail
		// (strings + string_refs + listing + JSON serialize). Loading a raw
		// image at its real base resolves thousands of pointers, so the
		// decompiled output is far larger and serializing it is slow; 600s was
		// too tight and the write was killed mid-serialize (504, no result).
		r.ExtractTailMarginSec = envInt("BINNY_EXTRACT_TAIL_MARGIN", 1200)
	}
}

func envInt(name string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// env renders worker environment overrides for docker run.
func (r Request) env() []string {
	var e []string
	if r.AnalyzeTimeoutSec > 0 {
		e = append(e, fmt.Sprintf("GHIDRA_ANALYZE_TIMEOUT=%d", r.AnalyzeTimeoutSec))
	}
	if r.PerFileTimeoutSec > 0 {
		e = append(e, fmt.Sprintf("GHIDRA_PER_FILE_TIMEOUT=%d", r.PerFileTimeoutSec))
	}
	if r.ExtractTailMarginSec > 0 {
		e = append(e, fmt.Sprintf("GHIDRA_EXTRACT_TAIL_MARGIN=%d", r.ExtractTailMarginSec))
	}
	if heap := r.workerHeap(); heap != "" {
		e = append(e, "MAXMEM="+heap)
	}
	return e
}

// workerHeap picks the JVM heap (-Xmx) for the ghidra worker. Empty means "leave
// the image default" — 2G on the binny worker, same as stock, which is safe on a
// small Docker VM and plenty for an ordinary binary. A raw image loaded at its
// real base (ImageBase set) makes the decompiler resolve thousands of pointers
// and OOMs at 2G, so it gets 4G (needs ~8 GB of VM). BINNY_WORKER_HEAP overrides
// either way, e.g. =6G on a 12 GB VM for fewer stubbed functions. Honored only
// by the binny worker image, whose MAXMEM is env-tunable; harmless on stock :7.
func (r Request) workerHeap() string {
	if v := strings.TrimSpace(os.Getenv("BINNY_WORKER_HEAP")); v != "" {
		return v
	}
	if r.ImageBase != "" {
		return "4G"
	}
	return ""
}

// EnsureImage makes sure the Docker daemon has the Ghidra worker image
// (loaded → cached tarball → release download, shared with the CLI).
func EnsureImage(image string, logf Logf) error {
	return worker.EnsureImage(image, ImageTarball, logf)
}

func postBinary(ctx context.Context, c *worker.Container, req Request) ([]byte, error) {
	f, err := os.Open(req.BinaryPath)
	if err != nil {
		return nil, fmt.Errorf("open binary: %w", err)
	}
	defer f.Close()

	arch := req.Arch
	if arch == "" {
		arch = "auto"
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("arch", arch)
	if req.Processor != "" {
		_ = mw.WriteField("processor", req.Processor)
	}
	if req.Loader != "" {
		_ = mw.WriteField("loader", req.Loader)
	}
	if req.ImageBase != "" {
		// Harmless on the stock worker (unknown Form fields are ignored); the
		// binny worker image turns it into BinaryLoader's -loader-baseAddr.
		_ = mw.WriteField("image_base", req.ImageBase)
	}
	part, err := mw.CreateFormFile("binary", filepath.Base(req.BinaryPath))
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(part, f); err != nil {
		return nil, fmt.Errorf("read binary: %w", err)
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}

	httpReq, _ := http.NewRequestWithContext(ctx, "POST", c.URL("/analyze"), &buf)
	httpReq.Header.Set("Content-Type", mw.FormDataContentType())
	httpReq.Header.Set("Accept", "application/json")

	// Worker's own wall is 25m by default; give it headroom, scaled with an
	// explicit override like the CLI does.
	httpTimeout := 30 * time.Minute
	if req.AnalyzeTimeoutSec > 0 {
		if d := time.Duration(req.AnalyzeTimeoutSec)*time.Second + 5*time.Minute; d > httpTimeout {
			httpTimeout = d
		}
	}
	client := &http.Client{Timeout: httpTimeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("worker /analyze: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read worker response: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, workerError(resp.StatusCode, body)
	}
	return body, nil
}

// LastErrorFile holds the full text of the most recent failed /analyze
// response. The worker's detail is stdout/stderr/ghidra.log tails glued
// together; the useful part (a Jython traceback or OutOfMemoryError in
// ghidra.log) is at the END, so it must never be cut off by a head-truncate.
func LastErrorFile() string {
	return filepath.Join(os.TempDir(), "binny-ghidra-last-error.txt")
}

// workerError turns a non-200 worker response into a readable error: the
// headline, plus the ghidra.log tail (where the real cause lives), with the
// full detail saved to LastErrorFile.
func workerError(status int, body []byte) error {
	detail := string(body)
	var j struct {
		Detail string `json:"detail"`
	}
	if json.Unmarshal(body, &j) == nil && j.Detail != "" {
		detail = j.Detail
	}
	saved := ""
	if os.WriteFile(LastErrorFile(), []byte(detail), 0o600) == nil {
		saved = "\n(full worker output: " + LastErrorFile() + ")"
	}

	headline, _, _ := strings.Cut(detail, "\n")
	cause := ""
	if _, logTail, ok := strings.Cut(detail, "--- ghidra.log (last 2KB) ---"); ok {
		cause = "\n--- ghidra.log (tail) ---\n" + tail(strings.TrimSpace(logTail), 1200)
	} else if detail != headline {
		cause = "\n" + tail(detail, 1200)
	}
	return fmt.Errorf("worker /analyze returned %d: %s%s%s", status, headline, cause, saved)
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

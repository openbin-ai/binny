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
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"openbin.ai/binny/internal/worker"
)

// DefaultImage is the worker tag BINNY runs. The tag is the cache key — keep it
// in lockstep with the openbin CLI's ghidraWorkerImage (cli/config.go) and the
// --tag in .github/workflows/release-cli.yml. :7 adds -processor/-loader
// passthrough for firmware whose arch Ghidra can't autodetect.
const DefaultImage = "openbin/ghidra-worker:7"

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
	Image      string // "" → Image()

	// Optional wall-clock overrides in seconds (0 = worker defaults:
	// 1500s whole-run / 1200s auto-analysis).
	AnalyzeTimeoutSec int
	PerFileTimeoutSec int
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

// env renders worker environment overrides for docker run.
func (r Request) env() []string {
	var e []string
	if r.AnalyzeTimeoutSec > 0 {
		e = append(e, fmt.Sprintf("GHIDRA_ANALYZE_TIMEOUT=%d", r.AnalyzeTimeoutSec))
	}
	if r.PerFileTimeoutSec > 0 {
		e = append(e, fmt.Sprintf("GHIDRA_PER_FILE_TIMEOUT=%d", r.PerFileTimeoutSec))
	}
	return e
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
		return nil, fmt.Errorf("worker /analyze returned %d: %s", resp.StatusCode, worker.Abbrev(string(body), 700))
	}
	return body, nil
}

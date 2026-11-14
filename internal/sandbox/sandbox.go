// Package sandbox runs BINNY's active-extraction tools inside a hardened,
// disposable Docker container. The audience is live malware, so the safety
// posture is non-negotiable:
//
//   - STATIC tier (default): tools READ the sample as data (readelf/objdump/
//     python-on-bytes/binwalk). The sample is NEVER executed. This covers the
//     whole config-extraction and firmware-carving cases.
//   - DYNAMIC tier (opt-in): would EXECUTE the sample. Not enabled here; it
//     belongs behind an explicit /danger flag and even more locked-down flags.
//
// Even STATIC runs in the container (parsing untrusted input is itself risky):
// --network none, read-only sample mount, non-root, dropped caps,
// no-new-privileges, and CPU/mem/pids limits. Never the host — and never sudo:
// what scripts can touch is defined by the MOUNTS, not by host privileges.
//
// The workspace is a real, PERSISTENT host directory mounted rw at /work
// (default ~/.local/share/binny/workspaces/<sample>, or wherever /workspace
// points it). Scripts have unrestricted read/write inside it, and artifacts
// (extracted configs, carved firmware filesystems) survive across sessions.
// Pass workDir "" for the legacy throwaway temp workspace (removed on Close).
package sandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Image is the extraction sandbox image. It bundles binutils + python3 +
// radare2 + binwalk (with squashfs/7z/xz carving helpers). Built from
// binny/sandbox/Dockerfile and loaded locally; the tag is the cache key (bump
// to ship a changed image).
const Image = "openbin/binny-extract:3"

// DefaultRunTimeout bounds one `run` call unless the tool passes its own
// (binwalk on a big firmware image needs more than the old 90s).
const DefaultRunTimeout = 120 * time.Second

// MaxRunTimeout caps a caller-supplied timeout.
const MaxRunTimeout = 900 * time.Second

// Sandbox manages a workspace directory on the host (bind-mounted into the
// container as /work) plus the read-only sample mount.
type Sandbox struct {
	workDir    string // host workspace, mounted rw at /work
	samplePath string // host path to the sample, mounted ro at /sample
	ephemeral  bool   // temp workspace — removed on Close
}

// New creates a sandbox for the given sample. workDir is the persistent host
// workspace to mount at /work (created if missing); "" falls back to a fresh
// throwaway temp dir that Close removes.
func New(samplePath, workDir string) (*Sandbox, error) {
	abs, err := filepath.Abs(samplePath)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(abs); err != nil {
		return nil, fmt.Errorf("sample not found: %w", err)
	}
	ephemeral := false
	if strings.TrimSpace(workDir) == "" {
		workDir, err = os.MkdirTemp("", "binny-extract-*")
		if err != nil {
			return nil, err
		}
		ephemeral = true
	} else {
		workDir, err = filepath.Abs(workDir)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(workDir, 0o755); err != nil {
			return nil, fmt.Errorf("create workspace %s: %w", workDir, err)
		}
	}
	return &Sandbox{workDir: workDir, samplePath: abs, ephemeral: ephemeral}, nil
}

// WorkDir returns the host workspace path (for display and /workspace status).
func (s *Sandbox) WorkDir() string { return s.workDir }

// Close removes the workspace only when it's a throwaway temp dir; a
// persistent workspace's artifacts are the point of keeping it.
func (s *Sandbox) Close() error {
	if s.ephemeral {
		return os.RemoveAll(s.workDir)
	}
	return nil
}

// WriteFile writes content to a path inside the workspace (relative paths only;
// traversal outside /work is rejected).
func (s *Sandbox) WriteFile(rel, content string) error {
	dst, err := s.resolve(rel)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, []byte(content), 0o644)
}

// ReadArtifact reads a file the container produced in the workspace.
func (s *Sandbox) ReadArtifact(rel string) ([]byte, error) {
	src, err := s.resolve(rel)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(src)
}

// resolve maps a workspace-relative path to a host path, rejecting escapes.
// This guards the HOST-side helpers (WriteFile/ReadArtifact); container scripts
// are confined by the mounts themselves.
func (s *Sandbox) resolve(rel string) (string, error) {
	clean := filepath.Clean("/" + rel) // force-absolute then strip
	dst := filepath.Join(s.workDir, clean)
	if !strings.HasPrefix(dst, filepath.Clean(s.workDir)+string(os.PathSeparator)) && dst != s.workDir {
		return "", fmt.Errorf("path %q escapes the workspace", rel)
	}
	return dst, nil
}

// RunResult is the outcome of a sandboxed command.
type RunResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	TimedOut bool
}

// Run executes cmd (via /bin/sh -c) inside the hardened container. The sample
// is available read-only at /sample; the workspace is /work (rw, persistent).
// timeout <= 0 uses DefaultRunTimeout; it is capped at MaxRunTimeout. STATIC
// tier: the sample is data, never executed by us — the model's scripts read it.
func (s *Sandbox) Run(ctx context.Context, cmd string, timeout time.Duration) (*RunResult, error) {
	if timeout <= 0 {
		timeout = DefaultRunTimeout
	}
	if timeout > MaxRunTimeout {
		timeout = MaxRunTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{
		"run", "--rm",
		"--network", "none",
		"--user", sandboxUser(), // the host user, so a 0600 sample it owns is readable (see below)
		"--read-only",
		"--security-opt", "no-new-privileges",
		"--cap-drop", "ALL",
		"--pids-limit", "512",
		"--memory", "2g",
		"--cpus", "2",
		"--tmpfs", "/tmp:rw,size=512m",
		"-v", s.workDir + ":/work:rw",
		"-v", s.samplePath + ":/sample:ro",
		"-w", "/work",
		Image,
		"/bin/sh", "-c", cmd,
	}
	c := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	c.Stdout, c.Stderr = &stdout, &stderr
	err := c.Run()

	res := &RunResult{Stdout: stdout.String(), Stderr: stderr.String()}
	if ctx.Err() == context.DeadlineExceeded {
		res.TimedOut = true
		return res, nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	}
	if err != nil {
		// docker missing / image not loaded / daemon down
		return nil, fmt.Errorf("docker run: %w (stderr: %s)", err, Abbrev(stderr.String(), 200))
	}
	return res, nil
}

// sandboxUser picks the uid:gid the container runs as. We use the HOST user's
// own ids rather than a fixed "nobody" so the container can read the sample the
// analyst attached — their own files are typically 0600, which nobody (65534)
// could not read, and an in-place /sample mount can't be chmod'd. The container
// stays hardened either way (--network none, --cap-drop ALL, --read-only,
// no-new-privileges); a non-root host uid is no less safe than nobody for a
// local, single-user tool reading a sample as data. Falls back to nobody where
// there is no meaningful uid (e.g. Windows, where Getuid returns -1).
func sandboxUser() string {
	uid, gid := os.Getuid(), os.Getgid()
	if uid < 0 || gid < 0 {
		return "65534:65534"
	}
	return fmt.Sprintf("%d:%d", uid, gid)
}

// SampleSHA256 returns the sample's hash (for provenance).
func (s *Sandbox) SampleSHA256() (string, error) {
	f, err := os.Open(s.samplePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 1<<16)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// EnsureImage checks the sandbox image is available locally; returns a helpful
// error if not (with the build command).
func EnsureImage(ctx context.Context) error {
	c := exec.CommandContext(ctx, "docker", "image", "inspect", Image)
	if err := c.Run(); err != nil {
		return fmt.Errorf("sandbox image %s not found — build it: docker build -t %s binny/sandbox", Image, Image)
	}
	return nil
}

// Abbrev truncates for error messages.
func Abbrev(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

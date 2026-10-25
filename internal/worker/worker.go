// Package worker runs the openbin worker Docker images (ghidra-worker,
// jadx-worker) on this machine: make sure the image is loaded, start it on a
// loopback port, wait for /health, tear it down. It is a port of the openbin
// CLI's local-worker orchestration (cli/ghidra.go, cli/jadx.go), with output
// routed through a Logf callback instead of stderr — BINNY is a fullscreen
// TUI and raw stderr writes would corrupt the display.
//
// The image tarball cache is SHARED with the openbin CLI
// ($XDG_DATA_HOME/openbin/<image>.tar.gz), so a user who has already run the
// CLI never re-downloads a worker image for BINNY.
package worker

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Logf receives human-readable progress lines (no trailing newline).
type Logf func(format string, args ...any)

// EnsureImage makes sure the Docker daemon has image, mirroring the CLI's
// resolution order: loaded already → bundled/cached tarball → download the
// named release asset into the shared openbin cache dir.
func EnsureImage(image, tarball string, logf Logf) error {
	if err := dockerPreflight(); err != nil {
		return err
	}
	if dockerImageExists(image) {
		return nil
	}
	dest := filepath.Join(xdgDataHome(), "openbin", tarball)
	if found, ok := findBundledImageTarball(tarball); ok {
		logf("Loading worker image from %s (first run only)…", found)
		if err := loadImageTarball(image, found); err == nil {
			return nil
		}
		// Stale cache after a worker tag bump — the asset name is version-less,
		// so an old cached tarball loads the old tag. Re-download the current one.
		logf("Cached %s doesn't contain %s (stale after a worker update) — re-downloading…", tarball, image)
	}
	if err := downloadWorkerImage(tarball, dest, logf); err != nil {
		return fmt.Errorf("worker image %q not available locally and download failed: %w\n"+
			"You can also drop %s in %s to install it offline.",
			image, err, tarball, filepath.Dir(dest))
	}
	logf("Loading worker image (first run only)…")
	return loadImageTarball(image, dest)
}

// Container is a running worker bound to a loopback port.
type Container struct {
	ID   string
	Port int
	name string // for log/error messages, e.g. "jadx-worker"
}

// Start launches image detached on a free loopback port (the workers listen on
// :8000 inside). No --rm so logs survive a crash for LogTail; Stop removes it.
func Start(image, name string, envVars ...string) (*Container, error) {
	port, err := findFreePort()
	if err != nil {
		return nil, fmt.Errorf("allocate port: %w", err)
	}
	runArgs := []string{"run", "-d", "-p", fmt.Sprintf("127.0.0.1:%d:8000", port)}
	for _, e := range envVars {
		runArgs = append(runArgs, "-e", e)
	}
	runArgs = append(runArgs, image)
	out, err := exec.Command("docker", runArgs...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("docker run failed: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("docker run: %w", err)
	}
	return &Container{ID: strings.TrimSpace(string(out)), Port: port, name: name}, nil
}

// URL is the worker's base URL on loopback.
func (c *Container) URL(path string) string {
	return fmt.Sprintf("http://127.0.0.1:%d%s", c.Port, path)
}

// Stop stops and removes the container. Safe on nil.
func (c *Container) Stop() {
	if c == nil || c.ID == "" {
		return
	}
	_ = exec.Command("docker", "stop", c.ID).Run()
	_ = exec.Command("docker", "rm", "-f", c.ID).Run()
}

// WaitHealthy polls /health until it answers 200, ctx is canceled, or timeout.
func (c *Container) WaitHealthy(ctx context.Context, timeout time.Duration) error {
	url := c.URL("/health")
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("%s did not become healthy within %s", c.name, timeout)
}

// LogTail surfaces the last worker log lines through logf on failure — the
// TUI-safe stand-in for the CLI's full post-mortem dump.
func (c *Container) LogTail(logf Logf) {
	if c == nil || c.ID == "" {
		return
	}
	out, _ := exec.Command("docker", "logs", "--tail", "25", c.ID).CombinedOutput()
	if s := strings.TrimSpace(string(out)); s != "" {
		logf("%s log tail:\n%s", c.name, s)
	}
}

func loadImageTarball(image, tarball string) error {
	if err := exec.Command("docker", "load", "-i", tarball).Run(); err != nil {
		return fmt.Errorf("docker load %s: %w", tarball, err)
	}
	if !dockerImageExists(image) {
		return fmt.Errorf("loaded %s but image %q still not found", tarball, image)
	}
	return nil
}

// dockerPreflight verifies Docker is installed AND the daemon answers, with
// platform-tailored guidance (same failure split as the CLI).
func dockerPreflight() error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("%s", dockerMissingMessage())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "info").CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(out))
		if detail == "" {
			detail = err.Error()
		}
		return fmt.Errorf("Docker is installed but its daemon isn't responding — start it and retry.\nDocker reported: %s", Abbrev(detail, 300))
	}
	return nil
}

func dockerMissingMessage() string {
	switch runtime.GOOS {
	case "darwin", "windows":
		return "Docker is required for local decompiles but wasn't found on PATH. Install Docker Desktop (https://www.docker.com/products/docker-desktop/) and retry."
	default:
		return "Docker is required for local decompiles but wasn't found on PATH. Install Docker Engine (https://docs.docker.com/engine/install/) and add your user to the docker group."
	}
}

func dockerImageExists(image string) bool {
	return exec.Command("docker", "image", "inspect", image).Run() == nil
}

// findBundledImageTarball searches the shared openbin install locations.
func findBundledImageTarball(tarball string) (string, bool) {
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		resolved := exe
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			resolved = real
		}
		candidates = append(candidates, filepath.Join(filepath.Dir(resolved), tarball))
	}
	candidates = append(candidates,
		filepath.Join(xdgDataHome(), "openbin", tarball),
		filepath.Join("/usr/local/share/openbin", tarball),
	)
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, tarball))
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, true
		}
	}
	return "", false
}

func xdgDataHome() string {
	if v := os.Getenv("XDG_DATA_HOME"); v != "" {
		return v
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "share")
	}
	return ""
}

func findFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// Abbrev trims s and cuts it to n bytes with an ellipsis.
func Abbrev(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

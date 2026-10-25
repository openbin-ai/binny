package worker

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// releaseDownloadBase mirrors the openbin CLI: GitHub's stable latest-release
// asset path, overridable via OPENBIN_RELEASE_BASE.
const releaseDownloadBase = "https://github.com/openbin-ai/platform/releases/latest/download"

func releaseBase() string {
	if v := os.Getenv("OPENBIN_RELEASE_BASE"); v != "" {
		return v
	}
	return releaseDownloadBase
}

// downloadWorkerImage streams the named release asset into dest (the shared
// openbin cache dir) with a .part+rename so an interrupted download never
// looks done. Progress goes through logf (~every 64MB) instead of a rewriting
// stderr line.
func downloadWorkerImage(tarball, dest string, logf Logf) error {
	url := releaseBase() + "/" + tarball
	logf("Worker image not found locally — downloading %s (hundreds of MB, first run only; cached at %s)…", tarball, dest)

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	client := &http.Client{Timeout: 60 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("GET %s returned %d", url, resp.StatusCode)
	}

	part := dest + ".part"
	out, err := os.Create(part)
	if err != nil {
		return fmt.Errorf("create %s: %w", part, err)
	}
	pr := &progressReader{r: resp.Body, total: resp.ContentLength, logf: logf}
	if _, err := io.Copy(out, pr); err != nil {
		out.Close()
		os.Remove(part)
		return fmt.Errorf("download: %w", err)
	}
	if err := out.Close(); err != nil {
		os.Remove(part)
		return err
	}
	if err := os.Rename(part, dest); err != nil {
		os.Remove(part)
		return fmt.Errorf("finalize %s: %w", dest, err)
	}
	return nil
}

// progressReader emits a log line every ~64MB (a TUI transcript can't rewrite
// a single line the way the CLI's \r progress does).
type progressReader struct {
	r        io.Reader
	total    int64
	read     int64
	lastTick int64
	logf     Logf
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.read += int64(n)
	if p.read-p.lastTick >= 64<<20 {
		p.lastTick = p.read
		if p.total > 0 {
			p.logf("  downloading: %.0f / %.0f MB (%.0f%%)",
				float64(p.read)/(1<<20), float64(p.total)/(1<<20), float64(p.read)*100/float64(p.total))
		} else {
			p.logf("  downloading: %.0f MB", float64(p.read)/(1<<20))
		}
	}
	return n, err
}

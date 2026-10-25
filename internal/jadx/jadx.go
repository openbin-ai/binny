// Package jadx runs the openapk jadx-worker Docker image locally so BINNY can
// decompile an APK on this machine — the same image, request and tree layout
// as `openbin apk` (cli/jadx.go), with the image cache shared with the CLI.
//
// The worker answers POST /decompile (multipart field `apk`; .apk, .xapk and
// .apks split containers all work) with a tar.gz of the JADX output:
// sources/ (Java) and resources/ (decoded AndroidManifest.xml, res/, assets/,
// lib/). That tarball is byte-for-byte what the backend's CLI-ingest path
// accepts, so a local decompile can later be uploaded as an OpenAPK project
// without decompiling again.
package jadx

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"openbin.ai/binny/internal/worker"
)

// DefaultImage is the worker tag BINNY runs. The tag is the cache key — keep it
// in lockstep with the openbin CLI's jadxWorkerImage (cli/config.go).
const DefaultImage = "openapk/jadx-worker:bundled-2"

// ImageTarball is the release asset / cache filename shared with the CLI.
const ImageTarball = "jadx-worker.tar.gz"

// Image resolves the worker image: OPENAPK_JADX_IMAGE env wins (same variable
// as the CLI), else the default.
func Image() string {
	if v := os.Getenv("OPENAPK_JADX_IMAGE"); v != "" {
		return v
	}
	return DefaultImage
}

// Decompile runs the worker against apkPath and streams the resulting tree
// tarball to outTarGz. ctx cancellation (Esc in the TUI) aborts the run.
func Decompile(ctx context.Context, apkPath, outTarGz string, logf worker.Logf) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	image := Image()
	if err := worker.EnsureImage(image, ImageTarball, logf); err != nil {
		return err
	}
	c, err := worker.Start(image, "jadx-worker")
	if err != nil {
		return err
	}
	defer c.Stop()
	if err := c.WaitHealthy(ctx, 60*time.Second); err != nil {
		c.LogTail(logf)
		return err
	}
	logf("JADX decompiling %s… (minutes for a big app; Esc cancels)", filepath.Base(apkPath))
	if err := postAPK(ctx, c, apkPath, outTarGz); err != nil {
		c.LogTail(logf)
		return err
	}
	return nil
}

// postAPK streams the APK up and the tar.gz back — both can be hundreds of MB
// (game APKs), so neither side is buffered in memory.
func postAPK(ctx context.Context, c *worker.Container, apkPath, outTarGz string) error {
	f, err := os.Open(apkPath)
	if err != nil {
		return fmt.Errorf("open apk: %w", err)
	}
	defer f.Close()

	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		part, err := mw.CreateFormFile("apk", filepath.Base(apkPath))
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		if _, err := io.Copy(part, f); err != nil {
			pw.CloseWithError(fmt.Errorf("read apk: %w", err))
			return
		}
		pw.CloseWithError(mw.Close())
	}()

	req, _ := http.NewRequestWithContext(ctx, "POST", c.URL("/decompile"), pr)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Accept", "application/gzip, application/json")

	// The worker's own wall-clock cap is 15m (JADX_TIMEOUT_SEC); go a touch
	// higher so the request isn't killed as it finalizes the tar stream.
	resp, err := (&http.Client{Timeout: 20 * time.Minute}).Do(req)
	if err != nil {
		return fmt.Errorf("worker /decompile: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return fmt.Errorf("worker /decompile returned %d: %s", resp.StatusCode, worker.Abbrev(string(body), 500))
	}

	part := outTarGz + ".part"
	out, err := os.Create(part)
	if err != nil {
		return fmt.Errorf("create %s: %w", part, err)
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		out.Close()
		os.Remove(part)
		return fmt.Errorf("stream decompiled tree: %w", err)
	}
	if err := out.Close(); err != nil {
		os.Remove(part)
		return err
	}
	return os.Rename(part, outTarGz)
}

// Extract unpacks a JADX tree tarball into dir. Only regular files and
// directories are accepted and every path must stay inside dir — the tarball
// came out of a container that just chewed on an untrusted APK, so a symlink
// or ../ entry is treated as hostile (same rule as the backend's ingest).
// Returns the number of files written.
func Extract(tarGz, dir string) (int, error) {
	f, err := os.Open(tarGz)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return 0, fmt.Errorf("decompiled tree is not gzip: %w", err)
	}
	defer gz.Close()

	root, err := filepath.Abs(dir)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return 0, err
	}
	files := 0
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return files, nil
		}
		if err != nil {
			return files, fmt.Errorf("read decompiled tree: %w", err)
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		if name == "" || name == "." {
			continue
		}
		dest := filepath.Join(root, filepath.FromSlash(name))
		if dest != root && !strings.HasPrefix(dest, root+string(filepath.Separator)) {
			return files, fmt.Errorf("decompiled tree rejected: unsafe path %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dest, 0o755); err != nil {
				return files, err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
				return files, err
			}
			out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return files, err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return files, err
			}
			if err := out.Close(); err != nil {
				return files, err
			}
			files++
		default:
			return files, fmt.Errorf("decompiled tree rejected: non-file member %q (type %q)", hdr.Name, hdr.Typeflag)
		}
	}
}

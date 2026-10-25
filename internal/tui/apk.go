package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/jadx"
	"openbin.ai/binny/internal/store"
	"openbin.ai/binny/internal/tools"
	"openbin.ai/binny/internal/worker"
)

// The local APK flow: /decompile on an .apk/.xapk runs the openbin CLI's
// jadx-worker image on this machine and keeps the tree in the local store —
// every APK tool then reads it from disk, no backend involved. /upload later
// turns it into an OpenAPK project with the same request `openbin apk` sends,
// reusing the stored tarball (no second decompile).

// runJADX is the worker call, swappable so tests can exercise the whole APK
// pipeline without Docker.
var runJADX = jadx.Decompile

// decompileAPKLocally is decompileLocally's APK branch: hash → store hit? →
// JADX → extract → store.
func decompileAPKLocally(ctx context.Context, path string, size int64, logf worker.Logf) (store.Meta, error) {
	var zero store.Meta
	logf("Hashing %s (%.1f MB)…", filepath.Base(path), float64(size)/(1024*1024))
	sha, err := sha256FileTUI(path)
	if err != nil {
		return zero, err
	}
	if store.HasTree(sha) {
		if meta, err := store.Load(sha); err == nil && meta.Kind == store.KindAPK {
			meta.SamplePath = path // refresh in case the file moved
			logf("Already decompiled locally — attaching from the store (no JADX run).")
			return *meta, nil
		}
	}

	tarPath, err := store.TreeTarball(sha)
	if err != nil {
		return zero, err
	}
	if err := os.MkdirAll(filepath.Dir(tarPath), 0o755); err != nil {
		return zero, err
	}
	logf("Android package — decompiling locally with JADX (the openbin CLI's jadx-worker).")
	if err := runJADX(ctx, path, tarPath, logf); err != nil {
		return zero, err
	}
	src, err := store.SrcDir(sha)
	if err != nil {
		return zero, err
	}
	_ = os.RemoveAll(src) // a half-extracted tree from an interrupted run
	n, err := jadx.Extract(tarPath, src)
	if err != nil {
		_ = os.RemoveAll(src)
		return zero, fmt.Errorf("unpack decompiled tree: %w", err)
	}

	meta := store.Meta{
		Sha256:      sha,
		Kind:        store.KindAPK,
		Name:        filepath.Base(path),
		SamplePath:  path,
		SizeBytes:   size,
		PackageName: apkPackageName(src),
	}
	if err := store.SaveMeta(meta); err != nil {
		return zero, fmt.Errorf("decompile succeeded but saving locally failed: %w", err)
	}
	logf("Done: %d files decompiled (package %s). Stored locally (%s).", n, orDefault(meta.PackageName, "unknown"), sha[:12])
	return meta, nil
}

var reManifestPackage = regexp.MustCompile(`<manifest[^>]*\spackage="([^"]+)"`)

// apkPackageName reads the package off the decoded manifest for the project
// label; "" when JADX produced no manifest.
func apkPackageName(src string) string {
	data, err := os.ReadFile(filepath.Join(src, "resources", "AndroidManifest.xml"))
	if err != nil {
		return ""
	}
	if m := reManifestPackage.FindSubmatch(data); m != nil {
		return string(m[1])
	}
	return ""
}

// --- /upload ---------------------------------------------------------------

// uploadLogMsg / uploadDoneMsg mirror the decompile messages for /upload.
type uploadLogMsg struct{ line string }

type uploadDoneMsg struct {
	project *api.Project
	sha     string
	err     error
}

// uploadReadyTimeout bounds the wait for the backend's ingest (tree extract,
// S3 push, file tree, usage index) to flip the new project READY.
const uploadReadyTimeout = 15 * time.Minute

// cmdUpload turns the attached local APK project into an OpenAPK project.
func (m *Model) cmdUpload() tea.Cmd {
	p := m.sess.Project
	if p == nil || !p.IsLocal() || p.Kind != api.KindAPK {
		m.append(sysLine("/upload creates an OpenAPK project from a locally decompiled APK — /decompile <app.apk> first."))
		return nil
	}
	if m.uploading {
		m.append(warnLine("An upload is already running."))
		return nil
	}
	meta, err := store.Load(p.Sha256)
	if err != nil {
		m.append(errLine("Local project metadata missing: " + err.Error()))
		return nil
	}
	if meta.ProjectID != "" {
		m.append(sysLine(fmt.Sprintf("Already uploaded as OpenAPK project %s — open it with /project.", meta.ProjectID)))
		return nil
	}
	apk := m.sess.SamplePath
	if apk == "" {
		apk = meta.SamplePath
	}
	if _, err := os.Stat(apk); err != nil {
		m.append(errLine(fmt.Sprintf("The original APK isn't at %s any more — /sample <path> to point at it, then /upload.", apk)))
		return nil
	}
	tree, err := store.TreeTarball(p.Sha256)
	if err == nil {
		_, err = os.Stat(tree)
	}
	if err != nil {
		m.append(errLine("The stored JADX tarball is missing — re-run /decompile on the APK, then /upload."))
		return nil
	}

	m.uploading = true
	m.append(sysLine(fmt.Sprintf("Uploading %s + its decompiled tree to OpenAPK (no re-decompile)…", filepath.Base(apk))))
	client, prog, sha := m.sess.API, m.program, p.Sha256
	return func() tea.Msg {
		logf := func(format string, args ...any) {
			if prog != nil {
				prog.Send(uploadLogMsg{line: fmt.Sprintf(format, args...)})
			}
		}
		proj, err := client.UploadAPKProject(apk, tree)
		if err != nil {
			return uploadDoneMsg{sha: sha, err: err}
		}
		logf("Uploaded — project %s created; waiting for OpenAPK to finish ingesting it…", proj.ID)
		proj, err = waitReady(client, proj.ID, uploadReadyTimeout, 3*time.Second)
		return uploadDoneMsg{project: proj, sha: sha, err: err}
	}
}

// waitReady polls a freshly uploaded project until the backend's ingest flips
// it READY (or FAILED, or the deadline passes).
func waitReady(client *api.Client, id string, timeout, every time.Duration) (*api.Project, error) {
	deadline := time.Now().Add(timeout)
	for {
		p, err := client.GetProject(id)
		if err == nil {
			switch p.Status {
			case "READY":
				return p, nil
			case "FAILED":
				return p, fmt.Errorf("OpenAPK ingest failed: %s", orDefault(p.ErrorMessage, "no error message"))
			}
		}
		if time.Now().After(deadline) {
			if err != nil {
				return nil, err
			}
			return p, fmt.Errorf("project %s still %s after %s — it may finish on its own; check it in OpenAPK", id, p.Status, timeout)
		}
		time.Sleep(every)
	}
}

// handleUploadDone records the backend project on the local meta and, when no
// session is running yet, re-attaches BINNY to the backend copy.
func (m *Model) handleUploadDone(msg uploadDoneMsg) {
	m.uploading = false
	if msg.project != nil {
		if meta, err := store.Load(msg.sha); err == nil {
			meta.ProjectID = msg.project.ID
			_ = store.SaveMeta(*meta)
		}
	}
	if msg.err != nil {
		m.append(errLine("Upload: " + msg.err.Error()))
		return
	}
	p := msg.project
	m.append(okLine(fmt.Sprintf("OpenAPK project %q is READY (%s).", p.Name, p.ID)))
	if m.engineStarted {
		m.append(sysLine("This session keeps working on the local copy; open the OpenAPK project next time with /project."))
		return
	}
	m.sess.Project = p
	m.sess.Sample = nil
	m.append(sysLine("Attached to the OpenAPK project — tools now read from the backend, and findings, highlights and the report land on it."))
}

// --- source-tree cache for BACKEND APK projects ------------------------------

// treeCacheMsg is a status line from the background source-tree prefetch.
type treeCacheMsg struct{ line string }

// prefetchTree pulls a backend APK project's source tree into the local cache
// in the background, so the agent's reads never touch the backend. nil for
// anything else.
func (m *Model) prefetchTree(p api.Project) tea.Cmd {
	if p.IsLocal() || p.Kind != api.KindAPK || !p.Ready() || m.sess.API == nil {
		return nil
	}
	client, prog, id := m.sess.API, m.program, p.ID
	return func() tea.Msg {
		logf := func(format string, args ...any) {
			if prog != nil {
				prog.Send(treeCacheMsg{line: fmt.Sprintf(format, args...)})
			}
		}
		if err := tools.PrefetchSourceTree(client, id, logf); err != nil {
			return treeCacheMsg{line: "Couldn't cache the source tree locally (" + err.Error() + ") — reads will go through the backend."}
		}
		return nil
	}
}

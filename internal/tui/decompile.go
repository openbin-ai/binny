package tui

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/archdetect"
	"openbin.ai/binny/internal/ghidra"
	"openbin.ai/binny/internal/sandbox"
	"openbin.ai/binny/internal/store"
)

// The local-decompile flow: BINNY runs the same ghidra-worker Docker image the
// openbin CLI uses, entirely on this machine, and keeps the result in the
// local analysis store — no backend project, no AWS cost. Reached from the
// start menu ("Decompile a local binary or APK") or /decompile in the REPL.
// APKs branch off to the JADX flow in apk.go.

// decompLogMsg is one progress line pushed from the background decompile.
type decompLogMsg struct{ line string }

// decompDoneMsg ends a background decompile.
type decompDoneMsg struct {
	meta store.Meta
	err  error
	hint string // extra guidance (e.g. binwalk output for a raw image)
}

// runDecompile decompiles path locally in the background, streaming progress
// via program.Send. processor ("" = autodetect) forces a Ghidra language ID.
func (m *Model) runDecompile(path, processor string) tea.Cmd {
	prog := m.program
	ctx, cancel := context.WithCancel(context.Background())
	m.decompCancel = cancel
	m.decompiling = true
	return func() tea.Msg {
		defer cancel()
		logf := func(format string, args ...any) {
			if prog != nil {
				prog.Send(decompLogMsg{line: fmt.Sprintf(format, args...)})
			}
		}
		meta, hint, err := decompileLocally(ctx, path, processor, logf)
		return decompDoneMsg{meta: meta, err: err, hint: hint}
	}
}

// decompileLocally is the shared pipeline: hash → store hit? → arch detect →
// (raw? identify via binwalk & bail with guidance) → ghidra → store.
func decompileLocally(ctx context.Context, path, processor string, logf ghidra.Logf) (store.Meta, string, error) {
	var zero store.Meta
	path = strings.Trim(strings.TrimSpace(path), `"'`)
	info, err := os.Stat(path)
	if err != nil {
		return zero, "", err
	}
	if info.IsDir() {
		return zero, "", fmt.Errorf("%s is a directory — point at the binary file itself", path)
	}
	abs, err := filepath.Abs(path)
	if err == nil {
		path = abs
	}
	if isAndroidPackage(path) {
		// A zip, so archdetect would call it a raw image and send it down the
		// firmware path. APKs go to JADX instead of Ghidra.
		meta, err := decompileAPKLocally(ctx, path, info.Size(), logf)
		return meta, "", err
	}

	logf("Hashing %s (%.1f MB)…", filepath.Base(path), float64(info.Size())/(1024*1024))
	sha, err := sha256FileTUI(path)
	if err != nil {
		return zero, "", err
	}

	// Store hit with the same processor choice → free re-attach, no Ghidra run.
	if store.Has(sha) {
		if meta, err := store.Load(sha); err == nil && meta.Processor == processor {
			meta.SamplePath = path // refresh in-memory in case the file moved
			logf("Already decompiled locally — attaching from the store (no Ghidra run).")
			return *meta, "", nil
		}
	}

	guess := archdetect.Detect(path)
	logf("Format: %s", guess.Detail)
	loader := ""
	if guess.Format == "raw" {
		if processor == "" {
			// The whole point of arch handling: only bother the analyst when
			// detection fails. uImage header / embedded ELF / opcode census
			// first; manual pick is the last resort.
			logf("Raw image — scanning for architecture evidence (uImage · embedded ELF · opcodes)…")
			firm := archdetect.DetectFirmware(path)
			if firm.Processor != "" {
				processor = firm.Processor
				logf("Detected %s (%s confidence):", firm.Processor, firm.Confidence)
				for _, ev := range firm.Evidence {
					logf("  · %s", ev)
				}
				if firm.Confidence != "high" {
					logf("Heuristic guess — if the output is garbage, re-run: /decompile %s <processor>", path)
				}
			} else {
				hint := rawIdentify(ctx, path, logf)
				return zero, hint, fmt.Errorf("%s", archdetect.FirmFailureMessage(path))
			}
		}
		loader = "binary"
	}
	if processor != "" {
		logf("Forcing processor %s%s", processor, map[bool]string{true: " (raw-binary loader)", false: ""}[loader == "binary"])
	}

	blob, err := ghidra.Analyze(ctx, ghidra.Request{
		BinaryPath: path,
		Arch:       guess.Detail,
		Processor:  processor,
		Loader:     loader,
	}, logf)
	if err != nil {
		return zero, "", err
	}

	a, err := api.ParseAnalysis(blob)
	if err != nil {
		return zero, "", fmt.Errorf("worker returned an unusable analysis: %w", err)
	}
	meta := store.Meta{
		Sha256:     sha,
		Name:       filepath.Base(path),
		SamplePath: path,
		SizeBytes:  info.Size(),
		Language:   a.Metadata.Language,
		Format:     a.Metadata.ExecutableFormat,
		Processor:  processor,
	}
	if err := store.Save(meta, blob); err != nil {
		return zero, "", fmt.Errorf("decompile succeeded but saving locally failed: %w", err)
	}
	logf("Done: language=%s — %d functions, %d strings, %d imports. Stored locally (%s).",
		a.Metadata.Language, a.Metadata.FunctionCount, a.Metadata.StringCount, a.Metadata.ImportCount, sha[:12])
	return meta, "", nil
}

// rawIdentify best-effort runs file + binwalk in the extraction sandbox to give
// the analyst arch evidence for a raw image. Empty string when Docker/the
// sandbox image isn't available — the flow still works, just without the hints.
func rawIdentify(ctx context.Context, path string, logf ghidra.Logf) string {
	if err := sandbox.EnsureImage(ctx); err != nil {
		return ""
	}
	sb, err := sandbox.New(path, "")
	if err != nil {
		return ""
	}
	defer sb.Close()
	logf("Identifying the image with file + binwalk…")
	res, err := sb.Run(ctx, "file /sample; echo '---'; binwalk /sample 2>/dev/null | head -40", 5*time.Minute)
	if err != nil || res == nil {
		return ""
	}
	out := strings.TrimSpace(res.Stdout)
	if out == "" {
		return ""
	}
	return "file/binwalk evidence:\n" + out
}

// localProject synthesizes the api.Project a stored local analysis attaches as.
func localProject(meta store.Meta) *api.Project {
	if meta.Kind == store.KindAPK {
		return &api.Project{
			ID:               store.LocalID(meta.Sha256),
			Kind:             api.KindAPK,
			Name:             meta.Name,
			OriginalFilename: meta.Name,
			SizeBytes:        meta.SizeBytes,
			Sha256:           meta.Sha256,
			Status:           "READY",
			AnalysisMode:     "MALWARE",
			PackageName:      meta.PackageName,
			CreatedAt:        meta.CreatedAt,
		}
	}
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

// attachLocal points the session at a local analysis (project + sample path).
func (m *Model) attachLocal(meta store.Meta) {
	m.sess.Project = localProject(meta)
	m.sess.Sample = nil
	if _, err := os.Stat(meta.SamplePath); err == nil {
		m.sess.SamplePath = meta.SamplePath
	}
}

// --- screenDecompile (start-menu flow) --------------------------------------

// updateDecompile drives the path-entry / running / error stages.
func (m *Model) updateDecompile(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		if m.decompiling && m.decompCancel != nil {
			m.decompCancel()
			m.appendDecompLog("Canceling…")
			return m, nil
		}
		m.screen = screenStart
		return m, nil
	case "enter":
		if m.decompiling {
			return m, nil
		}
		val := strings.TrimSpace(m.decompInput.Value())
		if val == "" {
			return m, nil
		}
		path, processor := splitPathProcessor(val)
		m.decompLog = nil
		m.decompErr = ""
		m.appendDecompLog("Starting local decompile of " + path)
		return m, m.runDecompile(expandHome(path), processor)
	}
	if !m.decompiling {
		var cmd tea.Cmd
		m.decompInput, cmd = m.decompInput.Update(msg)
		return m, cmd
	}
	return m, nil
}

// splitPathProcessor separates "path [processor]" — the processor is the last
// field iff it looks like a Ghidra language ID (has two ':').
func splitPathProcessor(val string) (string, string) {
	fields := strings.Fields(val)
	if len(fields) >= 2 && strings.Count(fields[len(fields)-1], ":") >= 2 {
		return strings.Join(fields[:len(fields)-1], " "), fields[len(fields)-1]
	}
	return val, ""
}

func (m *Model) appendDecompLog(s string) {
	for _, l := range strings.Split(s, "\n") {
		m.decompLog = append(m.decompLog, l)
	}
	const keep = 200
	if len(m.decompLog) > keep {
		m.decompLog = m.decompLog[len(m.decompLog)-keep:]
	}
}

func (m *Model) viewDecompile() string {
	var b strings.Builder
	b.WriteString(banner() + "\n\n")
	b.WriteString(styleHeader.Render("Decompile a local binary or APK") + "\n")
	b.WriteString(styleDim.Render("Runs Ghidra (binaries) or JADX (.apk/.xapk) headless locally in Docker and keeps the result on this machine — no upload, no cloud cost.") + "\n\n")

	if m.decompiling {
		b.WriteString(m.spinner.View() + styleDim.Render(" decompiling… (Esc to cancel)") + "\n\n")
	} else {
		b.WriteString(styleDim.Render("Path to the binary or APK — add a Ghidra processor ID for raw firmware, e.g.") + "\n")
		b.WriteString(styleDim.Render("  ~/samples/router.bin ARM:LE:32:v7") + "\n\n")
		b.WriteString(m.decompInput.View() + "\n")
		b.WriteString(styleDim.Render("enter run · esc back") + "\n\n")
	}

	if m.decompErr != "" {
		b.WriteString(styleErr.Render(m.decompErr) + "\n\n")
	}
	// Show the tail of the log so the screen doesn't overflow.
	logLines := m.decompLog
	maxLines := m.height - lineCount(b.String()) - 4
	if maxLines < 5 {
		maxLines = 5
	}
	if len(logLines) > maxLines {
		logLines = logLines[len(logLines)-maxLines:]
	}
	for _, l := range logLines {
		b.WriteString(styleDim.Render("  "+truncate(l, max(20, m.width-4))) + "\n")
	}
	return b.String()
}

// handleDecompDone routes a finished background decompile for both entry points.
func (m *Model) handleDecompDone(msg decompDoneMsg) (tea.Model, tea.Cmd) {
	m.decompiling = false
	m.decompCancel = nil

	if m.screen == screenDecompile {
		if msg.err != nil {
			m.decompErr = msg.err.Error()
			if msg.hint != "" {
				m.appendDecompLog(msg.hint)
			}
			return m, nil
		}
		m.attachLocal(msg.meta)
		m.openAutonomy()
		return m, nil
	}

	// REPL-origin /decompile
	if msg.err != nil {
		m.append(errLine("Decompile failed: " + msg.err.Error()))
		if msg.hint != "" {
			m.append(sysLine(msg.hint))
		}
		return m, nil
	}
	m.attachLocal(msg.meta)
	if msg.meta.Kind == store.KindAPK {
		m.append(okLine(fmt.Sprintf("Attached local APK project %q (%s). The decompiled source is served from disk — tell me what to look for then /start (direct) or /investigate (autopilot). /upload also creates it as an OpenAPK project.",
			msg.meta.Name, orDefault(msg.meta.PackageName, "unknown package"))))
		return m, nil
	}
	m.append(okLine(fmt.Sprintf("Attached local project %q (%s). Analysis is served from disk — tell me what to look for then /start (direct) or /investigate (autopilot).",
		msg.meta.Name, orDefault(msg.meta.Language, "unknown language"))))
	return m, nil
}

// cmdDecompile is the REPL /decompile handler.
func (m *Model) cmdDecompile(rest string) tea.Cmd {
	rest = strings.TrimSpace(rest)
	if rest == "" {
		m.append(sysLine("Usage: /decompile <path> [ghidra-processor-id]   e.g. /decompile ~/fw.bin MIPS:BE:32:default  ·  /decompile ~/app.apk"))
		m.append(sysLine("Decompiles locally (Ghidra for binaries, JADX for .apk/.xapk; Docker) and keeps the result on disk — no upload, no cloud cost."))
		return nil
	}
	if m.decompiling {
		m.append(warnLine("A decompile is already running."))
		return nil
	}
	if m.engineStarted {
		m.append(errLine("A session is already running — for a wrong-arch re-decompile just ask BINNY (it has the decompile_sample tool). To analyze a NEW binary, /quit and relaunch, or finish this session first."))
		return nil
	}
	path, processor := splitPathProcessor(rest)
	m.append(sysLine("Starting local decompile of " + path + " …"))
	return m.runDecompile(expandHome(path), processor)
}

// cmdWorkspace shows or sets the extraction workspace (/work mount).
func (m *Model) cmdWorkspace(rest string) {
	rest = strings.TrimSpace(strings.Trim(rest, `"'`))
	if rest == "" {
		cur := m.sess.WorkspacePath
		if cur == "" {
			name := "default"
			if m.sess.SamplePath != "" {
				name = filepath.Base(m.sess.SamplePath)
			} else if m.sess.Project != nil {
				name = m.sess.Project.Name
			}
			if w, err := store.WorkspaceFor(name); err == nil {
				cur = w + "  (per-sample default)"
			}
		}
		m.append(sysLine("Workspace (mounted rw at /work in the sandbox — scripts have full access, artifacts persist):"))
		m.append(sysLine("  " + cur))
		m.append(sysLine("Point it anywhere with /workspace <path> (e.g. the folder holding your firmware)."))
		return
	}
	p := expandHome(rest)
	abs, err := filepath.Abs(p)
	if err == nil {
		p = abs
	}
	if err := os.MkdirAll(p, 0o755); err != nil {
		m.append(errLine("Can't use that workspace: " + err.Error()))
		return
	}
	m.sess.WorkspacePath = p
	m.append(okLine("Workspace → " + p + " (takes effect on the next extraction tool call)."))
}

func sha256FileTUI(path string) (string, error) {
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

// isAndroidPackage reports whether path is an APK-family file: by extension,
// or a zip carrying AndroidManifest.xml (a renamed or extensionless sample).
func isAndroidPackage(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".apk", ".xapk", ".apks", ".aab":
		return true
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		return false
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name == "AndroidManifest.xml" || f.Name == "base/manifest/AndroidManifest.xml" {
			return true
		}
	}
	return false
}

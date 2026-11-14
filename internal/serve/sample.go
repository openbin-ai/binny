package serve

// The raw sample. Analysis (Ghidra/JADX) is what the read tools serve, but
// extraction — running a decryptor, readelf, strings, binwalk — needs the
// original bytes. The desktop keeps the file the analyst opened and lets them
// attach one to a cloud project, then gives the chat agent the same sandbox
// tools the TUI has (write_file / run / read_artifact, plus decompile_sample
// on binaries), mounted read-only at /sample.
//
//	GET  /api/sample   {attached, name, size, path}
//	POST /api/sample   multipart "file" (copied into the local store), or
//	                   JSON {"path": "/abs/path"} (used in place, not copied)

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"openbin.ai/binny/internal/agent"
	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/store"
	"openbin.ai/binny/internal/tools"
)

// hasTarget reports whether anything is open to attach a sample to.
func (s *server) hasTarget() bool {
	return s.reg() != nil || s.dir() != ""
}

// samplePath returns the attached raw sample's host path ("" = none).
func (s *server) samplePath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.curSample
}

// setSample attaches (or, with "", detaches) the raw sample for the open
// target. The sample tools are rebuilt on next use so they see the new path.
func (s *server) setSample(path string) {
	s.mu.Lock()
	s.curSample = path
	s.curXReg = nil
	s.mu.Unlock()
}

// setTargetProject records the project behind the open target, so the sample
// tools know its kind/name (decompile_sample is BIN-only; the extraction
// workspace is named after it).
func (s *server) setTargetProject(p *api.Project) {
	s.mu.Lock()
	s.curProj = p
	s.curXReg = nil
	s.mu.Unlock()
}

// sampleTools returns the raw-sample toolset for the open target (nil when
// nothing is open). Built lazily and cached until the target or sample changes.
// The tools exist even with no sample attached: they then fail with a message
// telling the agent to ask for one, rather than the capability being invisible.
func (s *server) sampleTools() *tools.Registry {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.curReg == nil && s.curDir == "" && s.opts.Dir == "" {
		return nil
	}
	if s.curXReg == nil {
		proj := s.curProj
		if proj == nil {
			kind := api.KindAPK
			if s.curReg != nil {
				kind = api.KindBIN
			}
			proj = &api.Project{ID: s.curPID, Name: s.curPName, Kind: kind}
		}
		reg := tools.NewRegistry()
		agent.RegisterSampleTooling(reg, &app.Session{Project: proj, SamplePath: s.curSample}, s.curTB,
			func(format string, args ...any) {
				line := fmt.Sprintf(format, args...)
				log.Printf("decompile_sample: %s", line)
				s.emitProgress(line) // keep the chat's SSE stream alive during the minutes-long run
			})
		s.curXReg = reg
	}
	return s.curXReg
}

// keepSample copies an uploaded file into the local store (the upload itself
// lives in a temp dir that is removed when the request ends) and attaches it.
// Failure is not fatal to the caller — the analysis still works without it.
func (s *server) keepSample(sha, name, tmpPath string) (string, error) {
	if sha == "" {
		var err error
		if sha, err = fileSHA(tmpPath); err != nil {
			return "", err
		}
	}
	p, err := store.SaveSample(sha, name, tmpPath)
	if err != nil {
		return "", err
	}
	s.setSample(p)
	return p, nil
}

func (s *server) sampleStatus() map[string]any {
	p := s.samplePath()
	if p == "" {
		return map[string]any{"attached": false}
	}
	out := map[string]any{"attached": true, "name": filepath.Base(p), "path": p}
	if info, err := os.Stat(p); err == nil {
		out["size"] = info.Size()
	}
	return out
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

func (s *server) handleSample(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, s.sampleStatus())
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "GET or POST")
		return
	}
	if !s.hasTarget() {
		writeErr(w, http.StatusConflict, "nothing is open yet — use Open to analyze the file, or open a project from Cloud, then attach its sample")
		return
	}

	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var in struct {
			Path string `json:"path"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "bad JSON: "+err.Error())
			return
		}
		path := expandHome(strings.Trim(strings.TrimSpace(in.Path), `"'`))
		if path == "" {
			writeErr(w, http.StatusBadRequest, "missing path")
			return
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		info, err := os.Stat(abs)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "can't attach sample: "+err.Error())
			return
		}
		if info.IsDir() {
			writeErr(w, http.StatusBadRequest, "that's a directory — point at the raw binary file itself")
			return
		}
		s.setSample(abs)
		writeJSON(w, http.StatusOK, s.sampleStatus())
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	file, hdr, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "expected a 'file' upload or JSON {path}: "+err.Error())
		return
	}
	defer file.Close()
	tmp, err := os.CreateTemp("", "binny-sample-*")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer os.Remove(tmp.Name())
	_, err = io.Copy(tmp, file)
	tmp.Close()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "saving upload: "+err.Error())
		return
	}
	if _, err := s.keepSample("", hdr.Filename, tmp.Name()); err != nil {
		writeErr(w, http.StatusInternalServerError, "storing sample: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.sampleStatus())
}

// sampleContext tells the agent whether the raw bytes are reachable and, if
// not, how the analyst attaches them in THIS app. Without it the model had no
// idea a sample could be attached and sent analysts hunting for a control that
// didn't exist.
func (s *server) sampleContext() string {
	if !s.hasTarget() {
		return ""
	}
	if p := s.samplePath(); p != "" {
		return fmt.Sprintf(" RAW SAMPLE: attached (%s). `run` executes static tooling (readelf, objdump, strings, xxd, python3, radare2, binwalk) against it at /sample in a no-network sandbox — the sample is data to read, never executed; write_file/read_artifact use the /work workspace. Use these when the analysis is missing something (strings, .rodata, an encrypted config) instead of saying it is unavailable.", filepath.Base(p))
	}
	return " RAW SAMPLE: NOT attached, so run/write_file/read_artifact (and decompile_sample) fail until it is. You cannot open host paths yourself. When you need the raw bytes, ask the analyst to attach the file with the \"Attach sample\" button in the top bar, or by typing `/sample <path>` in the chat box (the app attaches it directly; a path mentioned in an ordinary message does nothing). Once attached, continue without asking again."
}

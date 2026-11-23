// Package resume persists an in-progress BINNY session to disk so an interrupt
// or crash can pick up where it left off: the engine conversation + investigation
// (via agent.EngineState), the session context, and the visual transcript.
package resume

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"openbin.ai/binny/internal/agent"
	"openbin.ai/binny/internal/config"
)

const stateVersion = 1

// maxTranscript caps how many scrollback lines are persisted (the engine
// messages are the source of truth; this is just visual continuity).
const maxTranscript = 400

// Line is one persisted transcript entry (role is the tui's role enum as int).
type Line struct {
	Role  int    `json:"role"`
	Text  string `json:"text"`
	Agent string `json:"agent,omitempty"` // crew member the line belongs to
}

// State is the full resume payload for one project.
type State struct {
	Version       int               `json:"version"`
	SavedAt       string            `json:"savedAt"`
	ProjectID     string            `json:"projectID"`
	ProjectName   string            `json:"projectName"`
	Mode          string            `json:"mode"`
	Autonomy      string            `json:"autonomy"`
	ProviderID    string            `json:"providerID"`
	Model         string            `json:"model"`
	Intel         string            `json:"intel,omitempty"`
	SamplePath    string            `json:"samplePath,omitempty"`
	Engine        agent.EngineState `json:"engine"`
	Transcript    []Line            `json:"transcript,omitempty"`
	EngineStarted bool              `json:"engineStarted"`
	Awaiting      bool              `json:"awaiting,omitempty"`
	ReviewIdle    bool              `json:"reviewIdle,omitempty"`
	Checkpoint    bool              `json:"checkpoint,omitempty"`
	CapPaused     bool              `json:"capPaused,omitempty"`
}

// Save writes the session state atomically (stamping version + savedAt).
func Save(s State) error {
	path, err := config.SessionPath(s.ProjectID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	s.Version = stateVersion
	s.SavedAt = time.Now().UTC().Format(time.RFC3339)
	if len(s.Transcript) > maxTranscript {
		s.Transcript = s.Transcript[len(s.Transcript)-maxTranscript:]
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path) // atomic replace
}

// Load reads a project's saved session. The bool is false when none exists.
func Load(projectID string) (*State, bool, error) {
	path, err := config.SessionPath(projectID)
	if err != nil {
		return nil, false, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, false, err
	}
	return &s, true, nil
}

// Exists reports whether a saved session file is present for a project.
func Exists(projectID string) bool {
	path, err := config.SessionPath(projectID)
	if err != nil {
		return false
	}
	_, err = os.Stat(path)
	return err == nil
}

// Delete removes a project's saved session (used on "start fresh").
func Delete(projectID string) error {
	path, err := config.SessionPath(projectID)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

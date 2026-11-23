// Package experience is the crew's opt-in memory of METHOD across runs.
//
// A note records how to approach a kind of target — "in WiFi drivers the
// ioctl handler is the attacker-reachable entry; trace from there" — never
// what a particular sample turned out to be. Remembered conclusions would let
// the crew find what it expects, which breaks evidence-grounding. So notes
// are scoped to a target type, injected into a matching role's tasking as
// hints only, saved only when the analyst picks them, and kept reviewable.
package experience

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"openbin.ai/binny/internal/config"
)

// Note is one lesson.
type Note struct {
	ID string `json:"id"`
	// TargetType is the human key the note is filed under ("ransomware · BIN").
	TargetType string `json:"targetType"`
	// Kind / Mode / Types are what the note is matched on. A note never fires
	// on a different project kind or analysis mode; Types (STIX malware
	// types) narrows it further when set.
	Kind  string   `json:"kind,omitempty"`
	Mode  string   `json:"mode,omitempty"`
	Types []string `json:"types,omitempty"`
	// Role is the crew member the lesson is for ("" = any).
	Role    string `json:"role,omitempty"`
	Lesson  string `json:"lesson"`
	FromRun string `json:"fromRun,omitempty"` // the project the lesson came out of
	Created string `json:"created,omitempty"`
}

// Target describes the run a note is matched against.
type Target struct {
	Kind  string   // BIN | APK | SCRIPT
	Mode  string   // MALWARE | VULN_RESEARCH
	Types []string // STIX malware types from triage (empty in vuln mode)
}

// Label is the target type a note from this run is filed under.
func (t Target) Label() string {
	what := "vuln research"
	if !strings.Contains(strings.ToUpper(t.Mode), "VULN") {
		what = "malware"
		if len(t.Types) > 0 {
			ts := append([]string(nil), t.Types...)
			sort.Strings(ts)
			what = strings.Join(ts, "+")
		}
	}
	return what + " · " + t.Kind
}

// Applies reports whether the note is in scope for a run and a role.
func (n Note) Applies(t Target, role string) bool {
	if n.Kind != "" && !strings.EqualFold(n.Kind, t.Kind) {
		return false
	}
	if n.Mode != "" && !strings.EqualFold(n.Mode, t.Mode) {
		return false
	}
	if n.Role != "" && role != "" && !strings.EqualFold(n.Role, role) {
		return false
	}
	if len(n.Types) == 0 {
		return true
	}
	for _, a := range n.Types {
		for _, b := range t.Types {
			if strings.EqualFold(a, b) {
				return true
			}
		}
	}
	return false
}

// Match returns the notes in scope for a run and role.
func Match(notes []Note, t Target, role string) []Note {
	var out []Note
	for _, n := range notes {
		if n.Applies(t, role) {
			out = append(out, n)
		}
	}
	return out
}

var (
	reIP     = regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b`)
	reURL    = regexp.MustCompile(`(?i)\b(https?|ftp|tcp|udp)://`)
	reHash   = regexp.MustCompile(`\b[a-fA-F0-9]{32,64}\b`)
	reDomain = regexp.MustCompile(`(?i)\b[a-z0-9-]+(\.[a-z0-9-]+)*\.(com|net|org|ru|cn|io|xyz|top|info|biz|onion|su|cc|tk)\b`)
	reAddr   = regexp.MustCompile(`(?i)\b(0x[0-9a-f]{5,}|FUN_[0-9a-f]{4,}|sub_[0-9a-f]{4,})\b`)
	reClaim  = regexp.MustCompile(`(?i)\b(this|the) (sample|binary|file|apk|driver|app|package) (is|was|contains|connects|beacons|uses)\b|\bis (malicious|benign|ransomware|a trojan|a backdoor)\b|\bthe c2 (is|was)\b`)
)

// LooksLikeConclusion reports whether a lesson reads as a finding about one
// sample rather than a method: it names an indicator (IP, URL, domain, hash),
// a sample-specific address, or asserts what "this sample" is. Such a lesson
// is refused — carried into the next run it would be a planted conclusion.
func LooksLikeConclusion(lesson string) (bool, string) {
	switch {
	case reURL.MatchString(lesson), reIP.MatchString(lesson), reDomain.MatchString(lesson):
		return true, "it names a network indicator"
	case reHash.MatchString(lesson):
		return true, "it contains a hash"
	case reAddr.MatchString(lesson):
		return true, "it cites an address or auto-named function from one binary"
	case reClaim.MatchString(lesson):
		return true, "it states a conclusion about a sample"
	}
	return false, ""
}

// Clean validates a lesson for saving and returns it trimmed.
func Clean(lesson string) (string, error) {
	lesson = strings.Join(strings.Fields(lesson), " ")
	if len(lesson) < 12 {
		return "", errors.New("a lesson needs to say something a crew member can act on")
	}
	if len(lesson) > 400 {
		return "", errors.New("keep a lesson under 400 characters — one method, plainly")
	}
	if bad, why := LooksLikeConclusion(lesson); bad {
		return "", fmt.Errorf("refused: %s. Experience keeps METHOD (where to look, how to approach), never conclusions about a sample", why)
	}
	return lesson, nil
}

func fileFor(targetType string) (string, error) {
	dir, err := config.ExperienceDir()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(targetType) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	name := strings.TrimRight(b.String(), "-")
	if name == "" {
		name = "general"
	}
	return filepath.Join(dir, name+".json"), nil
}

func readFile(path string) ([]Note, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var notes []Note
	if err := json.Unmarshal(data, &notes); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return notes, nil
}

func writeFile(path string, notes []Note) error {
	if len(notes) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(notes, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// All returns every saved note, grouped by target type then oldest first. A
// file that doesn't parse is skipped rather than hiding the rest.
func All() []Note {
	dir, err := config.ExperienceDir()
	if err != nil {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []Note
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		notes, err := readFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		out = append(out, notes...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].TargetType != out[j].TargetType {
			return out[i].TargetType < out[j].TargetType
		}
		return out[i].Created < out[j].Created
	})
	return out
}

// Add saves a note the analyst chose to keep. The lesson is validated
// (method, not conclusion) and an exact duplicate for the same target type is
// not saved twice.
func Add(n Note) (Note, error) {
	lesson, err := Clean(n.Lesson)
	if err != nil {
		return Note{}, err
	}
	n.Lesson = lesson
	if strings.TrimSpace(n.TargetType) == "" {
		n.TargetType = "general"
	}
	path, err := fileFor(n.TargetType)
	if err != nil {
		return Note{}, err
	}
	notes, err := readFile(path)
	if err != nil {
		return Note{}, err
	}
	for _, old := range notes {
		if strings.EqualFold(old.Lesson, n.Lesson) && strings.EqualFold(old.Role, n.Role) {
			return old, nil
		}
	}
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return Note{}, err
	}
	n.ID = hex.EncodeToString(buf)
	n.Created = time.Now().UTC().Format(time.RFC3339)
	if err := writeFile(path, append(notes, n)); err != nil {
		return Note{}, err
	}
	return n, nil
}

// find locates a note by id (a unique prefix is enough).
func find(id string) (path string, notes []Note, idx int, err error) {
	id = strings.ToLower(strings.TrimSpace(id))
	if id == "" {
		return "", nil, 0, errors.New("which note? give its id")
	}
	dir, err := config.ExperienceDir()
	if err != nil {
		return "", nil, 0, err
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		ns, rerr := readFile(p)
		if rerr != nil {
			continue
		}
		for i, n := range ns {
			if strings.HasPrefix(n.ID, id) {
				return p, ns, i, nil
			}
		}
	}
	return "", nil, 0, fmt.Errorf("no experience note %q", id)
}

// Update rewrites a note's lesson.
func Update(id, lesson string) (Note, error) {
	lesson, err := Clean(lesson)
	if err != nil {
		return Note{}, err
	}
	path, notes, i, err := find(id)
	if err != nil {
		return Note{}, err
	}
	notes[i].Lesson = lesson
	return notes[i], writeFile(path, notes)
}

// Delete prunes a note.
func Delete(id string) error {
	path, notes, i, err := find(id)
	if err != nil {
		return err
	}
	return writeFile(path, append(notes[:i], notes[i+1:]...))
}

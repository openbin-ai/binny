// Package store is BINNY's local analysis store: decompiled-analysis JSON kept
// on disk so repeat sessions never re-decompile and never re-fetch the blob
// from the backend/CloudFront (zero AWS cost after the first time).
//
// Layout under $XDG_DATA_HOME/binny/ (~/.local/share/binny/):
//
//	analyses/<sha256>/analysis.json.gz  — raw worker JSON, gzipped (BIN)
//	analyses/<sha256>/tree.tar.gz       — JADX output as returned by the worker (APK)
//	analyses/<sha256>/src/              — that tree, extracted (APK)
//	analyses/<sha256>/meta.json         — Meta (name, sample path, language…)
//	analyses/<sha256>/report.md         — /save target for local projects
//	analyses/remote/<projectID>.json.gz — read-through cache of backend blobs
//	analyses/remote-trees/<projectID>/  — cached source tree of a backend APK project (src/ + etag)
//	workspaces/<name>/                  — persistent extraction workspaces
package store

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Meta describes one locally-decompiled sample.
type Meta struct {
	Sha256     string `json:"sha256"`
	Kind       string `json:"kind,omitempty"` // "APK" for a JADX tree; "" = BIN (Ghidra analysis)
	Name       string `json:"name"`
	SamplePath string `json:"samplePath"`
	SizeBytes  int64  `json:"sizeBytes"`
	Language   string `json:"language,omitempty"`  // Ghidra language ID the worker reported
	Format     string `json:"format,omitempty"`    // executable format the worker reported
	Processor  string `json:"processor,omitempty"` // forced processor, if any
	CreatedAt  string `json:"createdAt"`

	PackageName string `json:"packageName,omitempty"` // APK: manifest package
	ProjectID   string `json:"projectId,omitempty"`   // APK: OpenAPK project after /upload
}

// KindAPK is Meta.Kind for a locally JADX-decompiled APK.
const KindAPK = "APK"

// LocalIDPrefix marks synthesized local-project IDs ("local:<sha12>").
const LocalIDPrefix = "local:"

// LocalID renders the synthetic project id for a sample hash.
func LocalID(sha string) string {
	if len(sha) > 12 {
		sha = sha[:12]
	}
	return LocalIDPrefix + sha
}

// Root returns the store root (~/.local/share/binny), honoring XDG_DATA_HOME.
func Root() (string, error) {
	if v := os.Getenv("XDG_DATA_HOME"); v != "" {
		return filepath.Join(v, "binny"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home dir: %w", err)
	}
	return filepath.Join(home, ".local", "share", "binny"), nil
}

func analysisDir(sha string) (string, error) {
	root, err := Root()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "analyses", sanitize(sha)), nil
}

// Save persists a decompile result + metadata for a sample hash.
func Save(meta Meta, blob []byte) error {
	dir, err := analysisDir(meta.Sha256)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if meta.CreatedAt == "" {
		meta.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if err := writeGz(filepath.Join(dir, "analysis.json.gz"), blob); err != nil {
		return err
	}
	mj, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "meta.json"), mj, 0o644)
}

// SaveMeta writes (or rewrites) a sample's metadata on its own — the APK path,
// where the payload is a tree on disk rather than a blob.
func SaveMeta(meta Meta) error {
	dir, err := analysisDir(meta.Sha256)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if meta.CreatedAt == "" {
		meta.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	mj, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "meta.json"), mj, 0o644)
}

// TreeTarball is where an APK's JADX tarball is kept (the exact bytes the
// backend accepts on upload, so /upload never re-decompiles).
func TreeTarball(sha string) (string, error) {
	dir, err := analysisDir(sha)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "tree.tar.gz"), nil
}

// SrcDir is where an APK's JADX tree is extracted.
func SrcDir(sha string) (string, error) {
	dir, err := analysisDir(sha)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "src"), nil
}

// HasTree reports whether a sample hash has an extracted APK tree.
func HasTree(sha string) bool {
	src, err := SrcDir(sha)
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(src, "sources"))
	return err == nil
}

// Has reports whether a sample hash has a stored analysis.
func Has(sha string) bool {
	dir, err := analysisDir(sha)
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(dir, "analysis.json.gz"))
	return err == nil
}

// Blob loads the stored raw worker JSON for a sample hash.
func Blob(sha string) ([]byte, error) {
	dir, err := analysisDir(sha)
	if err != nil {
		return nil, err
	}
	return readGz(filepath.Join(dir, "analysis.json.gz"))
}

// Load reads a sample's metadata.
func Load(sha string) (*Meta, error) {
	dir, err := analysisDir(sha)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return nil, err
	}
	var m Meta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// List returns all locally stored analyses, newest first.
func List() []Meta {
	root, err := Root()
	if err != nil {
		return nil
	}
	entries, err := os.ReadDir(filepath.Join(root, "analyses"))
	if err != nil {
		return nil
	}
	var out []Meta
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "remote" {
			continue
		}
		if m, err := Load(e.Name()); err == nil {
			out = append(out, *m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

// ReportPath returns where /save writes a local project's report markdown.
func ReportPath(sha string) (string, error) {
	dir, err := analysisDir(sha)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, "report.md"), nil
}

// --- read-through cache for BACKEND analysis blobs -------------------------

func remotePath(projectID string) (string, error) {
	root, err := Root()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "analyses", "remote", sanitize(projectID)+".json.gz"), nil
}

// RemoteBlob returns a cached backend analysis blob, or nil on miss.
func RemoteBlob(projectID string) []byte {
	p, err := remotePath(projectID)
	if err != nil {
		return nil
	}
	b, err := readGz(p)
	if err != nil {
		return nil
	}
	return b
}

// SaveRemote caches a backend analysis blob (best-effort; a failed cache write
// must never fail the session).
func SaveRemote(projectID string, blob []byte) {
	p, err := remotePath(projectID)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return
	}
	_ = writeGz(p, blob)
}

// DropRemote evicts a cached backend blob (used by /refresh after a re-run).
func DropRemote(projectID string) {
	if p, err := remotePath(projectID); err == nil {
		_ = os.Remove(p)
	}
}

// --- cached source trees of BACKEND APK projects -----------------------------

// RemoteTreeDir is where a backend APK project's source bundle is cached:
// <dir>/src is the extracted tree, <dir>/etag the bundle's S3 ETag.
func RemoteTreeDir(projectID string) (string, error) {
	root, err := Root()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "analyses", "remote-trees", sanitize(projectID)), nil
}

// RemoteTreeETag returns the ETag of the cached bundle, "" when there is no
// complete cached tree.
func RemoteTreeETag(projectID string) string {
	dir, err := RemoteTreeDir(projectID)
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(dir, "etag"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// SetRemoteTreeETag marks the cached tree complete for a bundle ETag. Written
// last, after extraction, so a crash mid-extract never looks cached.
func SetRemoteTreeETag(projectID, etag string) error {
	dir, err := RemoteTreeDir(projectID)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "etag"), []byte(etag+"\n"), 0o644)
}

// DropRemoteTree evicts a cached tree (stale ETag, /refresh).
func DropRemoteTree(projectID string) {
	if dir, err := RemoteTreeDir(projectID); err == nil {
		_ = os.RemoveAll(dir)
	}
}

// --- workspaces -------------------------------------------------------------

// WorkspaceFor returns the default persistent extraction workspace for a
// sample, creating it: ~/.local/share/binny/workspaces/<sanitized-name>.
func WorkspaceFor(name string) (string, error) {
	root, err := Root()
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(name) == "" {
		name = "default"
	}
	dir := filepath.Join(root, "workspaces", sanitize(name))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// --- helpers ----------------------------------------------------------------

func sanitize(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "x"
	}
	return b.String()
}

func writeGz(path string, data []byte) error {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	tmp := path + ".part"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readGz(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(zr)
}

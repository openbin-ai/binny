package tools

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/jadx"
	"openbin.ai/binny/internal/store"
)

// A backend APK project's reads are served from a local copy of its source
// tree: the bundle is downloaded from S3 once (the same presigned src.tar.gz
// the OpenAPK web app's local mode uses), cached on disk keyed by its ETag,
// and every list/read/search/manifest/definition/usage call after that costs
// the backend nothing. Writes — highlights, the report on /save — still go to
// the API. Any failure falls back to the server-side endpoints.

// cachedRemoteSource returns the project's tree served from the local cache,
// downloading the bundle first when there's no copy or the copy is stale.
// One cheap API call per session (the presign) decides freshness; when the
// backend is unreachable, an existing copy is used as-is.
func cachedRemoteSource(client *api.Client, projectID string, logf func(string, ...any)) (sourceTree, error) {
	// The TUI prefetch and the agent's first tool call can race for the same
	// project; one download at a time, and the loser finds the fresh copy.
	cacheMu.Lock()
	defer cacheMu.Unlock()
	dir, err := store.RemoteTreeDir(projectID)
	if err != nil {
		return nil, err
	}
	src := filepath.Join(dir, "src")
	cached := store.RemoteTreeETag(projectID)

	bundle, err := client.SourceBundle(projectID)
	switch {
	case err != nil && cached != "":
		logf("Backend unreachable for a freshness check (%v) — using the cached source tree.", err)
	case err != nil:
		return nil, fmt.Errorf("no source bundle: %w", err)
	case bundleKey(bundle) == cached:
		logf("Source tree cached locally — reads are served from disk.")
	default:
		if cached != "" {
			logf("Project changed since the cached copy — refreshing the source tree.")
		}
		if err := downloadBundle(client, projectID, bundle, dir, src, logf); err != nil {
			return nil, err
		}
	}

	renames := map[string]string{}
	if list, err := client.Renames(projectID); err == nil {
		for _, r := range list {
			if r.Status == "APPLIED" && r.Original != "" && r.Suggested != "" {
				renames[r.Original] = r.Suggested
			}
		}
	}
	return newRenamedSource(newLocalSource(src), renames), nil
}

var cacheMu sync.Mutex

// PrefetchSourceTree downloads (or freshness-checks) a backend APK project's
// source tree into the local cache, so the agent's first read is instant.
// The TUI runs it in the background right after a project is picked.
func PrefetchSourceTree(client *api.Client, projectID string, logf func(string, ...any)) error {
	_, err := cachedRemoteSource(client, projectID, logf)
	return err
}

// bundleKey identifies a bundle version: its ETag, or its size when S3 didn't
// give one (better than trusting any cached copy forever).
func bundleKey(b *api.SourceBundle) string {
	if b.ETag != "" {
		return b.ETag
	}
	return fmt.Sprintf("size:%d", b.CompressedBytes)
}

func downloadBundle(client *api.Client, projectID string, b *api.SourceBundle, dir, src string, logf func(string, ...any)) error {
	store.DropRemoteTree(projectID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "bundle.tar.gz")
	logf("Downloading the decompiled source once (%.1f MB) — every read after this is local…", float64(b.CompressedBytes)/(1<<20))
	if err := client.Download(b.URL, tmp); err != nil {
		store.DropRemoteTree(projectID)
		return fmt.Errorf("download source bundle: %w", err)
	}
	defer os.Remove(tmp)
	n, err := jadx.Extract(tmp, src)
	if err != nil {
		store.DropRemoteTree(projectID)
		return fmt.Errorf("unpack source bundle: %w", err)
	}
	if err := store.SetRemoteTreeETag(projectID, bundleKey(b)); err != nil {
		return err
	}
	logf("Cached %d source files locally.", n)
	return nil
}

// renamedSource is a local tree with the project's applied renames
// substituted into file reads — what the backend's /file endpoint returns
// (RenameService.applyMapToContent: whole-word, project-wide).
type renamedSource struct {
	*localSource
	renames []renameRule
}

type renameRule struct {
	re  *regexp.Regexp
	new string
}

func newRenamedSource(l *localSource, renames map[string]string) *renamedSource {
	rs := &renamedSource{localSource: l}
	for orig, repl := range renames {
		rs.renames = append(rs.renames, renameRule{re: regexp.MustCompile(`\b` + regexp.QuoteMeta(orig) + `\b`), new: repl})
	}
	return rs
}

func (r *renamedSource) File(path string) (*api.FileContent, error) {
	fc, err := r.localSource.File(path)
	if err != nil || fc.Encoding == "binary" || len(r.renames) == 0 {
		return fc, err
	}
	for _, rule := range r.renames {
		fc.Content = rule.re.ReplaceAllLiteralString(fc.Content, rule.new)
	}
	return fc, nil
}

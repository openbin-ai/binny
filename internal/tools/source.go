package tools

import (
	"fmt"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/store"
)

// sourceTree is a decompiled APK/script source tree — what list_files,
// read_file, search, get_manifest, find_definition and find_usages read.
// A backend project serves it over the API; a locally JADX-decompiled APK
// serves the same answers from the tree on disk, so every tool behaves the
// same either way.
type sourceTree interface {
	Tree() (*api.FileNode, error)
	File(path string) (*api.FileContent, error)
	Search(regex string, includeSdks bool, limit int) ([]api.SearchHit, error)
	Manifest() (*api.Manifest, error)
	Definitions(name string, includeSdks bool) ([]api.JavaSymbol, error)
	Usages(name, className string, includeSdks bool) ([]api.SymbolUsage, error)
}

// remoteSource is a backend project's tree, via the existing endpoints.
type remoteSource struct {
	api *api.Client
	id  string
}

func (r remoteSource) Tree() (*api.FileNode, error) { return r.api.FileTree(r.id) }
func (r remoteSource) File(path string) (*api.FileContent, error) {
	return r.api.FileContent(r.id, path)
}
func (r remoteSource) Search(regex string, includeSdks bool, limit int) ([]api.SearchHit, error) {
	return r.api.SearchCode(r.id, regex, true, false, includeSdks, limit)
}
func (r remoteSource) Manifest() (*api.Manifest, error) { return r.api.Manifest(r.id) }
func (r remoteSource) Definitions(name string, includeSdks bool) ([]api.JavaSymbol, error) {
	return r.api.SymbolDefinition(r.id, name, includeSdks)
}
func (r remoteSource) Usages(name, className string, includeSdks bool) ([]api.SymbolUsage, error) {
	return r.api.SymbolUsages(r.id, name, className, includeSdks)
}

// source resolves (once) where this project's tree lives.
func (tb *Toolbox) source() (sourceTree, error) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if tb.src != nil {
		return tb.src, nil
	}
	p := tb.Project
	switch {
	case !p.IsLocal() && p.Kind == api.KindAPK && tb.API != nil:
		// Pull the tree once and read it locally; the server endpoints are
		// only the fallback (no bundle / download failed).
		if s, err := cachedRemoteSource(tb.API, p.ID, tb.progress()); err == nil {
			tb.src = s
		} else {
			tb.progress()("Reading the source tree through the backend (%v).", err)
			tb.src = remoteSource{api: tb.API, id: p.ID}
		}
	case !p.IsLocal():
		tb.src = remoteSource{api: tb.API, id: p.ID}
	case p.Kind == api.KindAPK:
		dir, err := store.SrcDir(p.Sha256)
		if err != nil {
			return nil, err
		}
		if !store.HasTree(p.Sha256) {
			return nil, fmt.Errorf("local APK tree missing for %s (was the store dir deleted?) — re-run /decompile", p.Name)
		}
		tb.src = newLocalSource(dir)
	default:
		return nil, fmt.Errorf("local binary project — there is no source tree; use the sandbox (`run` in /work) for workspace files")
	}
	return tb.src, nil
}

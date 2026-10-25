package tools

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"openbin.ai/binny/internal/api"
)

// localSource serves a JADX tree extracted on disk (a locally decompiled APK).
// It ports the backend's behavior — SearchService, ManifestService, the
// SymbolService declaration regexes and usage grep — so an offline session
// sees the same answers an OpenAPK project would give.
type localSource struct {
	root string

	once    sync.Once
	symbols []api.JavaSymbol
}

func newLocalSource(root string) *localSource { return &localSource{root: root} }

// Limits mirror the backend's (SearchService / SymbolService).
const (
	localMaxFileBytes = 1 << 20 // skip bigger files in search / symbol scans
	localMaxFiles     = 20000
	localMaxUsages    = 500
	localSnippetMax   = 240
	localMaxReadBytes = 4 << 20 // read_file serves at most this much of one file
)

func (l *localSource) Tree() (*api.FileNode, error) { return buildTree(l.root) }

// buildTree builds the nested tree in two passes (collect, then nest by
// path) so no pointer into a growing slice is ever kept.
func buildTree(rootDir string) (*api.FileNode, error) {
	type item struct {
		rel   string
		isDir bool
		size  int64
	}
	var items []item
	err := filepath.WalkDir(rootDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == rootDir {
			return err
		}
		it := item{rel: filepath.ToSlash(mustRel(rootDir, p)), isDir: d.IsDir()}
		if !d.IsDir() {
			if info, err := d.Info(); err == nil {
				it.size = info.Size()
			}
		}
		items = append(items, it)
		return nil
	})
	if err != nil {
		return nil, err
	}
	children := map[string][]item{}
	for _, it := range items {
		parent := ""
		if i := strings.LastIndexByte(it.rel, '/'); i >= 0 {
			parent = it.rel[:i]
		}
		children[parent] = append(children[parent], it)
	}
	var build func(rel, name string) api.FileNode
	build = func(rel, name string) api.FileNode {
		n := api.FileNode{Name: name, Path: rel, Type: "dir"}
		kids := children[rel]
		sort.Slice(kids, func(i, j int) bool {
			if kids[i].isDir != kids[j].isDir {
				return kids[i].isDir
			}
			return kids[i].rel < kids[j].rel
		})
		for _, k := range kids {
			base := k.rel[strings.LastIndexByte(k.rel, '/')+1:]
			if k.isDir {
				n.Children = append(n.Children, build(k.rel, base))
			} else {
				sz := k.size
				n.Children = append(n.Children, api.FileNode{Name: base, Path: k.rel, Type: "file", Size: &sz})
			}
		}
		return n
	}
	root := build("", "/")
	return &root, nil
}

// resolve maps a tool-supplied relative path to a file under root, refusing
// anything that escapes it.
func (l *localSource) resolve(rel string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(strings.TrimPrefix(rel, "/")))
	if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q is outside the project tree", rel)
	}
	return filepath.Join(l.root, clean), nil
}

func (l *localSource) File(rel string) (*api.FileContent, error) {
	p, err := l.resolve(rel)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file not found: %s (list_files to see the tree)", rel)
		}
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory — list_files dir=%s", rel, rel)
	}
	data, err := io.ReadAll(io.LimitReader(f, localMaxReadBytes))
	if err != nil {
		return nil, err
	}
	fc := &api.FileContent{Path: filepath.ToSlash(rel), Size: info.Size(), Truncated: info.Size() > localMaxReadBytes}
	if looksBinary(data) {
		fc.Encoding = "binary"
		return fc, nil
	}
	fc.Encoding = "utf-8"
	fc.Content = string(data)
	return fc, nil
}

func looksBinary(b []byte) bool {
	if len(b) > 8000 {
		b = b[:8000]
	}
	return bytes.IndexByte(b, 0) >= 0
}

// eachFile walks the tree's regular files (SDK paths skipped unless
// includeSdks, capped like the backend), handing fn the relative path and
// absolute path. fn returns false to stop.
func (l *localSource) eachFile(includeSdks bool, javaOnly bool, fn func(rel, abs string) bool) error {
	seen := 0
	stop := fmt.Errorf("stop")
	err := filepath.WalkDir(l.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry — skip, like the backend
		}
		if d.IsDir() {
			return nil
		}
		if javaOnly && !strings.HasSuffix(d.Name(), ".java") {
			return nil
		}
		rel := filepath.ToSlash(mustRel(l.root, p))
		if !includeSdks && isSdkPath(rel) {
			return nil
		}
		if seen >= localMaxFiles {
			return stop
		}
		seen++
		if info, err := d.Info(); err != nil || info.Size() > localMaxFileBytes {
			return nil
		}
		if !fn(rel, p) {
			return stop
		}
		return nil
	})
	if err == stop {
		return nil
	}
	return err
}

func (l *localSource) Search(pattern string, includeSdks bool, limit int) ([]api.SearchHit, error) {
	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return nil, fmt.Errorf("bad regex (RE2 syntax for local projects): %v", err)
	}
	var hits []api.SearchHit
	err = l.eachFile(includeSdks, false, func(rel, abs string) bool {
		data, err := os.ReadFile(abs)
		if err != nil || looksBinary(data) {
			return true
		}
		for i, line := range strings.Split(string(data), "\n") {
			if re.MatchString(line) {
				hits = append(hits, api.SearchHit{File: rel, Line: i + 1, Snippet: snippet(line)})
				if len(hits) >= limit {
					return false
				}
			}
		}
		return true
	})
	return hits, err
}

func snippet(line string) string {
	line = strings.TrimRight(line, "\r")
	if len(line) > localSnippetMax {
		return line[:localSnippetMax] + "…"
	}
	return line
}

// --- symbols (port of the backend SymbolService declaration scan) ----------

var (
	reClassDecl  = regexp.MustCompile(`^\s*(?:(?:public|private|protected|abstract|final|static|sealed|non-sealed)\s+)*(class|interface|enum)\s+(\w+)`)
	reMethodDecl = regexp.MustCompile(`^\s*(?:(?:public|private|protected|static|final|synchronized|abstract|native|default|strictfp)\s+)+([\w<>\[\]?,.\s$]+?)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws[^{;]*)?[{;]`)
	reCtorDecl   = regexp.MustCompile(`^\s*(?:(?:public|private|protected)\s+)+(\w+)\s*\(([^)]*)\)\s*(?:throws[^{]*)?\{`)
	reFieldDecl  = regexp.MustCompile(`^\s*(?:(?:public|private|protected|static|final|volatile|transient)\s+)+([\w<>\[\]?,.\s$]+?)\s+(\w+)\s*(?:=[^;]*)?;`)
	rePackage    = regexp.MustCompile(`^\s*package\s+([\w.]+)\s*;`)
	controlFlow  = map[string]bool{"if": true, "for": true, "while": true, "switch": true, "catch": true, "return": true, "new": true, "synchronized": true, "try": true, "do": true, "else": true}
)

// symbolIndex scans every .java file once (SDK code included — lookups filter
// it per call, like the backend's cached index).
func (l *localSource) symbolIndex() []api.JavaSymbol {
	l.once.Do(func() {
		_ = l.eachFile(true, true, func(rel, abs string) bool {
			if data, err := os.ReadFile(abs); err == nil {
				l.symbols = append(l.symbols, extractSymbols(string(data), rel)...)
			}
			return true
		})
	})
	return l.symbols
}

func extractSymbols(content, rel string) []api.JavaSymbol {
	lines := strings.Split(content, "\n")
	pkg := ""
	for _, line := range lines {
		if m := rePackage.FindStringSubmatch(line); m != nil {
			pkg = m[1]
			break
		}
	}
	current := strings.TrimSuffix(filepath.Base(rel), ".java")
	outerDepth, depth := -1, 0
	var out []api.JavaSymbol
	for i, line := range lines {
		n := i + 1
		if m := reClassDecl.FindStringSubmatch(line); m != nil {
			out = append(out, api.JavaSymbol{Kind: strings.ToUpper(m[1]), Name: m[2], ClassName: m[2], File: rel, Line: n,
				Modifiers: strings.TrimSpace(line[:strings.Index(line, m[1])]), Pkg: pkg})
			if outerDepth == -1 {
				current, outerDepth = m[2], depth
			}
		} else if m := reMethodDecl.FindStringSubmatch(line); m != nil && !controlFlow[m[2]] && m[2] != current {
			out = append(out, api.JavaSymbol{Kind: "METHOD", Name: m[2], ClassName: current, File: rel, Line: n,
				Signature: "(" + strings.TrimSpace(m[3]) + ")", Modifiers: strings.TrimSpace(m[1]), Pkg: pkg})
		} else if m := reCtorDecl.FindStringSubmatch(line); m != nil && m[1] == current {
			out = append(out, api.JavaSymbol{Kind: "CONSTRUCTOR", Name: m[1], ClassName: current, File: rel, Line: n,
				Signature: "(" + strings.TrimSpace(m[2]) + ")", Pkg: pkg})
		} else if m := reFieldDecl.FindStringSubmatch(line); m != nil && outerDepth >= 0 && depth == outerDepth+1 && !controlFlow[m[2]] {
			out = append(out, api.JavaSymbol{Kind: "FIELD", Name: m[2], ClassName: current, File: rel, Line: n,
				Signature: strings.TrimSpace(m[1]), Pkg: pkg})
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
	}
	return out
}

func (l *localSource) Definitions(name string, includeSdks bool) ([]api.JavaSymbol, error) {
	var out []api.JavaSymbol
	for _, s := range l.symbolIndex() {
		if s.Name == name && (includeSdks || !isSdkPath(s.File)) {
			out = append(out, s)
		}
	}
	return out, nil
}

func (l *localSource) Usages(name, className string, includeSdks bool) ([]api.SymbolUsage, error) {
	pat := `\b` + regexp.QuoteMeta(name) + `\b`
	if className != "" {
		// Code refers to a class by its simple name far more often than its
		// FQN; accept either qualifier.
		simple := className[strings.LastIndexByte(className, '.')+1:]
		pat = `\b(?:` + regexp.QuoteMeta(className) + `|` + regexp.QuoteMeta(simple) + `)\s*\.\s*` + regexp.QuoteMeta(name) + `\b`
	}
	re := regexp.MustCompile(pat)
	var out []api.SymbolUsage
	err := l.eachFile(includeSdks, true, func(rel, abs string) bool {
		data, err := os.ReadFile(abs)
		if err != nil {
			return true
		}
		for i, line := range strings.Split(string(data), "\n") {
			if re.MatchString(line) {
				out = append(out, api.SymbolUsage{File: rel, Line: i + 1, Snippet: snippet(strings.TrimSpace(line))})
				if len(out) >= localMaxUsages {
					return false
				}
			}
		}
		return true
	})
	return out, err
}

// --- manifest (port of the backend ManifestService) --------------------------

const androidNS = "http://schemas.android.com/apk/res/android"

type xmlNode struct {
	XMLName  xml.Name
	Attrs    []xml.Attr `xml:",any,attr"`
	Children []xmlNode  `xml:",any"`
}

// attr returns an attribute's value; android=true matches the android:
// namespace (by URI, or by the bare prefix when the xmlns is missing).
func (n xmlNode) attr(local string, android bool) string {
	for _, a := range n.Attrs {
		if a.Name.Local != local {
			continue
		}
		if !android && a.Name.Space == "" {
			return a.Value
		}
		if android && (a.Name.Space == androidNS || a.Name.Space == "android") {
			return a.Value
		}
	}
	return ""
}

func (n xmlNode) intAttr(local string) *int {
	v, err := strconv.Atoi(n.attr(local, true))
	if err != nil {
		return nil
	}
	return &v
}

func (n xmlNode) child(local string) *xmlNode {
	for i := range n.Children {
		if n.Children[i].XMLName.Local == local {
			return &n.Children[i]
		}
	}
	return nil
}

func (l *localSource) Manifest() (*api.Manifest, error) {
	data, err := os.ReadFile(filepath.Join(l.root, "resources", "AndroidManifest.xml"))
	if err != nil {
		return nil, fmt.Errorf("AndroidManifest.xml not found in the decompiled tree: %w", err)
	}
	var root xmlNode
	if err := xml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse AndroidManifest.xml: %w", err)
	}
	pkg := root.attr("package", false)
	m := &api.Manifest{
		PackageName: pkg,
		VersionCode: root.intAttr("versionCode"),
		VersionName: root.attr("versionName", true),
	}
	if sdk := root.child("uses-sdk"); sdk != nil {
		m.MinSdk, m.TargetSdk = sdk.intAttr("minSdkVersion"), sdk.intAttr("targetSdkVersion")
	}
	for _, c := range root.Children {
		switch c.XMLName.Local {
		case "uses-permission":
			if v := c.attr("name", true); v != "" {
				m.Permissions = append(m.Permissions, v)
			}
		case "permission":
			if v := c.attr("name", true); v != "" {
				m.DefinedPermissions = append(m.DefinedPermissions, v)
			}
		}
	}
	app := root.child("application")
	if app == nil {
		return m, nil
	}
	appC := l.component("application", *app, pkg)
	m.Application = &appC
	for _, c := range app.Children {
		switch c.XMLName.Local {
		case "activity", "activity-alias":
			m.Activities = append(m.Activities, l.component("activity", c, pkg))
		case "service":
			m.Services = append(m.Services, l.component("service", c, pkg))
		case "receiver":
			m.Receivers = append(m.Receivers, l.component("receiver", c, pkg))
		case "provider":
			m.Providers = append(m.Providers, l.component("provider", c, pkg))
		}
	}
	return m, nil
}

func (l *localSource) component(kind string, n xmlNode, pkg string) api.ManifestComponent {
	c := api.ManifestComponent{
		Kind:       kind,
		ClassName:  expandRelativeName(pkg, n.attr("name", true)),
		Enabled:    !strings.EqualFold(n.attr("enabled", true), "false"),
		Permission: n.attr("permission", true),
	}
	for _, f := range n.Children {
		if f.XMLName.Local != "intent-filter" {
			continue
		}
		var filt api.IntentFilter
		for _, e := range f.Children {
			name := e.attr("name", true)
			switch e.XMLName.Local {
			case "action":
				if name != "" {
					filt.Actions = append(filt.Actions, name)
				}
			case "category":
				if name != "" {
					filt.Categories = append(filt.Categories, name)
				}
			case "data":
				if scheme := e.attr("scheme", true); scheme != "" {
					if host := e.attr("host", true); host != "" {
						scheme += "://" + host
					}
					filt.DataSchemes = append(filt.DataSchemes, scheme)
				} else if mime := e.attr("mimeType", true); mime != "" {
					filt.DataSchemes = append(filt.DataSchemes, mime)
				}
			}
		}
		filt.Priority = f.intAttr("priority")
		c.IntentFilters = append(c.IntentFilters, filt)
	}
	// Exported: the explicit attribute, else implied by having an intent filter.
	if v := n.attr("exported", true); v != "" {
		c.Exported = strings.EqualFold(v, "true")
	} else {
		c.Exported = len(c.IntentFilters) > 0
	}
	if kind == "provider" {
		for _, a := range strings.Split(n.attr("authorities", true), ";") {
			if a = strings.TrimSpace(a); a != "" {
				c.Authorities = append(c.Authorities, a)
			}
		}
	}
	c.File, c.Line = l.classLocation(c.ClassName)
	return c
}

// classLocation finds a component class's declaration, preferring the one
// whose package matches the FQN (obfuscated apps reuse simple names).
func (l *localSource) classLocation(fqn string) (string, *int) {
	if fqn == "" {
		return "", nil
	}
	simple := fqn[strings.LastIndexByte(fqn, '.')+1:]
	file, line := "", 0
	for _, s := range l.symbolIndex() {
		if s.Kind != "CLASS" || s.Name != simple {
			continue
		}
		def := simple
		if s.Pkg != "" {
			def = s.Pkg + "." + simple
		}
		if def == fqn {
			return s.File, &s.Line
		}
		if file == "" {
			file, line = s.File, s.Line
		}
	}
	if file == "" {
		return "", nil
	}
	return file, &line
}

// expandRelativeName: Android allows `.Foo` and `Foo` as shorthand for `{pkg}.Foo`.
func expandRelativeName(pkg, name string) string {
	switch {
	case name == "":
		return ""
	case strings.HasPrefix(name, "."):
		return pkg + name
	case !strings.Contains(name, ".") && pkg != "":
		return pkg + "." + name
	}
	return name
}

func mustRel(base, p string) string {
	rel, err := filepath.Rel(base, p)
	if err != nil {
		return p
	}
	return rel
}

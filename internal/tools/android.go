package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"openbin.ai/binny/internal/api"
)

// APK / script read tools. These projects have no binary-analysis blob — their
// code is a decompiled source tree on the backend, which already serves search,
// the parsed manifest and a symbol index. These tools speak to those endpoints
// instead of the blob the native toolset reads.

// sdkPrefixes mirrors the backend's util/SdkPaths: library code that drowns
// the app's own classes in a listing. Search and symbol lookups skip it
// server-side; list_files skips it here, with the same opt-in to include it.
var sdkPrefixes = []string{
	"android/", "androidx/",
	"kotlin/", "kotlinx/",
	"com/google/", "com/android/",
	"com/facebook/", "com/squareup/", "com/bumptech/",
	"okhttp3/", "okio/", "retrofit2/",
	"org/jetbrains/", "org/apache/", "org/json/",
	"dagger/", "javax/", "jakarta/",
	"io/reactivex/", "rx/",
}

func isSdkPath(p string) bool {
	p = strings.TrimPrefix(strings.ReplaceAll(p, `\`, "/"), "sources/")
	for _, pre := range sdkPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// dangerousPermissions are the manifest permissions worth calling out at
// triage — the ones that map to stealer/banker/spyware/RAT capability.
var dangerousPermissions = map[string]bool{
	"android.permission.READ_SMS":                             true,
	"android.permission.RECEIVE_SMS":                          true,
	"android.permission.SEND_SMS":                             true,
	"android.permission.READ_CONTACTS":                        true,
	"android.permission.READ_CALL_LOG":                        true,
	"android.permission.READ_PHONE_STATE":                     true,
	"android.permission.CALL_PHONE":                           true,
	"android.permission.RECORD_AUDIO":                         true,
	"android.permission.CAMERA":                               true,
	"android.permission.ACCESS_FINE_LOCATION":                 true,
	"android.permission.ACCESS_BACKGROUND_LOCATION":           true,
	"android.permission.BIND_ACCESSIBILITY_SERVICE":           true,
	"android.permission.BIND_DEVICE_ADMIN":                    true,
	"android.permission.BIND_NOTIFICATION_LISTENER_SERVICE":   true,
	"android.permission.SYSTEM_ALERT_WINDOW":                  true,
	"android.permission.REQUEST_INSTALL_PACKAGES":             true,
	"android.permission.QUERY_ALL_PACKAGES":                   true,
	"android.permission.MANAGE_EXTERNAL_STORAGE":              true,
	"android.permission.READ_EXTERNAL_STORAGE":                true,
	"android.permission.WRITE_EXTERNAL_STORAGE":               true,
	"android.permission.RECEIVE_BOOT_COMPLETED":               true,
	"android.permission.FOREGROUND_SERVICE":                   true,
	"android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": true,
	"android.permission.GET_ACCOUNTS":                         true,
	"android.permission.USE_FULL_SCREEN_INTENT":               true,
}

// manifest lazily loads + caches the parsed AndroidManifest.xml.
func (tb *Toolbox) manifest() (*api.Manifest, error) {
	if tb.Project.Kind != api.KindAPK {
		return nil, fmt.Errorf("project kind %s has no AndroidManifest", tb.Project.Kind)
	}
	src, srcErr := tb.source()
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if !tb.manifestLoaded {
		tb.manifestLoaded = true
		if srcErr != nil {
			tb.manifestErr = srcErr
		} else {
			tb.manifestData, tb.manifestErr = src.Manifest()
		}
	}
	return tb.manifestData, tb.manifestErr
}

// fileTree lazily loads + caches the project's file tree. A big APK's tree is
// ~10k nodes; list_files is called many times per session, so fetch it once.
func (tb *Toolbox) fileTree() (*api.FileNode, error) {
	src, srcErr := tb.source()
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if !tb.treeLoaded {
		tb.treeLoaded = true
		if srcErr != nil {
			tb.treeErr = srcErr
		} else {
			tb.tree, tb.treeErr = src.Tree()
		}
	}
	return tb.tree, tb.treeErr
}

// apkMetadata is get_metadata's APK body: the manifest at a glance — enough to
// orient triage (what the app is, what it can do, how it starts).
func (tb *Toolbox) apkMetadata(b *strings.Builder) {
	m, err := tb.manifest()
	if err != nil {
		fmt.Fprintf(b, "(manifest unavailable: %v)\n", err)
		return
	}
	fmt.Fprintf(b, "package: %s", orNA(m.PackageName))
	if m.VersionName != "" {
		fmt.Fprintf(b, "  version: %s", m.VersionName)
	}
	if m.VersionCode != nil {
		fmt.Fprintf(b, " (%d)", *m.VersionCode)
	}
	b.WriteByte('\n')
	fmt.Fprintf(b, "minSdk: %s  targetSdk: %s\n", intOrNA(m.MinSdk), intOrNA(m.TargetSdk))
	if m.Application != nil && m.Application.ClassName != "" {
		fmt.Fprintf(b, "application class: %s%s\n", m.Application.ClassName, fileRef(*m.Application))
	}
	for _, c := range m.Activities {
		if isLauncher(c) {
			fmt.Fprintf(b, "launcher activity: %s%s\n", c.ClassName, fileRef(c))
		}
	}
	var risky []string
	for _, p := range m.Permissions {
		if dangerousPermissions[p] {
			risky = append(risky, strings.TrimPrefix(p, "android.permission."))
		}
	}
	fmt.Fprintf(b, "permissions: %d requested", len(m.Permissions))
	if len(risky) > 0 {
		fmt.Fprintf(b, "; high-signal: %s", strings.Join(risky, ", "))
	}
	b.WriteByte('\n')
	all := allComponents(m)
	exported := 0
	for _, c := range all {
		if c.Exported {
			exported++
		}
	}
	fmt.Fprintf(b, "components: %d activities, %d services, %d receivers, %d providers (%d exported)\n",
		len(m.Activities), len(m.Services), len(m.Receivers), len(m.Providers), exported)
	b.WriteString("Next: get_manifest for every component + intent filter; search / find_definition / find_usages / read_file over the code.\n")
}

func (tb *Toolbox) getManifestTool() *Tool {
	return &Tool{
		Def: Def("get_manifest",
			"Get the parsed AndroidManifest.xml: every requested/defined permission, and every activity/service/receiver/provider with exported flag, guarding permission, intent filters (actions, categories, data schemes, priority), authorities, and the file:line of its class in the decompiled tree. The Android attack surface and capability map in one call.",
			Obj(map[string]any{
				"exported_only": map[string]any{"type": "boolean",
					"description": "only list exported components (the cross-app attack surface)"},
			})),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var args struct {
				ExportedOnly bool `json:"exported_only"`
			}
			_ = json.Unmarshal(input, &args)
			m, err := tb.manifest()
			if err != nil {
				return "", err
			}
			var b strings.Builder
			fmt.Fprintf(&b, "package: %s  minSdk: %s  targetSdk: %s\n", orNA(m.PackageName), intOrNA(m.MinSdk), intOrNA(m.TargetSdk))
			if m.Application != nil {
				fmt.Fprintf(&b, "application: %s%s\n", orNA(m.Application.ClassName), fileRef(*m.Application))
			}
			fmt.Fprintf(&b, "\nuses-permission (%d):\n", len(m.Permissions))
			for _, p := range m.Permissions {
				mark := ""
				if dangerousPermissions[p] {
					mark = "  [high-signal]"
				}
				fmt.Fprintf(&b, "  %s%s\n", p, mark)
			}
			if len(m.DefinedPermissions) > 0 {
				fmt.Fprintf(&b, "\ndefines permission (%d):\n", len(m.DefinedPermissions))
				for _, p := range m.DefinedPermissions {
					fmt.Fprintf(&b, "  %s\n", p)
				}
			}
			groups := []struct {
				title string
				cs    []api.ManifestComponent
			}{
				{"activities", m.Activities}, {"services", m.Services},
				{"receivers", m.Receivers}, {"providers", m.Providers},
			}
			for _, g := range groups {
				var lines []string
				for _, c := range g.cs {
					if args.ExportedOnly && !c.Exported {
						continue
					}
					lines = append(lines, formatComponent(c))
				}
				if len(lines) == 0 {
					continue
				}
				fmt.Fprintf(&b, "\n%s (%d):\n", g.title, len(lines))
				if len(lines) > maxListItems {
					lines = append(lines[:maxListItems], "  … (truncated)")
				}
				b.WriteString(strings.Join(lines, "\n"))
				b.WriteByte('\n')
			}
			return b.String(), nil
		},
	}
}

func (tb *Toolbox) codeSearchTool() *Tool {
	return &Tool{
		Def: Def("search",
			"Search the decompiled source tree line by line with a case-insensitive regular expression (stick to the common Java/RE2 subset — no lookarounds or backreferences). Returns file:line: snippet hits — then read_file with start_line to see the context. Library/SDK code (androidx, kotlin, com.google, okhttp, …) is skipped unless include_sdks is true. Use for URLs/hosts, API keys, crypto (Cipher.getInstance, SecretKeySpec), dangerous APIs (Runtime.exec, DexClassLoader, addJavascriptInterface, SmsManager, AccessibilityService), and string literals.",
			Obj(map[string]any{
				"regex": StrProp("regular expression, matched per line"),
				"include_sdks": map[string]any{"type": "boolean",
					"description": "also search library/SDK packages (default false)"},
			}, "regex")),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var args struct {
				Regex       string `json:"regex"`
				IncludeSdks bool   `json:"include_sdks"`
			}
			_ = json.Unmarshal(input, &args)
			if args.Regex == "" {
				return "", fmt.Errorf("provide regex")
			}
			src, err := tb.source()
			if err != nil {
				return "", err
			}
			// Over-fetch: the namespace-noise filter may drop some hits.
			hits, err := src.Search(args.Regex, args.IncludeSdks, 4*maxSearchHits+1)
			if err != nil {
				return "", err
			}
			hits, nsDropped := filterXMLNamespaceNoise(hits, args.Regex)
			if len(hits) == 0 {
				switch {
				case nsDropped > 0:
					return fmt.Sprintf("no matches except %d XML namespace declaration(s) (xmlns=\"http://schemas…\"), filtered as noise", nsDropped), nil
				case !args.IncludeSdks:
					return "no matches outside SDK/library code (retry with include_sdks=true to search libraries too)", nil
				default:
					return "no matches", nil
				}
			}
			more := len(hits) > maxSearchHits
			if more {
				hits = hits[:maxSearchHits]
			}
			lines := make([]string, len(hits))
			for i, h := range hits {
				lines[i] = fmt.Sprintf("%s:%d: %s", h.File, h.Line, strings.TrimSpace(h.Snippet))
			}
			out := strings.Join(lines, "\n")
			if more {
				out += "\n… (more hits truncated; refine the regex)"
			}
			if nsDropped > 0 {
				out += fmt.Sprintf("\n(%d XML namespace-declaration line(s) filtered as noise)", nsDropped)
			}
			return out, nil
		},
	}
}

// reXMLNS strips xmlns / xmlns:prefix attributes so a search for a URL scheme
// doesn't drown in schema declarations like xmlns:android="http://schemas…".
var reXMLNS = regexp.MustCompile(`\s*xmlns(:[\w.-]+)?\s*=\s*"[^"]*"`)

// filterXMLNamespaceNoise drops hits in .xml files that match ONLY because of
// an xmlns declaration: it removes the xmlns attributes from the line and keeps
// the hit only if the regex still matches the remainder. A real value (a URL in
// an attribute, a string in <string>…</string>) survives; schema boilerplate
// does not. If the pattern itself targets xmlns/schema text, nothing is
// dropped. RE2-uncompilable patterns (Java-only syntax) skip the filter.
func filterXMLNamespaceNoise(hits []api.SearchHit, pattern string) ([]api.SearchHit, int) {
	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return hits, 0
	}
	if re.MatchString("xmlns") || re.MatchString("schemas.android.com") {
		return hits, 0 // the search is for namespace/schema text — keep it
	}
	var kept []api.SearchHit
	dropped := 0
	for _, h := range hits {
		if strings.HasSuffix(strings.ToLower(h.File), ".xml") {
			stripped := reXMLNS.ReplaceAllString(h.Snippet, "")
			if !re.MatchString(stripped) {
				dropped++
				continue
			}
		}
		kept = append(kept, h)
	}
	return kept, dropped
}

func (tb *Toolbox) findDefinitionTool() *Tool {
	return &Tool{
		Def: Def("find_definition",
			"Find where a class, method or field is declared in the decompiled Java (by simple name, e.g. `MainActivity`, `decrypt`, `API_KEY`). Returns kind, owning class, signature, modifiers and file:line. App code only unless include_sdks.",
			Obj(map[string]any{
				"name": StrProp("simple name of the class/method/field"),
				"include_sdks": map[string]any{"type": "boolean",
					"description": "also look in library/SDK packages (default false)"},
			}, "name")),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var args struct {
				Name        string `json:"name"`
				IncludeSdks bool   `json:"include_sdks"`
			}
			_ = json.Unmarshal(input, &args)
			if args.Name == "" {
				return "", fmt.Errorf("provide name")
			}
			src, err := tb.source()
			if err != nil {
				return "", err
			}
			syms, err := src.Definitions(args.Name, args.IncludeSdks)
			if err != nil {
				return "", err
			}
			if len(syms) == 0 {
				return fmt.Sprintf("no declaration named %q (names are case-sensitive simple names; try search for a partial match)", args.Name), nil
			}
			var lines []string
			for i, s := range syms {
				if i >= maxSearchHits {
					lines = append(lines, "… (more truncated)")
					break
				}
				owner := ""
				if s.ClassName != "" && s.ClassName != s.Name {
					owner = " in " + s.ClassName
				}
				sig := strings.TrimSpace(strings.Join([]string{s.Modifiers, s.Signature}, " "))
				if sig != "" {
					sig = "  " + sig
				}
				lines = append(lines, fmt.Sprintf("%s %s%s  %s:%d%s", strings.ToLower(s.Kind), s.Name, owner, s.File, s.Line, sig))
			}
			return strings.Join(lines, "\n"), nil
		},
	}
}

func (tb *Toolbox) findUsagesTool() *Tool {
	return &Tool{
		Def: Def("find_usages",
			"Find references to a class/method/field across the decompiled Java (the APK equivalent of xrefs). Pass `class` to disambiguate a common member name (e.g. name=`decrypt`, class=`com.evil.Crypto`). Returns file:line: snippet.",
			Obj(map[string]any{
				"name":  StrProp("simple name of the symbol"),
				"class": StrProp("optional: fully-qualified owning class to narrow member lookups"),
				"include_sdks": map[string]any{"type": "boolean",
					"description": "also look in library/SDK packages (default false)"},
			}, "name")),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var args struct {
				Name        string `json:"name"`
				Class       string `json:"class"`
				IncludeSdks bool   `json:"include_sdks"`
			}
			_ = json.Unmarshal(input, &args)
			if args.Name == "" {
				return "", fmt.Errorf("provide name")
			}
			src, err := tb.source()
			if err != nil {
				return "", err
			}
			uses, err := src.Usages(args.Name, args.Class, args.IncludeSdks)
			if err != nil {
				return "", err
			}
			if len(uses) == 0 {
				return fmt.Sprintf("no usages of %q found", args.Name), nil
			}
			var lines []string
			for i, u := range uses {
				if i >= maxSearchHits {
					lines = append(lines, fmt.Sprintf("… (%d more truncated)", len(uses)-maxSearchHits))
					break
				}
				lines = append(lines, fmt.Sprintf("%s:%d: %s", u.File, u.Line, strings.TrimSpace(u.Snippet)))
			}
			return strings.Join(lines, "\n"), nil
		},
	}
}

// listTree renders list_files: every file under dir matching filter, or —
// when that's more than a listing can hold — a per-subdirectory count so the
// model can drill in instead of reading an arbitrary first 200 paths.
func listTree(root *api.FileNode, dir, filter string, includeSdks bool) string {
	dir = strings.Trim(strings.ReplaceAll(dir, `\`, "/"), "/")
	prefix := ""
	if dir != "" {
		prefix = dir + "/"
	}
	f := strings.ToLower(filter)
	var files []string
	skippedSdk := 0
	var walk func(n *api.FileNode)
	walk = func(n *api.FileNode) {
		if n.Type == "file" {
			p := strings.TrimPrefix(n.Path, "/")
			if prefix != "" && !strings.HasPrefix(p, prefix) {
				return
			}
			if f != "" && !strings.Contains(strings.ToLower(p), f) {
				return
			}
			if !includeSdks && isSdkPath(p) {
				skippedSdk++
				return
			}
			files = append(files, p)
		}
		for i := range n.Children {
			walk(&n.Children[i])
		}
	}
	walk(root)
	sdkNote := ""
	if skippedSdk > 0 {
		sdkNote = fmt.Sprintf("\n(%d library/SDK files hidden; include_sdks=true to show)", skippedSdk)
	}
	if len(files) == 0 {
		return "no files" + sdkNote
	}
	sort.Strings(files)
	if len(files) <= maxListItems {
		return strings.Join(files, "\n") + sdkNote
	}
	// Too many to list: summarize one level below dir.
	counts := map[string]int{}
	var direct []string
	for _, p := range files {
		rest := strings.TrimPrefix(p, prefix)
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			counts[prefix+rest[:i]+"/"]++
		} else {
			direct = append(direct, p)
		}
	}
	dirs := make([]string, 0, len(counts))
	for d := range counts {
		dirs = append(dirs, d)
	}
	sort.Slice(dirs, func(i, j int) bool {
		if counts[dirs[i]] != counts[dirs[j]] {
			return counts[dirs[i]] > counts[dirs[j]]
		}
		return dirs[i] < dirs[j]
	})
	var b strings.Builder
	fmt.Fprintf(&b, "%d files — too many to list. Subdirectories (file count); call list_files with dir=<one of these> to drill in, or pass filter:\n", len(files))
	for i, d := range dirs {
		if i >= maxListItems {
			b.WriteString("… (more directories truncated)\n")
			break
		}
		fmt.Fprintf(&b, "  %s (%d)\n", d, counts[d])
	}
	if len(direct) > 0 {
		fmt.Fprintf(&b, "files directly in %s:\n", orNA(dir))
		for i, p := range direct {
			if i >= 50 {
				b.WriteString("  …\n")
				break
			}
			fmt.Fprintf(&b, "  %s\n", p)
		}
	}
	return strings.TrimRight(b.String(), "\n") + sdkNote
}

// sliceLines returns the window of text starting at 1-based line start,
// numbered, capped at maxChars, plus the next line to continue from (0 = done).
func sliceLines(text string, start, maxChars int) (string, int) {
	lines := strings.Split(text, "\n")
	if start < 1 {
		start = 1
	}
	if start > len(lines) {
		return fmt.Sprintf("(file has only %d lines)", len(lines)), 0
	}
	var b strings.Builder
	for i := start - 1; i < len(lines); i++ {
		line := fmt.Sprintf("%6d  %s\n", i+1, lines[i])
		if b.Len()+len(line) > maxChars && b.Len() > 0 {
			return b.String(), i + 1
		}
		b.WriteString(line)
	}
	return b.String(), 0
}

func allComponents(m *api.Manifest) []api.ManifestComponent {
	var out []api.ManifestComponent
	out = append(out, m.Activities...)
	out = append(out, m.Services...)
	out = append(out, m.Receivers...)
	out = append(out, m.Providers...)
	return out
}

func isLauncher(c api.ManifestComponent) bool {
	for _, f := range c.IntentFilters {
		hasMain, hasLauncher := false, false
		for _, a := range f.Actions {
			hasMain = hasMain || a == "android.intent.action.MAIN"
		}
		for _, cat := range f.Categories {
			hasLauncher = hasLauncher || cat == "android.intent.category.LAUNCHER"
		}
		if hasMain && hasLauncher {
			return true
		}
	}
	return false
}

func formatComponent(c api.ManifestComponent) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  %s", c.ClassName)
	var tags []string
	if c.Exported {
		tags = append(tags, "EXPORTED")
	}
	if !c.Enabled {
		tags = append(tags, "disabled")
	}
	if c.Permission != "" {
		tags = append(tags, "permission="+c.Permission)
	}
	if len(c.Authorities) > 0 {
		tags = append(tags, "authorities="+strings.Join(c.Authorities, ","))
	}
	if len(tags) > 0 {
		fmt.Fprintf(&b, "  [%s]", strings.Join(tags, " "))
	}
	b.WriteString(fileRef(c))
	for _, f := range c.IntentFilters {
		var parts []string
		if len(f.Actions) > 0 {
			parts = append(parts, "actions="+strings.Join(f.Actions, ","))
		}
		if len(f.Categories) > 0 {
			parts = append(parts, "categories="+strings.Join(f.Categories, ","))
		}
		if len(f.DataSchemes) > 0 {
			parts = append(parts, "schemes="+strings.Join(f.DataSchemes, ","))
		}
		if f.Priority != nil {
			parts = append(parts, fmt.Sprintf("priority=%d", *f.Priority))
		}
		if len(parts) > 0 {
			fmt.Fprintf(&b, "\n      intent-filter: %s", strings.Join(parts, " "))
		}
	}
	return b.String()
}

func fileRef(c api.ManifestComponent) string {
	if c.File == "" {
		return "  (class not in decompiled tree)"
	}
	if c.Line != nil {
		return fmt.Sprintf("  → %s:%d", c.File, *c.Line)
	}
	return "  → " + c.File
}

func intOrNA(p *int) string {
	if p == nil {
		return "n/a"
	}
	return fmt.Sprint(*p)
}

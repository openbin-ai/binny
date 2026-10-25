package playbook

import (
	"fmt"
	"strings"
)

// A VulnClass is one family of vulnerability the researcher can hunt. Vuln mode
// can run broad (survey every class across the attack surface) or be SCOPED to
// one or more classes — "look for memory-safety bugs and nothing else" — in
// which case INVESTIGATE dispatches only those classes' recipes to the agent.
//
// The recipe is deliberately behavioural, not just a sink list: many real bugs
// (an input-controlled copy loop into a fixed buffer, an auth check that falls
// open on error) involve no "dangerous function" at all. It is detection /
// triage guidance for a defensive audit — what the pattern looks like so the
// agent can find it and judge reachability — never exploitation.
type VulnClass struct {
	Key     string   // stable id, e.g. "memory"
	Aliases []string // what a researcher might type/say for it
	Name    string   // display name
	CWEs    []string // the CWE ids this class covers
	// Objectives replace the generic vuln objectives when the session is scoped
	// to this class.
	Objectives []Objective
	// Hunt is the recipe for NATIVE targets; HuntAPK / HuntScript override it for
	// those kinds when the sink/pattern vocabulary differs. Empty falls back to Hunt.
	Hunt       string
	HuntAPK    string
	HuntScript string
}

// HuntFor returns the class's recipe for a project kind.
func (c VulnClass) HuntFor(kind string) string {
	switch kind {
	case "APK":
		if c.HuntAPK != "" {
			return c.HuntAPK
		}
	case "SCRIPT":
		if c.HuntScript != "" {
			return c.HuntScript
		}
	}
	return c.Hunt
}

var vulnClasses = []VulnClass{
	{
		Key:     "memory",
		Aliases: []string{"memory-safety", "mem", "buffer-overflow", "overflow", "bof", "oob", "uaf", "use-after-free"},
		Name:    "Memory safety",
		CWEs:    []string{"CWE-787", "CWE-125", "CWE-121", "CWE-122", "CWE-416", "CWE-415", "CWE-476", "CWE-824"},
		Objectives: []Objective{
			{"mem-surface", "Map where external bytes enter (parsers, read/recv/fread, exported APIs taking buffers+lengths)"},
			{"mem-copies", "Find size-unsafe copies: memcpy/memmove/strcpy/strcat/sprintf/gets/alloca where the length is attacker-influenced or the dest is fixed"},
			{"mem-loops", "Find input-controlled loops: a loop whose bound comes from input writing into a fixed-size buffer (no library sink needed)"},
			{"mem-lifetime", "Find use-after-free / double-free: a pointer used or freed after a free on a path reachable from input"},
			{"mem-verdict", "For each candidate, trace source→sink and record a reachability verdict (incl. ruled_out) with the controllability of size/offset/value"},
		},
		Hunt:    "Memory-safety hunt. SINKS by import/call: memcpy, memmove, memset, strcpy, strncpy (misused), strcat, sprintf/vsprintf, scanf family, gets, alloca, read/recv/fread into a stack buffer. BEHAVIOURAL patterns that have NO named sink — look for these in decompiled code: (1) a loop `for/while (i < n)` where `n` is read from input and the body does `dst[i] = src[i]` into a fixed-size `dst`; (2) a length taken from a header/field then passed to a copy without a bounds check against the destination size; (3) signed length compared with `<=` then used as unsigned (negative → huge copy); (4) `malloc(a*b)` or `+len` that can wrap, then a copy of the pre-wrap size; (5) an index from input used without a range check; (6) a pointer freed on one path and used/freed again on another. For each: get_function the routine, read the arithmetic, and use `reachability` to connect the buffer to an export/entry. Record controllability = what the attacker sets (length, index, element values).",
		HuntAPK: "Memory-safety applies to the APK's NATIVE libraries (lib/<abi>/*.so), not the Java. In the Java tree, map the JNI surface: `native` method declarations and System.loadLibrary(...) — find_usages on each native method to see what untrusted data (Intent extras, file bytes, network buffers) is handed across JNI. Record which .so + JNI entry takes attacker bytes and should be audited as its own BIN project; a Java-only project can't prove the native memory bug, so record those as reachability=unproven candidates pointing at the .so.",
	},
	{
		Key:     "integer",
		Aliases: []string{"int", "integer-overflow", "int-overflow", "truncation", "signedness"},
		Name:    "Integer errors",
		CWEs:    []string{"CWE-190", "CWE-191", "CWE-192", "CWE-197", "CWE-680"},
		Objectives: []Objective{
			{"int-sites", "Find size/length/count arithmetic on attacker-influenced values (multiply, add, shift) feeding an allocation or copy"},
			{"int-conv", "Find narrowing/sign conversions (int→short, signed→unsigned) on lengths or indices"},
			{"int-verdict", "For each, show the overflow/truncation value and whether it reaches a memory op; record a verdict"},
		},
		Hunt: "Integer-error hunt. Look for arithmetic on sizes/counts/indices that come from input: `a * b`, `len + k`, `count << s` feeding malloc/realloc/memcpy; a 32-bit length truncated from a 64-bit field; a signed int length that a `< size` check lets pass while negative, then used as a huge unsigned size. The bug is the arithmetic, not a function — read the exact types and widths in the decompilation. Pair each integer issue with the memory op it feeds and record that as the sink; an integer overflow that reaches no unsafe op is reachability=ruled_out.",
	},
	{
		Key:     "format-string",
		Aliases: []string{"fmt", "format", "formatstring"},
		Name:    "Format string",
		CWEs:    []string{"CWE-134"},
		Objectives: []Objective{
			{"fmt-sites", "Find printf-family / logging calls whose FORMAT argument is non-literal and attacker-influenced"},
			{"fmt-verdict", "Confirm the format string is attacker-controlled (not just the varargs) and record a verdict"},
		},
		Hunt: "Format-string hunt. Find printf, fprintf, sprintf, snprintf, syslog, err/warn and logging wrappers where the FORMAT argument is a variable, not a string literal, and that variable traces back to input. `printf(buf)` where buf is attacker data is the bug; `printf(\"%s\", buf)` is safe. Trace the format argument's origin; record ruled_out when it's a literal or a fixed internal string.",
	},
	{
		Key:     "command-injection",
		Aliases: []string{"cmd", "command", "cmdi", "rce", "exec", "code-injection", "eval"},
		Name:    "Command / code injection",
		CWEs:    []string{"CWE-78", "CWE-77", "CWE-95", "CWE-94"},
		Objectives: []Objective{
			{"cmd-sinks", "Find process/command and dynamic-eval sinks"},
			{"cmd-flow", "Trace attacker input into the command/code string without neutralization"},
			{"cmd-verdict", "Record a verdict per sink, noting any sanitization/allow-listing in the path"},
		},
		Hunt:       "Command/code-injection hunt. SINKS: system, popen, exec* (execl/execve/…), posix_spawn, ShellExecute/CreateProcess, Runtime.exec/ProcessBuilder (Java), and dynamic code: dlopen+dlsym of an input-named lib, LoadLibrary, DexClassLoader. Trace whether attacker input reaches the command/arg/path with no allow-list or escaping. A fixed command with no input is ruled_out; a command built by concatenating input is the bug — note exactly which fragment is controlled.",
		HuntScript: "Command/code-injection hunt. SINKS: os.system, subprocess.* with shell=True, eval, exec, compile (Python); child_process.exec, eval, new Function, vm.runInContext (Node); backticks, system, `eval`, Kernel#open('|…') (Ruby). Trace input into the command string or evaluated code without escaping/allow-listing. shell=False with a list argv, or a parameterized call, is ruled_out.",
	},
	{
		Key:     "injection-data",
		Aliases: []string{"sqli", "sql", "sql-injection", "ldap", "xpath", "nosql"},
		Name:    "Data-store injection",
		CWEs:    []string{"CWE-89", "CWE-90", "CWE-643", "CWE-943"},
		Objectives: []Objective{
			{"inj-queries", "Find query construction (SQL/LDAP/NoSQL) built by string concatenation with input"},
			{"inj-verdict", "Record whether parameterization/escaping is used; a verdict per query site"},
		},
		Hunt: "Data-store-injection hunt. Find query/statement construction where input is concatenated or formatted into the query text: SQL (SELECT/INSERT/UPDATE with `+`/format), raw query APIs (rawQuery/execSQL on Android, Statement.execute in Java, cursor.execute with %-format in Python), LDAP filters, NoSQL `$where`/JSON queries. Parameterized queries / prepared statements / bound args are ruled_out. Name the controlled fragment and the store.",
	},
	{
		Key:     "path-traversal",
		Aliases: []string{"path", "traversal", "lfi", "zip-slip", "file"},
		Name:    "Path traversal",
		CWEs:    []string{"CWE-22", "CWE-23", "CWE-36", "CWE-73"},
		Objectives: []Objective{
			{"path-sinks", "Find filesystem opens/reads/writes whose path includes attacker input"},
			{"path-verdict", "Check for canonicalization/allow-listing; record a verdict (note zip-slip on archive extraction)"},
		},
		Hunt: "Path-traversal hunt. Find file opens (open/fopen/CreateFile, File(), FileInputStream, openFileOutput, ContentProvider openFile) where the path or filename comes from input and is joined without canonicalization or a `..`/absolute-path check. Include ZIP-slip: extracting an archive and writing each entry by its name without validating the resolved path stays under the target dir. A path confined to a fixed dir with a canonicalized, allow-listed name is ruled_out.",
	},
	{
		Key:     "deserialization",
		Aliases: []string{"deser", "deserialize", "unpickle", "unmarshal"},
		Name:    "Unsafe deserialization",
		CWEs:    []string{"CWE-502"},
		Objectives: []Objective{
			{"deser-sinks", "Find deserialization of attacker-controlled bytes into objects"},
			{"deser-verdict", "Record whether types are constrained/allow-listed; a verdict per sink"},
		},
		Hunt: "Unsafe-deserialization hunt. SINKS: Java ObjectInputStream.readObject / Serializable / Parcelable from an untrusted source, Android Intent.getSerializableExtra/getParcelableExtra into a mutable graph; Python pickle.loads, yaml.load (non-safe), marshal; Node node-serialize, unserialize. The bug is deserializing attacker bytes without a type allow-list / safe loader. A constrained schema (yaml.safe_load, JSON into a fixed struct) is ruled_out.",
	},
	{
		Key:     "auth",
		Aliases: []string{"authentication", "authz", "authorization", "access-control", "authn", "login", "session"},
		Name:    "Authentication & access control",
		CWEs:    []string{"CWE-287", "CWE-862", "CWE-863", "CWE-306", "CWE-284", "CWE-639", "CWE-640", "CWE-384"},
		Objectives: []Objective{
			{"auth-points", "Map the authentication and authorization decision points (who may call what)"},
			{"auth-logic", "Audit each check's LOGIC for flaws, not just its presence"},
			{"auth-verdict", "Record a verdict per weakness, with what it grants"},
		},
		Hunt:    "Auth / access-control hunt — this is LOGIC, not a sink list; read the decision code. Look for: a check that falls OPEN on error or exception (returns authenticated/authorized when a lookup throws or a value is null/empty); credential or token comparison with `==`/strcmp/.equals (non-constant-time, or comparing a user value to \"\" that an empty input satisfies); a sensitive operation with NO authorization check on a path reachable from input (CWE-862); an identifier (user id, object id, file key) taken from input and used without an ownership check (IDOR, CWE-639); missing authentication on an exposed entry point (CWE-306); predictable/again-usable session tokens or fixation; a hardcoded/backdoor credential or a debug bypass flag. For each, read the exact branch logic, state what it protects and what bypasses it, and record a verdict.",
		HuntAPK: "Auth / access-control hunt (Android). Exported components (get_manifest exported_only=true) that perform privileged actions with NO permission guard and NO caller check are the headline access-control bug (CWE-862/926): trace each exported onCreate/onStartCommand/onReceive/openFile/call to the privileged action and see whether anything checks the caller. Also: custom permissions declared with protectionLevel=normal guarding sensitive ops; checkCallingPermission/enforce missing on a Service/Provider; a signature check or token comparison done with .equals (non-constant-time) or that falls open; an object/file id from an Intent used without an ownership check (IDOR). Read the branch logic, don't just note the component.",
	},
	{
		Key:     "crypto",
		Aliases: []string{"cryptography", "encryption", "weak-crypto", "tls", "cert"},
		Name:    "Cryptographic weakness",
		CWEs:    []string{"CWE-327", "CWE-328", "CWE-326", "CWE-329", "CWE-330", "CWE-759", "CWE-760", "CWE-295", "CWE-347"},
		Objectives: []Objective{
			{"crypto-prims", "Find weak primitives/modes and misuse (ECB, static/zero IV, MD5/SHA1 for integrity, small keys)"},
			{"crypto-random", "Find insecure randomness used for keys/tokens/IVs"},
			{"crypto-trust", "Find disabled/also-accept certificate or signature verification"},
			{"crypto-verdict", "Record a verdict per weakness with its security impact"},
		},
		Hunt:    "Crypto-weakness hunt. Look for: weak algorithms/modes — DES/3DES/RC4, AES in ECB, MD5/SHA1 used for integrity or signatures; STATIC or zero IV/nonce, or a nonce reused across messages; a key or salt derived from a constant, or a hardcoded key (overlaps hardcoded-secrets); insecure randomness (rand/random/Math.random, srand(time)) feeding a key, IV, token or salt (want a CSPRNG); disabled transport/cert validation — a TrustManager that accepts all, HostnameVerifier returning true, SSL_VERIFY_NONE, `verify=False`; signature verification that is skipped or whose result is ignored. Name the primitive, where the key/IV/randomness comes from, and the impact. A correct AEAD with a CSPRNG nonce is ruled_out.",
		HuntAPK: "Crypto-weakness hunt (Android). Cipher.getInstance(\"AES\") or \"AES/ECB/…\" (ECB default), IvParameterSpec built from a constant byte[] or a hardcoded string, SecretKeySpec from a literal/constant key, MessageDigest MD5/SHA-1 for integrity, `new Random()` (not SecureRandom) for keys/IVs/tokens, a custom X509TrustManager whose checkServerTrusted is empty, a HostnameVerifier returning true, or WebView onReceivedSslError calling proceed(). Also android:usesCleartextTraffic / a network-security-config that permits cleartext or user CAs. Read where the key and IV actually come from before judging severity.",
	},
	{
		Key:     "secrets",
		Aliases: []string{"hardcoded", "hardcoded-secret", "secret", "credentials", "keys", "token"},
		Name:    "Hardcoded secrets",
		CWEs:    []string{"CWE-798", "CWE-321", "CWE-259", "CWE-312", "CWE-532"},
		Objectives: []Objective{
			{"secret-scan", "Find embedded credentials, API keys, private keys, and tokens in code/resources"},
			{"secret-verdict", "Confirm each is a real secret (not a placeholder/public id) and record its exposure and impact"},
		},
		Hunt: "Hardcoded-secrets hunt. Search for: assignments to names containing key/secret/token/password/passwd/pwd/apikey/credential; long base64/hex string literals; PEM markers (BEGIN ... PRIVATE KEY); known key shapes (AKIA… AWS, AIza… Google, ghp_… GitHub, sk_live/sk-… Stripe/OpenAI, Bearer literals, JWTs); cloud/service config with embedded creds. For APKs also scan resources/ (strings.xml, assets/, *.properties, *.json). Decode and verify it's a real, usable secret — distinguish a live private key or API token (high) from a public key, a placeholder, or a non-sensitive id (ruled_out / info). Note where it's exposed (shipped binary, world-readable resource, log line) and what it grants.",
	},
	{
		Key:     "ssrf",
		Aliases: []string{"server-side-request-forgery", "request-forgery", "url"},
		Name:    "SSRF / request forgery",
		CWEs:    []string{"CWE-918"},
		Objectives: []Objective{
			{"ssrf-sinks", "Find outbound requests whose destination (host/URL) is attacker-influenced"},
			{"ssrf-verdict", "Check for host allow-listing / scheme restriction; record a verdict"},
		},
		Hunt: "SSRF hunt. Find outbound HTTP/network calls (fetch/axios/requests/urllib/HttpURLConnection/OkHttp/curl) whose destination host or URL comes from input with no allow-list or scheme/host restriction, letting an attacker aim the request at internal services or metadata endpoints. A fixed base URL or an allow-listed host is ruled_out. Note what the response exposes back to the attacker.",
	},
	{
		Key:     "race",
		Aliases: []string{"toctou", "race-condition", "concurrency", "tempfile"},
		Name:    "Race condition / TOCTOU",
		CWEs:    []string{"CWE-362", "CWE-367", "CWE-377"},
		Objectives: []Objective{
			{"race-sites", "Find check-then-use gaps on shared state/files and insecure temp-file creation"},
			{"race-verdict", "Record whether the window is attacker-reachable and the impact"},
		},
		Hunt: "Race/TOCTOU hunt. Look for a security check on a resource followed by a use of it through a re-resolvable name (access() then open(); stat() then use; a permission check then an action on the same path) where an attacker can swap the target in the window; predictable temp-file names (tmpnam/mktemp, fixed /tmp paths) created without O_EXCL; shared mutable state updated without locking on an input-reachable path. Record the window and whether it's attacker-reachable.",
	},
	{
		Key:     "android-components",
		Aliases: []string{"android", "components", "intent", "ipc", "webview", "exported", "deeplink"},
		Name:    "Android component exposure",
		CWEs:    []string{"CWE-926", "CWE-927", "CWE-749", "CWE-200", "CWE-939"},
		Objectives: []Objective{
			{"ac-surface", "Enumerate exported components and the input each accepts"},
			{"ac-intent", "Audit Intent/extra/URI handling for injection, redirection and trust-of-input"},
			{"ac-webview", "Audit WebView config and JS bridges"},
			{"ac-verdict", "Record a verdict per exposed component"},
		},
		HuntAPK: "Android-component-exposure hunt. From get_manifest exported_only=true, for each exported component: (1) does it perform a privileged/sensitive action reachable by any other app with no permission guard? (CWE-926) (2) Intent handling — extras/data trusted without validation, an Intent re-sent or a PendingIntent built mutable/implicit allowing redirection (CWE-927), a returned Intent leaking data; (3) ContentProvider — exported with grantUriPermissions, SQL from query() selection/args (overlaps injection-data), openFile path from the URI (overlaps path-traversal); (4) WebView — setJavaScriptEnabled with addJavascriptInterface exposed to remote/untrusted content (CWE-749), loadUrl/loadData with attacker input, onReceivedSslError proceeding, file:// access with JS. Read each handler; record a verdict with what a malicious app gains.",
		Hunt:    "Android-component exposure applies to APK projects; this target isn't one. Use the other classes.",
	},
}

// VulnClasses returns the registry (display/listing).
func VulnClasses() []VulnClass { return append([]VulnClass(nil), vulnClasses...) }

// LookupVulnClass resolves a user token (key or alias, case/space/underscore
// insensitive) to a class. ok=false when nothing matches.
func LookupVulnClass(token string) (VulnClass, bool) {
	n := normalizeClassToken(token)
	if n == "" {
		return VulnClass{}, false
	}
	for _, c := range vulnClasses {
		if normalizeClassToken(c.Key) == n {
			return c, true
		}
		for _, a := range c.Aliases {
			if normalizeClassToken(a) == n {
				return c, true
			}
		}
	}
	// Substring fallback: "memory safety" → memory, "weak crypto" → crypto.
	for _, c := range vulnClasses {
		if strings.Contains(n, normalizeClassToken(c.Key)) {
			return c, true
		}
		for _, a := range c.Aliases {
			na := normalizeClassToken(a)
			if len(na) >= 4 && strings.Contains(n, na) {
				return c, true
			}
		}
	}
	return VulnClass{}, false
}

func normalizeClassToken(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer("_", "", "-", "", " ", "").Replace(s)
	return s
}

// VulnPlaybookForFocus builds a vuln playbook scoped to the given class keys:
// its objectives are the union of those classes' objectives, and its tool bias
// is each class's recipe for the target kind. Unknown keys are skipped; an
// empty/all-unknown result falls back to the generic VulnPlaybookFor(kind).
func VulnPlaybookForFocus(kind string, classKeys []string) (Playbook, []VulnClass) {
	var classes []VulnClass
	seen := map[string]bool{}
	for _, k := range classKeys {
		if c, ok := LookupVulnClass(k); ok && !seen[c.Key] {
			seen[c.Key] = true
			classes = append(classes, c)
		}
	}
	if len(classes) == 0 {
		return VulnPlaybookFor(kind), nil
	}
	var names, cwes []string
	var objectives []Objective
	var recipe strings.Builder
	cweSeen := map[string]bool{}
	for _, c := range classes {
		names = append(names, c.Name)
		objectives = append(objectives, c.Objectives...)
		for _, w := range c.CWEs {
			if !cweSeen[w] {
				cweSeen[w] = true
				cwes = append(cwes, w)
			}
		}
		recipe.WriteString(c.HuntFor(kind))
		recipe.WriteString("\n")
	}
	pb := Playbook{
		Name:       "Vuln — scoped: " + strings.Join(names, " + "),
		vuln:       true,
		Objectives: objectives,
		ToolBias:   recipe.String(),
		Sections:   VulnPlaybookFor(kind).Sections,
	}
	return pb, classes
}

// VulnClassList renders the registry for /focus help and listings.
func VulnClassList() string {
	var b strings.Builder
	for _, c := range vulnClasses {
		fmt.Fprintf(&b, "  %-20s %s  [%s]\n", c.Key, c.Name, strings.Join(c.CWEs, " "))
	}
	return b.String()
}

// vulnIntentCues are phrases that, in an opening message or intel, signal the
// analyst wants VULNERABILITY RESEARCH rather than malware analysis.
var vulnIntentCues = []string{
	"vulnerab", "vuln research", "vuln mode", "find vulns", "find bugs", "security bug",
	"security audit", "security review", "security assessment", "pentest", "pen test",
	"exploitab", "attack surface", "source to sink", "source-to-sink",
	"memory corruption", "buffer overflow", "out-of-bounds", "out of bounds",
	"use after free", "use-after-free", "double free", "integer overflow",
	"command injection", "code injection", "sql injection", "path traversal",
	"insecure deserial", "hardcoded secret", "hard-coded secret", "weak crypto",
	"cwe", "cve", "coordinated disclosure", "0day", "0-day", "zero day",
}

// malwareIntentCues pull the other way — if present without vuln cues, keep
// malware mode (so "analyze this malware for vulnerabilities it exploits"
// doesn't misfire, and a plain malware brief stays malware).
var malwareIntentCues = []string{
	"malware", "ransomware", "infostealer", "stealer", "trojan", "rat ", "c2", "c&c",
	"iocs", "ioc ", "family", "campaign", "apt", "classify", "detection signature",
}

// DetectVulnIntent reports whether free-text intent asks for vulnerability
// research. A vuln cue wins unless the text is clearly a malware brief with no
// vuln cue. Returns the matched cue for a user-facing notice.
func DetectVulnIntent(text string) (bool, string) {
	t := strings.ToLower(text)
	for _, cue := range vulnIntentCues {
		if strings.Contains(t, cue) {
			return true, strings.TrimSpace(cue)
		}
	}
	return false, ""
}

// DetectVulnClasses scans text for vulnerability-class names/aliases and returns
// the matched class keys (deduped, in registry order). Drives auto-/focus from
// an opening brief like "look for buffer overflows and weak crypto".
func DetectVulnClasses(text string) []string {
	t := strings.ToLower(text)
	var keys []string
	seen := map[string]bool{}
	for _, c := range vulnClasses {
		matched := strings.Contains(t, strings.ToLower(c.Name))
		if !matched {
			for _, a := range c.Aliases {
				// Only multi-char, word-ish aliases, to avoid "int"/"mem" noise;
				// match hyphen- or space-separated spellings ("weak-crypto" ↔ "weak crypto").
				if len(a) < 5 {
					continue
				}
				al := strings.ToLower(a)
				if strings.Contains(t, al) || strings.Contains(t, strings.ReplaceAll(al, "-", " ")) {
					matched = true
					break
				}
			}
		}
		if matched && !seen[c.Key] {
			seen[c.Key] = true
			keys = append(keys, c.Key)
		}
	}
	return keys
}

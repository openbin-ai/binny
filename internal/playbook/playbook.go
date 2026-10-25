// Package playbook is BINNY's first-class playbook registry. A playbook is
// data, not code: objectives[] + a biased toolset hint + report-section
// template, selected by the STIX malware type(s) from TRIAGE. Adding a malware
// family means adding a Playbook entry — the INVESTIGATE loop never changes.
package playbook

import "strings"

// Objective is one work item the INVESTIGATE loop drives toward.
type Objective struct {
	ID   string // short handle, e.g. "encryption-scheme"
	Desc string // what to establish
}

// Playbook bundles objectives, a toolset bias (prose hint injected into the
// prompt), and the report sections the draft should assemble.
type Playbook struct {
	Name       string
	STIXTypes  []string // types that select this playbook (malware playbooks)
	vuln       bool     // mode-selected vuln playbook (skipped by SelectByTypes)
	Objectives []Objective
	ToolBias   string // prose hint on which tools/paths to favor
	// AndroidBias replaces ToolBias on APK projects. ToolBias names native
	// tools (get_strings, get_imports, Win32 APIs) an APK project doesn't have.
	AndroidBias string
	Sections    []Section // report template
}

// Section is one templated report section (id + title + guidance for content).
type Section struct {
	ID    string
	Title string
	Guide string // what this section should contain
}

// Registry holds all playbooks + the mode-specific vuln playbooks.
var registry = []Playbook{ransomware, infostealer, ratBackdoor, generic, vulnNative, vulnScript, vulnAndroid}

// vulnPlaybooks maps a project kind to its vuln-research playbook. Vuln mode is
// selected by MODE + target kind, not by malware type — a native binary, a
// script package, and an APK each have a different bug surface.
var vulnPlaybooks = map[string]Playbook{
	"BIN":    vulnNative,
	"SCRIPT": vulnScript,
	"APK":    vulnAndroid,
}

// SelectByTypes returns playbooks matching the given STIX types, most-relevant
// first (a playbook matches if any of its STIXTypes is present). Falls back to
// the Generic playbook when nothing matches. On multi-label input, several may
// match — the caller merges them, most-confident-first.
func SelectByTypes(types []string) []Playbook {
	var out []Playbook
	seen := map[string]bool{}
	for _, t := range types {
		for _, pb := range registry {
			if pb.vuln {
				continue // vuln playbooks are mode-selected, not type-selected
			}
			if seen[pb.Name] {
				continue
			}
			for _, st := range pb.STIXTypes {
				if strings.EqualFold(st, t) {
					out = append(out, pb)
					seen[pb.Name] = true
					break
				}
			}
		}
	}
	if len(out) == 0 {
		out = []Playbook{generic}
	}
	return out
}

// VulnPlaybookFor returns the vuln-research playbook for a project kind
// ("BIN"|"SCRIPT"|"APK"), falling back to the native memory-safety playbook for
// an unknown kind.
func VulnPlaybookFor(kind string) Playbook {
	if pb, ok := vulnPlaybooks[kind]; ok {
		return pb
	}
	return vulnNative
}

// All returns every registered playbook (for /playbooks display).
func All() []Playbook { return registry }

// --- the starters ---------------------------------------------------------

var ransomware = Playbook{
	Name:        "Ransomware",
	STIXTypes:   []string{"ransomware", "wiper"},
	ToolBias:    "Favor: get_strings for ransom-note text and file extensions; search for crypto constants (AES S-box, RSA, ChaCha), file enumeration APIs (FindFirstFile/opendir), and vssadmin/wbadmin shadow-copy deletion; get_function on the encryption routine and key handling.",
	AndroidBias: "Favor (Android): get_manifest for DEVICE_ADMIN / BIND_ACCESSIBILITY_SERVICE / SYSTEM_ALERT_WINDOW (lockers) and storage permissions; search for Cipher.getInstance, SecretKeySpec, file walks over Environment.getExternalStorageDirectory / MediaStore, DevicePolicyManager.lockNow / resetPassword, full-screen overlay activities, and ransom-note text in res/values/strings.xml or layouts.",
	Objectives: []Objective{
		{"crypto-keygen", "Identify the encryption algorithm and key generation / exchange scheme"},
		{"file-enum-encrypt", "Locate the file-enumeration + encryption routine and what it targets"},
		{"ransom-note", "Find the ransom note text and dropped-file names"},
		{"extension-rewrite", "Determine the appended/rewritten file extension"},
		{"shadow-copy", "Check for shadow-copy / backup deletion (vssadmin, wbadmin, bcdedit)"},
		{"c2-killswitch", "Look for C2 key exchange and any kill-switch"},
	},
	Sections: []Section{
		{"encryption-scheme", "Encryption Scheme", "Algorithm(s), key generation/exchange, mode, and IV handling."},
		{"targeted-files", "Targeted Files", "Which files/extensions are enumerated and encrypted; exclusions."},
		{"recovery-outlook", "Recovery Outlook", "Whether decryption without the key is feasible; shadow-copy status."},
		{"iocs", "IOCs", "Ransom note names, extension, C2, mutexes, dropped paths."},
	},
}

var infostealer = Playbook{
	Name:        "Infostealer",
	STIXTypes:   []string{"spyware", "keylogger", "screen-capture"},
	ToolBias:    "Favor: get_strings for browser/credential paths (Login Data, cookies, Local State), crypto-wallet paths, and exfil endpoints (http, Telegram bot API, Discord webhooks); search for keylogging (SetWindowsHookEx, GetAsyncKeyState) and screenshot APIs.",
	AndroidBias: "Favor (Android): get_manifest for READ_SMS/RECEIVE_SMS, READ_CONTACTS, READ_CALL_LOG, accessibility and notification-listener services (credential and OTP capture), overlay (SYSTEM_ALERT_WINDOW) and QUERY_ALL_PACKAGES (target-app lists); search for SmsManager, ContentResolver queries on content://sms / contacts, AccessibilityEvent text capture, getInstalledPackages, clipboard listeners, WebView overlay injection, and exfil endpoints (http(s)://, Telegram bot API, Firebase).",
	Objectives: []Objective{
		{"browser-creds", "Identify targeted browsers and credential/cookie paths"},
		{"wallets", "Find crypto-wallet paths and targeted apps"},
		{"keylog-screenshot", "Detect keylogging and screenshot capability"},
		{"exfil-channel", "Determine the exfiltration channel (HTTP / Telegram / Discord / FTP)"},
		{"persistence", "Establish persistence mechanism"},
	},
	Sections: []Section{
		{"stolen-data", "Stolen Data Types", "Categories of data collected (credentials, cookies, wallets, keystrokes, screenshots)."},
		{"exfil-destinations", "Exfiltration Destinations", "Where and how data is sent."},
		{"persistence", "Persistence", "How the sample maintains presence."},
		{"iocs", "IOCs", "Exfil endpoints, tokens, targeted paths, mutexes."},
	},
}

var ratBackdoor = Playbook{
	Name:        "RAT / Backdoor",
	STIXTypes:   []string{"remote-access-trojan", "backdoor", "bot"},
	ToolBias:    "Favor: search for the command dispatch table (large switch/if-else on a command id or string), C2 protocol handling (socket/send/recv, HTTP beaconing), and persistence; get_function on the command handler.",
	AndroidBias: "Favor (Android): trace from BOOT_COMPLETED receivers and foreground/persistent services to the C2 client; search for the command dispatcher (switch on a command string/id), sockets / OkHttp / WebSocket / Firebase Cloud Messaging handlers, Runtime.exec, DexClassLoader / InMemoryDexClassLoader (payload loading), MediaRecorder / Camera / location capture, and accessibility-driven remote control (dispatchGesture, performGlobalAction).",
	Objectives: []Objective{
		{"c2-protocol", "Determine the C2 protocol and beacon format"},
		{"command-dispatch", "Map the command dispatch table (supported commands)"},
		{"persistence", "Establish persistence mechanism"},
		{"capabilities", "Enumerate the capability surface (shell, file ops, upload/download, proxy)"},
	},
	Sections: []Section{
		{"c2", "Command & Control", "Protocol, endpoints, beacon interval, encryption of C2 traffic."},
		{"commands", "Supported Commands", "The command set the backdoor implements."},
		{"iocs", "IOCs", "C2 hosts/ports, user-agents, mutexes, install paths."},
	},
}

var generic = Playbook{
	Name:        "Generic Malware",
	STIXTypes:   []string{"trojan", "dropper", "downloader", "adware", "rootkit", "bootkit", "webshell", "virus", "worm", "unknown"},
	ToolBias:    "Broad sweep: get_metadata, get_imports for capability hints, get_strings for URLs/paths/commands, search for persistence and anti-analysis; get_function on entry points and any suspicious routine.",
	AndroidBias: "Broad sweep (Android): get_metadata and get_manifest for permissions and entry components; search for URLs/hosts, DexClassLoader / reflection-based loading of assets (droppers), PackageInstaller / REQUEST_INSTALL_PACKAGES, AccessibilityService, SmsManager, Runtime.exec, root checks and emulator/anti-analysis checks (Build.FINGERPRINT, ro.kernel.qemu, Debug.isDebuggerConnected); read the Application class and launcher activity first.",
	Objectives: []Objective{
		{"persistence", "Establish persistence mechanism(s)"},
		{"c2-network", "Identify C2 / network endpoints"},
		{"capabilities", "Enumerate capabilities"},
		{"anti-analysis", "Detect anti-analysis / evasion (anti-debug, anti-VM, packing)"},
	},
	Sections: []Section{
		{"overview", "Overview", "What the sample is and does, at a glance."},
		{"capabilities", "Capabilities", "What the sample can do."},
		{"persistence", "Persistence", "How it maintains presence."},
		{"iocs", "IOCs", "Network endpoints, files, registry, mutexes."},
	},
}

// --- vuln playbooks (mode-selected, one per target kind) ------------------

var vulnNative = Playbook{
	Name:     "Vuln — Native Binary",
	vuln:     true,
	ToolBias: "Favor: get_imports for memory-unsafe sinks (strcpy/strcat/sprintf/gets/memcpy/alloca) and command/exec sinks (system/popen/exec*); search decompiled code for unchecked lengths, signed/unsigned mixups, and format strings passed a non-literal; get_function on input parsers and any function handling untrusted data; use the `reachability` tool to prove a sink is reachable from an export/entry (attacker surface) and get the source→sink path.",
	Objectives: []Objective{
		{"attack-surface", "Map the attacker-controllable entry surface (exports, entry points, parsers of external input)"},
		{"memory-sinks", "Identify memory-unsafe sinks (overflow: CWE-787/121/122, OOB read: CWE-125)"},
		{"other-sinks", "Identify other dangerous sinks: integer overflow (CWE-190), format string (CWE-134), command exec (CWE-78), UAF/double-free (CWE-416/415)"},
		{"reachability", "For each candidate sink, use `reachability` to establish a source→sink path from the attack surface"},
		{"exploitability", "Assess whether attacker-controlled data actually flows to each reachable sink and whether size/values are controllable"},
	},
	Sections: []Section{
		{"summary", "Summary", "The bugs found, their CWE + severity, and the overall exploitability posture."},
		{"attack-surface", "Attack Surface", "Where untrusted input enters (exports/entry points/parsers)."},
		{"findings", "Vulnerabilities", "Per bug: CWE, severity, the vulnerable function + line/logic, the source→sink path (cite `reachability`), and why the input is attacker-controlled."},
		{"exploitability", "Exploitability", "For each finding: reachable? controllable? mitigations present (stack canaries, NX, ASLR, RELRO)? Honest assessment, no overclaiming."},
	},
}

var vulnScript = Playbook{
	Name:     "Vuln — Script / Package",
	vuln:     true,
	ToolBias: "Favor: list_files to map the package, read_file on entry points and anything handling input; search for injection sinks (eval/exec/child_process/os.system/subprocess with shell=True, SQL string-concatenation), unsafe deserialization (pickle.loads/yaml.load/Marshal/node-serialize), path traversal (unsanitized path joins, ../), SSRF (requests/fetch/axios to user URLs), and hardcoded secrets/tokens. Note install-time hooks (npm preinstall/postinstall, setup.py) as supply-chain risk.",
	Objectives: []Objective{
		{"input-surface", "Identify where external/untrusted input enters (args, HTTP handlers, file/stdin, package consumers)"},
		{"injection", "Find injection sinks: command (CWE-78), code/eval (CWE-95), SQL (CWE-89)"},
		{"deserialization-traversal", "Find unsafe deserialization (CWE-502), path traversal (CWE-22), SSRF (CWE-918)"},
		{"secrets-supplychain", "Find hardcoded secrets (CWE-798) and install-time/supply-chain hooks"},
		{"exploitability", "Trace whether untrusted input reaches each sink and under what conditions"},
	},
	Sections: []Section{
		{"summary", "Summary", "The vulnerabilities found, CWE + severity, and overall risk."},
		{"input-surface", "Input Surface", "How untrusted data enters the code."},
		{"findings", "Vulnerabilities", "Per bug: CWE, severity, file:function, the tainted source→sink flow (quote the code), and trigger conditions."},
		{"exploitability", "Exploitability & Supply-chain", "Reachability of each sink; any install-time execution or typosquat/supply-chain concern."},
	},
}

var vulnAndroid = Playbook{
	Name:     "Vuln — Android (APK)",
	vuln:     true,
	ToolBias: "Favor: get_manifest exported_only=true for the cross-app attack surface (exported components, guarding permissions, intent filters, provider authorities), then read_file on each handler; find_usages to follow intent extras to sinks; search for exported Activities/Services/Receivers/Providers reachable without permission, intent handling that trusts extras, insecure crypto (ECB, hardcoded keys/IVs, static seeds), insecure storage (world-readable files, plaintext prefs), WebView misuse (setJavaScriptEnabled + addJavascriptInterface, loadUrl with untrusted input), and hardcoded secrets/API keys.",
	Objectives: []Objective{
		{"exported-components", "Enumerate exported components and whether they're reachable by other apps without permission (CWE-926)"},
		{"intent-handling", "Assess intent/extras handling for injection or privilege issues (CWE-927), including PendingIntent misuse"},
		{"crypto-storage", "Find insecure crypto (CWE-327) and insecure data storage (CWE-312/922)"},
		{"webview-secrets", "Find WebView/JS-bridge issues (CWE-749) and hardcoded secrets/keys (CWE-798)"},
		{"exploitability", "Determine which issues are remotely/locally reachable and what an attacker gains"},
	},
	Sections: []Section{
		{"summary", "Summary", "The vulnerabilities found, CWE + severity, and overall risk."},
		{"attack-surface", "Attack Surface", "Exported components, permissions, and how another app / remote input reaches them."},
		{"findings", "Vulnerabilities", "Per bug: CWE, severity, component/file, the code path, and how it's reached."},
		{"exploitability", "Exploitability", "Reachability of each issue (cross-app, remote, local) and impact; honest assessment."},
	},
}

// BiasFor returns the tool-bias hint for a project kind: AndroidBias on APK
// projects when the playbook has one, ToolBias otherwise.
func (p Playbook) BiasFor(kind string) string {
	if kind == "APK" && p.AndroidBias != "" {
		return p.AndroidBias
	}
	return p.ToolBias
}

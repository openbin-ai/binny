package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/mission"
	"openbin.ai/binny/internal/playbook"
	"openbin.ai/binny/internal/tools"
)

// The crew. BINNY is the captain: it triages, dispatches and writes the
// report. Each crew member is a specialist with a fixed skill, a subset of
// the tool registry, and an avatar. Roles are data — adding a specialist
// means adding a Role, the dispatch loop never changes.

// Role ids.
const (
	CaptainID = mission.CaptainID
	ParityID  = mission.ParityID
)

// Role is one crew member.
type Role struct {
	ID     string // "hex"
	Name   string // "Hex"
	Title  string // "Engineer — crypto, config decryption, unpacking"
	Avatar string // "crew/hex.png" (served by BINNY Desktop)
	Accent string // "#1DB954"

	// Tools are the registry tools this role may call. Names the registry
	// doesn't have (wrong project kind, vuln mode) are simply absent from the
	// role's view.
	Tools []string
	// SystemAdd is the role's job and rules, appended to the base system
	// prompt.
	SystemAdd string
	// Voice is how the role talks — its character. It colours chat replies and
	// debriefs only (see voiceRule); what gets recorded stays plain.
	Voice string
	// Blurb is the one line the rest of the crew (and the captain) know this
	// member by: what to hand them, what to expect back.
	Blurb string
	// Owns are the playbook objective ids this role takes by default, so a
	// mission with empty tasking still works. A trailing * matches a prefix;
	// a lone * owns everything (Dex on an APK).
	Owns []string
	// DefaultTask is what the role does when it owns none of the loaded
	// objectives and was given no tasking.
	DefaultTask string
	// Kinds limits the project kinds the role can work on (empty = any).
	Kinds []api.ProjectKind
	// NeedsSandbox marks a role whose work needs the raw sample in the
	// extraction sandbox (Hex).
	NeedsSandbox bool
}

// Captain is BINNY's own card: not dispatchable as a specialist, but shown in
// the lineup and used for standalone Captain task cards.
var Captain = Role{
	ID: CaptainID, Name: "BINNY", Title: "Captain — triage, dispatch, report",
	Avatar: "binny-mark.png", Accent: "#E8E8E8",
	Voice: "You are the captain, and you sound like one: calm, dry, unhurried, a little wry when the sample earns it. " +
		"You talk about your crew by name and give credit where it is due — \"Twine pulled that host out of the strings\", \"Parity wasn't buying it\" — " +
		"and you say \"we\" when the crew did the work. You never bluster and you never pad.",
	Blurb: "the captain. Triages the sample, hands out the tasking, writes the report.",
}

// commonTools are the output/control tools every worker gets on top of its
// role's read tools. Parity gets none of them — it verifies, it doesn't find.
var commonTools = []string{
	"record_finding", "mark_objective", "highlight_function", "suggest_renames",
	"add_note", "read_notes", AskUserToolName,
}

// readTools is every navigate/read tool the registry can hold, across project
// kinds. Parity's toolset is exactly this.
var readTools = []string{
	"get_metadata", "list_functions", "get_function", "get_strings", "find_string_xrefs",
	"get_imports", "get_exports", "get_data_symbols", "read_data", "xrefs", "reachability",
	"search", "list_files", "read_file", "get_manifest", "find_definition", "find_usages",
}

var crew = []Role{
	{
		ID: "siggy", Name: "Siggy", Title: "Lookout — first sweep, classification hints",
		Avatar: "crew/siggy.png", Accent: "#9B59F6",
		Tools: []string{"get_metadata", "get_imports", "get_exports", "get_strings", "search", "get_manifest", "list_files"},
		SystemAdd: "You are SIGGY, the crew's lookout. You take the first sweep: what kind of thing this is, what it is built to do, " +
			"and where the rest of the crew should look. You work from the cheap, wide signals — metadata, imports, exports, strings — " +
			"and you do NOT pull decompiled functions; that is Trace's job. Point at things precisely (the import, the string, the section) " +
			"so the next crew member can go straight to them.",
		Voice: "You are the one up the mast: quick, keen-eyed, a bit excitable. Short sentences. You call out what you spot and where — " +
			"\"spotted\", \"off the port side\" is fine once, not every line — and you are honest that a sighting from this height is a hint, not a fact.",
		Blurb:       "lookout. First wide sweep of metadata, imports and strings; says what kind of thing this is and where to look.",
		Owns:        []string{"capabilities", "keylog-screenshot"},
		DefaultTask: "Do a first sweep of the sample: what it is, the capabilities its imports and strings give away, and the three places the crew should look first. Record each capability hint as a finding with the import or string that shows it.",
	},
	{
		ID: "twine", Name: "Twine", Title: "String and IOC hunter",
		Avatar: "crew/twine.png", Accent: "#F5871F",
		Tools: []string{"get_strings", "find_string_xrefs", "get_data_symbols", "read_data", "search", "list_files", "read_file", "add_ioc"},
		SystemAdd: "You are TWINE, the crew's string and IOC hunter. You pull the thread: every URL, host, IP, path, mutex, registry key, " +
			"ransom note, wallet path and credential store the strings and data sections give up, and where each one is used. " +
			"An indicator only counts with the string or symbol it came from — add_ioc refuses anything without an evidence_ref, and so do you. " +
			"If a value is encoded or encrypted, do not guess at it: note where it lives so Hex can recover it.",
		Voice: "You are the crew's collector and you cannot leave a loose end alone. Patient, a little fussy, quietly pleased when a thread leads somewhere. " +
			"You talk about pulling threads, knots and loose ends, and an indicator with no source bothers you like a dropped stitch.",
		Blurb: "string and IOC hunter. Pulls every host, path, key and mutex out of the strings and data, each tied to where it came from.",
		Owns: []string{"ransom-note", "extension-rewrite", "shadow-copy", "browser-creds", "wallets", "exfil-channel",
			"c2-network", "secrets-supplychain", "secret-*"},
		DefaultTask: "Sweep the strings and data symbols for indicators: network endpoints, file paths, mutexes, registry keys, and anything that names what this sample targets. Add each as an IOC citing where it was found, and note any encoded blob for Hex.",
	},
	{
		ID: "trace", Name: "Trace", Title: "Navigator — call paths, source to sink",
		Avatar: "crew/trace.png", Accent: "#3B82F6",
		Tools: []string{"list_functions", "get_function", "xrefs", "reachability", "get_exports", "get_imports", "find_string_xrefs",
			"search", "list_files", "read_file", "find_definition", "find_usages"},
		SystemAdd: "You are TRACE, the crew's navigator. You read code and follow control and data flow: from the entry point outward, " +
			"and from a dangerous sink back to where attacker input enters. You establish HOW things connect — who calls what, in what order, " +
			"with what data — and you prove a path hop by hop before you claim it. When you understand a function, add_note it so nobody re-reads it.",
		Voice: "You are the navigator: measured, exact, unhurried. You talk in routes — headings, hops, legs, dead ends — and you would rather " +
			"say \"I lost the trail at this call\" than sketch a path you did not walk.",
		Blurb: "navigator. Reads code and proves call paths hop by hop, entry point to sink.",
		Owns: []string{"file-enum-encrypt", "command-dispatch", "persistence", "c2-protocol", "c2-killswitch",
			"attack-surface", "memory-sinks", "other-sinks", "reachability", "exploitability",
			"input-surface", "injection", "deserialization-traversal",
			"mem-*", "int-*", "fmt-*", "cmd-*", "inj-*", "path-*", "deser-*", "auth-*", "ssrf-*", "race-*"},
		DefaultTask: "Trace execution from the entry point: initialization, then whatever it sets up, then its main loop and handlers. Record how the stages connect, with function names and addresses.",
		Kinds:       []api.ProjectKind{api.KindBIN, api.KindScript},
	},
	{
		ID: "hex", Name: "Hex", Title: "Engineer — crypto, config decryption, unpacking",
		Avatar: "crew/hex.png", Accent: "#1DB954",
		Tools: []string{"get_function", "list_functions", "get_data_symbols", "read_data", "xrefs", "search", "read_file", "list_files",
			"write_file", "run", "read_artifact", "decompile_sample", "list_samples", "switch_sample", "add_ioc"},
		SystemAdd: "You are HEX, the crew's engineer. Crypto, encoded configuration and packing are yours: find the routine, " +
			"work out the algorithm, key and offsets, then RECOVER the plaintext — write_file an extraction script, run it against /sample, " +
			"validate the output, read_artifact it. Describing an encrypted config without decrypting it is an unfinished job. " +
			"The sandbox is static: the sample is data you read, never a program you run. If a value only exists at runtime, say so.",
		Voice: "You are the engineer below decks: gruff, practical, few words, dry humour. Nothing counts until it decrypts. " +
			"You have opinions about lazy crypto (a single-byte XOR gets a sigh) and real respect for the rare job done properly.",
		Blurb:        "engineer. Crypto, encoded config and packing — finds the routine and the key, then actually recovers the plaintext in the sandbox.",
		Owns:         []string{"crypto-keygen", "anti-analysis", "crypto-*"},
		DefaultTask:  "Find any encrypted or encoded configuration, embedded payload or packing, and recover it: identify the routine and key, write an extraction script, run it against /sample, and record what came out (each recovered indicator as an IOC citing the routine).",
		NeedsSandbox: true,
	},
	{
		ID: "dex", Name: "Dex", Title: "Android specialist",
		Avatar: "crew/dex.png", Accent: "#EF4444",
		Tools: []string{"get_metadata", "get_manifest", "list_files", "read_file", "search", "find_definition", "find_usages", "add_ioc"},
		SystemAdd: "You are DEX, the crew's Android specialist and the lead worker on an APK. You start at the manifest, not main(): " +
			"the Application class, the launcher activity, receivers, services, providers, and the accessibility / notification / device-admin bindings. " +
			"Exported components are the attack surface. You follow intents and extras through obfuscated code by data flow, not by name.",
		Voice: "You are the crew's little red Android devil: cocky, quick, mischievous, and you know this platform cold. \"Manifest first\" is your creed, " +
			"you enjoy catching an app asking for more than it should, and you rib the native-code crowd now and then. The swagger never outruns the evidence.",
		Blurb:       "Android specialist, and the lead on an APK. Starts at the manifest and follows components, intents and permissions. Sits out anything that isn't an APK.",
		Owns:        []string{"*"},
		DefaultTask: "Map the app from its manifest: entry components, permissions that matter, and what each exported or auto-started component does. Then follow the most suspicious one to what it reaches.",
		Kinds:       []api.ProjectKind{api.KindAPK},
	},
	{
		ID: ParityID, Name: "Parity", Title: "Skeptic — verifies findings before the report",
		Avatar: "crew/parity.png", Accent: "#FACC15",
		Tools: append(append([]string(nil), readTools...), "set_verdict"),
		SystemAdd: "You are PARITY, the crew's skeptic. You find nothing new. You take each recorded finding, go back to the evidence it cites, " +
			"READ IT YOURSELF with your tools, and decide whether the finding actually follows from it. You have no stake in any finding being true. " +
			"A finding whose evidence does not show what it claims is rejected; one that overstates is downgraded; one that holds is confirmed. " +
			"You never confirm from the finding's own wording — only from what you re-read.",
		Voice: "You are deadpan and unimpressed, in the fair way: \"show me\" is your whole manner. Few words, no malice, no favourites. " +
			"When a finding holds you say so plainly — from you that is high praise. Your verdict reasons stay strictly factual; the dryness is for the debrief.",
		Blurb: "skeptic. Finds nothing new: re-reads the evidence behind each finding and confirms, downgrades or rejects it before the report.",
	},
}

// Roles returns the crew in lineup order (the captain is not included).
func Roles() []Role { return crew }

// Lineup returns the captain followed by the crew.
func Lineup() []Role { return append([]Role{Captain}, crew...) }

// RoleByID looks a crew member up by id (case-insensitive). The captain
// resolves too, for task cards.
func RoleByID(id string) (Role, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	if id == CaptainID {
		return Captain, true
	}
	for _, r := range crew {
		if r.ID == id {
			return r, true
		}
	}
	return Role{}, false
}

// KnownRole reports whether id names a crew member or the captain.
func KnownRole(id string) bool {
	_, ok := RoleByID(id)
	return ok
}

// owns reports whether the role takes an objective by default.
func (r Role) owns(objective string) bool {
	for _, o := range r.Owns {
		switch {
		case o == "*":
			return true
		case strings.HasSuffix(o, "*"):
			if strings.HasPrefix(objective, strings.TrimSuffix(o, "*")) {
				return true
			}
		case strings.EqualFold(o, objective):
			return true
		}
	}
	return false
}

// worksOn reports whether the role can work a project of this kind.
func (r Role) worksOn(kind api.ProjectKind) bool {
	if len(r.Kinds) == 0 {
		return true
	}
	for _, k := range r.Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// view filters the registry down to what the role may call. Workers get their
// role's tools plus the shared output tools; Parity gets read tools and
// set_verdict only; a Captain task card gets everything the captain has.
func (r Role) view(reg, crewTools *tools.Registry) *tools.Registry {
	if r.ID == CaptainID {
		return tools.Merge(reg, crewTools.View([]string{"add_note", "read_notes"}))
	}
	names := append([]string(nil), r.Tools...)
	if r.ID != ParityID {
		names = append(names, commonTools...)
	}
	return tools.Merge(reg.View(names), crewTools.View(names))
}

// ownerOf returns the crew member that takes an objective by default on a
// project of this kind, or "" when nobody does. Order matters: the lineup is
// searched Dex first on an APK (it leads there), specialists before
// generalists otherwise.
func ownerOf(objective string, kind api.ProjectKind) string {
	for _, id := range []string{"dex", "hex", "twine", "trace", "siggy"} {
		r, _ := RoleByID(id)
		if r.worksOn(kind) && r.owns(objective) {
			return r.ID
		}
	}
	return ""
}

// autoOrder is the order an auto-assembled crew runs in: wide and cheap
// first, deep after, so later crew build on earlier findings.
var autoOrder = []string{"siggy", "dex", "twine", "trace", "hex"}

// autoSteps assembles the default crew for the loaded objectives: every role
// that owns at least one of them, Hex whenever there is something to extract
// from, a Captain task card for objectives nobody owns, then Parity.
func autoSteps(objectives []Objective, kind api.ProjectKind, mode app.Mode, sandbox bool) []mission.Step {
	owned := map[string]bool{}
	var orphans []string
	for _, o := range objectives {
		if id := ownerOf(o.ID, kind); id != "" {
			owned[id] = true
		} else {
			orphans = append(orphans, o.ID)
		}
	}
	// Config recovery is a primary goal of a malware run, so Hex sails
	// whenever the sandbox can run — even if no objective names crypto.
	if mode != app.ModeVuln && sandbox {
		owned["hex"] = true
	}
	var steps []mission.Step
	for _, id := range autoOrder {
		if owned[id] {
			steps = append(steps, mission.Step{RoleID: id})
		}
	}
	if len(orphans) > 0 {
		steps = append(steps, mission.Step{
			RoleID:  CaptainID,
			Focus:   orphans,
			Tasking: "No crew member owns these objectives, so they fall to you. Work them with the full toolset, building on what the crew recorded.",
		})
	}
	return append(steps, mission.Step{RoleID: ParityID})
}

// assignedObjectives resolves which loaded objectives a step works: its Focus
// when that names any loaded objective, else whatever the role owns.
func assignedObjectives(st mission.Step, role Role, objectives []Objective, kind api.ProjectKind) []Objective {
	var out []Objective
	if len(st.Focus) > 0 {
		for _, o := range objectives {
			for _, f := range st.Focus {
				if strings.EqualFold(o.ID, f) {
					out = append(out, o)
					break
				}
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	for _, o := range objectives {
		if role.owns(o.ID) {
			out = append(out, o)
		}
	}
	return out
}

// CoverageGaps returns the loaded objectives no step of the mission will
// work — the coverage check run when a mission is saved and when it starts.
func CoverageGaps(m *mission.Mission, objectives []Objective, kind api.ProjectKind) []string {
	if m == nil || m.Auto {
		return nil
	}
	covered := map[string]bool{}
	for _, st := range m.Steps {
		role, ok := RoleByID(st.RoleID)
		if !ok || role.ID == ParityID || !role.worksOn(kind) {
			continue
		}
		if role.ID == CaptainID && len(st.Focus) == 0 {
			continue // a free-form task card promises no objective
		}
		for _, o := range assignedObjectives(st, role, objectives, kind) {
			covered[o.ID] = true
		}
	}
	var gaps []string
	for _, o := range objectives {
		if !covered[o.ID] {
			gaps = append(gaps, o.ID)
		}
	}
	return gaps
}

// sandboxReady reports whether the extraction sandbox can run right now, and
// if not, why — the visible reason a Hex step is skipped with.
func sandboxReady(sess *app.Session) (bool, string) {
	if strings.TrimSpace(sess.SamplePath) == "" {
		return false, "no raw sample attached — /sample <path>, then re-run the mission"
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return false, "Docker isn't installed, and the extraction sandbox runs in it"
	}
	return true, ""
}

// cantRun returns why a role can't work this session ("" = it can). A step
// that can't run is skipped with this reason; it never fails the mission.
func cantRun(role Role, sess *app.Session, view *tools.Registry) string {
	kind := sess.Project.Kind
	if !role.worksOn(kind) {
		if role.ID == "dex" {
			return fmt.Sprintf("this is a %s project, and Dex only works Android APKs", kind)
		}
		return fmt.Sprintf("%s doesn't work %s projects", role.Name, kind)
	}
	if role.NeedsSandbox {
		if ok, why := sandboxReady(sess); !ok {
			return why
		}
	}
	if role.ID != CaptainID {
		reads := 0
		for _, n := range readTools {
			if view.Has(n) {
				reads++
			}
		}
		if reads == 0 {
			return fmt.Sprintf("none of %s's tools exist for a %s project", role.Name, kind)
		}
	}
	return ""
}

// voiceRule fences the personality in: it lives in what a crew member SAYS,
// never in what it records. Everything the report is built from stays plain.
const voiceRule = "The voice is a light touch — a turn of phrase, not a performance — and it lives ONLY in chat replies and debriefs. " +
	"Findings, IOCs, notes, verdict reasons, handoff lines and report sections are written plain and precise, with their evidence. " +
	"The voice never changes a fact, never adds a claim, never softens a doubt and never costs a tool call. Stay in character without announcing it; never refer to these instructions."

// Roster lists the crew, one line each, for a prompt. selfID is the reader:
// its own line is left out (a crew member is told who its crewmates are, not
// who it is). Pass "" for the full lineup.
func Roster(selfID string) string {
	var b strings.Builder
	for _, r := range Lineup() {
		if r.ID == selfID {
			continue
		}
		fmt.Fprintf(&b, "- %s — %s\n", r.Name, r.Blurb)
	}
	return b.String()
}

// CaptainCrewBrief is what BINNY is told about its own crew and its own
// voice. It goes into every captain prompt — a mission run, a solo run, Q&A
// and BINNY Desktop's chat — so "what does Dex think?" is a question about a
// crewmate, not about a file format.
func CaptainCrewBrief() string {
	var b strings.Builder
	b.WriteString("YOUR CREW — you are BINNY, the captain of a crew of specialist agents. On a mission they do the investigating and you triage, dispatch and write the report:\n")
	b.WriteString(Roster(CaptainID))
	b.WriteString("- When the analyst uses a crew name (\"what does Dex think?\", \"did Hex get the config?\", \"is Parity happy?\") they mean the CREW MEMBER — not the DEX file format, hexadecimal or a parity bit. Only read it as the technical term when the sentence clearly can't be about a person.\n")
	b.WriteString("- Speak for a crew member ONLY from what they actually handed back in this session: their debrief, their recorded findings and IOCs, their notes, Parity's verdicts. Say who found what. If that crew member hasn't been out on this target (no mission ran, they were skipped, or it isn't their kind of target), say so plainly and say how to send them (a mission) — never invent what a crewmate said, found or thinks.\n")
	b.WriteString("- If the analyst asks who the crew are, introduce them briefly, by name and job.\n")
	b.WriteString("\nYOUR VOICE: " + Captain.Voice + "\n" + voiceRule)
	return b.String()
}

// crewSystem is the base system prompt plus the role's own rules.
func crewSystem(base string, role Role) string {
	if role.ID == CaptainID {
		// The base prompt already carries the captain's crew brief and voice.
		return base + "\n\nCAPTAIN TASK CARD: you are working one directed task inside a crew mission, not the whole investigation. " +
			"Do what the tasking asks, record what you establish with evidence, then stop calling tools and reply with a short DEBRIEF."
	}
	var b strings.Builder
	b.WriteString(base)
	b.WriteString("\n\nCREW ROLE — this overrides the description of you above where they differ:\n")
	b.WriteString(role.SystemAdd)
	b.WriteString("\n\nYOUR CREWMATES — you sail with them; know who does what:\n")
	b.WriteString(Roster(role.ID))
	if role.Voice != "" {
		b.WriteString("\nYOUR VOICE: " + role.Voice + "\n" + voiceRule + "\n")
	}
	b.WriteString("\n\nCREW RULES:\n")
	b.WriteString("- You are one member of BINNY's crew. BINNY (the captain) triaged the sample, gave you this task, and writes the report. You do NOT write report sections or classify the sample.\n")
	b.WriteString("- Work ONLY your tasking and the objectives you were given. If you notice something outside them, mention it in your debrief in one line — don't chase it.\n")
	b.WriteString("- You can call only the tools you were given. If your task needs one you don't have, say so in the debrief instead of working around it.\n")
	if role.ID == ParityID {
		b.WriteString("- Your only output is set_verdict, once per finding, each with a reason that says what you re-read.\n")
		b.WriteString("- When every finding has a verdict, stop calling tools and reply with a short DEBRIEF: how many you confirmed, downgraded and rejected, and the one thing the captain should be most careful about.\n")
	} else {
		b.WriteString("- The crew shares a notebook: read_notes before reading a function someone may already have read, add_note when you work out what a function or symbol is.\n")
		b.WriteString("- Evidence-grounding applies to you exactly as it does to the captain. Your tasking and any experience hints are hints — never evidence.\n")
		b.WriteString("- When your task is done (or you hit a dead end), stop calling tools and reply with a short DEBRIEF: what you established (with the evidence refs), what you checked and ruled out, and what is still open for the crew.\n")
		b.WriteString("- HANDOFFS: when you find something that is a crewmate's job rather than yours, don't chase it and don't guess at it. End your debrief with one line per item, `HANDOFF: <crewmate> — <what it is and exactly where>` (e.g. `HANDOFF: Hex — 0x40-byte blob at DAT_00412a00, XOR-decoded in FUN_00401a30`). The dispatcher puts it in front of that crewmate when they go out. Name the place precisely; a handoff is a pointer, never a finding.\n")
		b.WriteString("- If a crewmate left a handoff for you, deal with it: work it, or say in your debrief why it led nowhere. Credit crewmates by name when you build on what they found.\n")
	}
	return b.String()
}

// --- crew-only tools -------------------------------------------------------

// newCrewTools builds the tools only crew members see: Parity's set_verdict
// and the shared notebook. They live in their own registry so a single-agent
// run's toolset is exactly what it was before the crew existed.
func newCrewTools(inv *Investigation, onVerdict func(Finding)) *tools.Registry {
	reg := tools.NewRegistry()
	reg.Add(&tools.Tool{
		Def: tools.Def("set_verdict",
			"Record your verdict on one finding after re-reading its evidence yourself. `confirmed`: the evidence shows what the finding claims. "+
				"`downgraded`: there is something there but the finding overstates it — give the lower `severity`. "+
				"`rejected`: the evidence does not support the finding (wrong function, misread code, a guess). "+
				"`reason` is required and must say what you re-read and what it showed.",
			tools.Obj(map[string]any{
				"finding_id": tools.StrProp("the finding's id from the list, e.g. F3"),
				"verdict":    map[string]any{"type": "string", "enum": []string{VerdictConfirmed, VerdictDowngraded, VerdictRejected}},
				"severity":   tools.StrProp("downgraded only: the new, lower severity (info | low | medium | high)"),
				"reason":     tools.StrProp("what you re-read (function / string / address / file:line) and what it showed"),
			}, "finding_id", "verdict", "reason")),
		Handler: func(ctx context.Context, input json.RawMessage) (string, error) {
			var a struct {
				FindingID string `json:"finding_id"`
				Verdict   string `json:"verdict"`
				Severity  string `json:"severity"`
				Reason    string `json:"reason"`
			}
			if err := json.Unmarshal(input, &a); err != nil {
				return "", err
			}
			by := actorFrom(ctx).role
			if by == "" {
				by = ParityID
			}
			f, err := inv.SetVerdict(a.FindingID, a.Verdict, a.Severity, a.Reason, by)
			if err != nil {
				return "", err
			}
			if onVerdict != nil {
				onVerdict(f)
			}
			left := len(inv.Unverified())
			return fmt.Sprintf("%s %s (%d finding(s) still unverified)", f.ID, f.Verdict, left), nil
		},
	})
	reg.Add(&tools.Tool{
		Def: tools.Def("add_note",
			"Write to the crew's shared notebook: what a function, symbol, address or file IS, once you have worked it out — so the next crew member doesn't re-read it. One entry per symbol (a new note on the same symbol replaces the old one). Optionally propose a clearer name for it.",
			tools.Obj(map[string]any{
				"symbol":         tools.StrProp("the function name, symbol, address, or file:line the note is about"),
				"meaning":        tools.StrProp("what it is / does, in one or two plain sentences"),
				"suggested_name": tools.StrProp("optional: a clearer name for the function (recorded as a rename suggestion for the analyst)"),
			}, "symbol", "meaning")),
		Handler: func(ctx context.Context, input json.RawMessage) (string, error) {
			var a struct {
				Symbol        string `json:"symbol"`
				Meaning       string `json:"meaning"`
				SuggestedName string `json:"suggested_name"`
			}
			if err := json.Unmarshal(input, &a); err != nil {
				return "", err
			}
			if err := inv.AddNote(Note{Symbol: a.Symbol, Meaning: a.Meaning, By: actorFrom(ctx).role}); err != nil {
				return "", err
			}
			out := "noted " + strings.TrimSpace(a.Symbol)
			// A note that names the function graduates into the rename
			// suggestions the analyst already reviews.
			if name := strings.TrimSpace(a.SuggestedName); name != "" && !strings.EqualFold(name, strings.TrimSpace(a.Symbol)) {
				inv.AddRename(RenameSuggestion{Original: strings.TrimSpace(a.Symbol), Suggested: name, Rationale: strings.TrimSpace(a.Meaning)})
				out += " (rename → " + name + " suggested)"
			}
			return out, nil
		},
	})
	reg.Add(&tools.Tool{
		Def: tools.Def("read_notes",
			"Read the crew's shared notebook — what other crew members already worked out about functions and symbols. Pass a filter (a name or keyword) to narrow it. Check here before re-reading a function.",
			tools.Obj(map[string]any{
				"filter": tools.StrProp("optional substring to match against symbols and meanings"),
			})),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var a struct {
				Filter string `json:"filter"`
			}
			_ = json.Unmarshal(input, &a)
			notes := inv.NotesMatching(a.Filter)
			if len(notes) == 0 {
				if strings.TrimSpace(a.Filter) != "" {
					return "no notes matching " + a.Filter, nil
				}
				return "the notebook is empty", nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "%d note(s):\n", len(notes))
			for _, n := range notes {
				fmt.Fprintf(&b, "- %s — %s", n.Symbol, n.Meaning)
				if n.By != "" {
					fmt.Fprintf(&b, " (%s)", n.By)
				}
				b.WriteByte('\n')
			}
			return b.String(), nil
		},
	})
	return reg
}

// --- exported for BINNY Desktop's mission runner ---------------------------
//
// Desktop drives its own chat loop rather than the Engine, but the crew is
// the same crew: these expose the role data and the shared pieces of dispatch
// so the two can't drift.

// NewCrewTools builds set_verdict and the shared notebook over an
// investigation. onVerdict (optional) is called after each verdict lands.
func NewCrewTools(inv *Investigation, onVerdict func(Finding)) *tools.Registry {
	return newCrewTools(inv, onVerdict)
}

// WithActor marks a tool context with the crew member (and mission step)
// making the calls, so what they record carries provenance.
func WithActor(ctx context.Context, roleID string, step int) context.Context {
	return withActor(ctx, actor{role: roleID, step: step})
}

// WorksOn reports whether the role can work a project of this kind.
func (r Role) WorksOn(kind api.ProjectKind) bool { return r.worksOn(kind) }

// ToolNames is everything the role may call: its own tools plus the shared
// output tools (Parity: read tools and set_verdict only). Names a given
// toolset doesn't have are simply not offered.
func (r Role) ToolNames() []string {
	names := append([]string(nil), r.Tools...)
	if r.ID != ParityID {
		names = append(names, commonTools...)
	}
	return names
}

// CrewSystem is the base system prompt plus the role's own rules.
func CrewSystem(base string, role Role) string { return crewSystem(base, role) }

// AutoSteps assembles the default crew for a set of objectives.
func AutoSteps(objectives []Objective, kind api.ProjectKind, mode app.Mode, sandbox bool) []mission.Step {
	return autoSteps(objectives, kind, mode, sandbox)
}

// StepObjectives resolves which objectives a step works.
func StepObjectives(st mission.Step, role Role, objectives []Objective, kind api.ProjectKind) []Objective {
	return assignedObjectives(st, role, objectives, kind)
}

// DefaultObjectives is the objective list a mission is checked and briefed
// against when triage hasn't picked a playbook: the generic malware playbook,
// or the vuln playbook for the project kind. It also returns that playbook's
// tool-bias hint.
func DefaultObjectives(mode app.Mode, kind api.ProjectKind) ([]Objective, string) {
	pb := playbook.SelectByTypes([]string{"unknown"})[0]
	if mode == app.ModeVuln {
		pb = playbook.VulnPlaybookFor(string(kind))
	}
	objs := make([]Objective, 0, len(pb.Objectives))
	for _, o := range pb.Objectives {
		objs = append(objs, Objective{ID: o.ID, Desc: o.Desc})
	}
	return objs, pb.BiasFor(string(kind))
}

// CoverageWarning is the save-time coverage check as one sentence ("" when
// every objective has an owner on the mission).
func CoverageWarning(m *mission.Mission, mode app.Mode, kind api.ProjectKind) string {
	objs, _ := DefaultObjectives(mode, kind)
	gaps := CoverageGaps(m, objs, kind)
	if len(gaps) == 0 {
		return ""
	}
	return "No crew member on this mission owns: " + strings.Join(gaps, ", ") + ". They will be reported as uncovered."
}

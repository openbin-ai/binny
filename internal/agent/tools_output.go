package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/tools"
)

// AskUserToolName is intercepted by the loop (it suspends the turn and surfaces
// the question) rather than executed as a normal handler.
const AskUserToolName = "ask_user"

// registerOutputTools adds the Findings/Output, Highlights, and Control tools
// to the registry. They write to the shared Investigation; record_finding and
// add_ioc enforce evidence-grounding at write time.
//
// Vuln mode gets the structured vuln record_finding and no IOC/classification
// tools: those are malware-report concepts, and offering them pulls a
// vulnerability hunt toward malware triage.
func registerOutputTools(reg *tools.Registry, inv *Investigation, client *api.Client, project *api.Project, mode app.Mode) {
	if mode == app.ModeVuln {
		reg.Add(recordVulnFindingTool(inv))
	} else {
		reg.Add(recordFindingTool(inv))
		reg.Add(addIOCTool(inv))
		reg.Add(setClassificationTool(inv))
	}
	reg.Add(writeReportSectionTool(inv))
	reg.Add(markObjectiveTool(inv))
	reg.Add(highlightFunctionTool(inv, client, project))
	reg.Add(suggestRenamesTool(inv))
	reg.Add(askUserTool())
}

func recordFindingTool(inv *Investigation) *tools.Tool {
	return &tools.Tool{
		Def: tools.Def("record_finding",
			"Record an evidence-grounded finding. REQUIRED: at least one evidence_ref (a function name, string, address, or for APK/script projects a file:line). A finding with no evidence is refused — never record a claim you can't point to. For VULN findings, set `category` to the bug class (e.g. stack-overflow, use-after-free, command-injection) and `cwe` to the CWE id.",
			tools.Obj(map[string]any{
				"category":      tools.StrProp("malware: persistence, c2, crypto, anti-analysis, capability. vuln: the bug class, e.g. stack-overflow, integer-overflow, command-injection, path-traversal, insecure-deserialization"),
				"severity":      tools.StrProp("info | low | medium | high | critical"),
				"note":          tools.StrProp("what you found, in plain language (for vuln: the source→sink path and why it's controllable)"),
				"cwe":           tools.StrProp("optional CWE id for vuln findings, e.g. CWE-787, CWE-416, CWE-78"),
				"evidence_refs": tools.ArrProp("function names / strings / addresses (or file:line for APK/script projects) that ground this finding"),
			}, "category", "note", "evidence_refs")),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var a struct {
				Category     string   `json:"category"`
				Severity     string   `json:"severity"`
				Note         string   `json:"note"`
				CWE          string   `json:"cwe"`
				EvidenceRefs []string `json:"evidence_refs"`
			}
			if err := json.Unmarshal(input, &a); err != nil {
				return "", err
			}
			if a.Severity == "" {
				a.Severity = "info"
			}
			if err := inv.AddFinding(Finding{
				Category: a.Category, Severity: a.Severity, Note: a.Note, CWE: a.CWE, EvidenceRefs: a.EvidenceRefs,
			}); err != nil {
				return "", err
			}
			label := a.Category
			if a.CWE != "" {
				label += " " + a.CWE
			}
			return fmt.Sprintf("recorded finding [%s/%s]", label, a.Severity), nil
		},
	}
}

func addIOCTool(inv *Investigation) *tools.Tool {
	return &tools.Tool{
		Def: tools.Def("add_ioc",
			"Add an indicator of compromise. REQUIRED: an evidence_ref citing where it was found. An IOC with no evidence is refused — no hallucinated C2 / IOCs.",
			tools.Obj(map[string]any{
				"type":         tools.StrProp("ip | domain | url | hash | path | mutex | registry | email | port | other"),
				"value":        tools.StrProp("the indicator value"),
				"evidence_ref": tools.StrProp("the function/string/address where this was found"),
			}, "type", "value", "evidence_ref")),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var a struct{ Type, Value, EvidenceRef string }
			if err := json.Unmarshal(input, &struct {
				Type        *string `json:"type"`
				Value       *string `json:"value"`
				EvidenceRef *string `json:"evidence_ref"`
			}{&a.Type, &a.Value, &a.EvidenceRef}); err != nil {
				return "", err
			}
			if err := inv.AddIOC(IOC{Type: a.Type, Value: a.Value, EvidenceRef: a.EvidenceRef}); err != nil {
				return "", err
			}
			return fmt.Sprintf("recorded IOC %s: %s", a.Type, a.Value), nil
		},
	}
}

func setClassificationTool(inv *Investigation) *tools.Tool {
	return &tools.Tool{
		Def: tools.Def("set_classification",
			"Set the malware classification using STIX 2.1 malware-type-ov values (multi-label — a sample can be several types). Preferred values: "+strings.Join(STIXMalwareTypes, ", ")+". Use `unknown` if triage can't determine a type.",
			tools.Obj(map[string]any{
				"malware_types": tools.ArrProp("one or more STIX malware types"),
				"confidence":    tools.StrProp("low | medium | high"),
			}, "malware_types")),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var a struct {
				MalwareTypes []string `json:"malware_types"`
				Confidence   string   `json:"confidence"`
			}
			if err := json.Unmarshal(input, &a); err != nil {
				return "", err
			}
			var unknown []string
			for _, t := range a.MalwareTypes {
				if !IsSTIXType(t) {
					unknown = append(unknown, t)
				}
			}
			inv.SetClassification(a.MalwareTypes, a.Confidence)
			msg := fmt.Sprintf("classification set: %s (confidence %s)", strings.Join(a.MalwareTypes, ", "), orUnknown(a.Confidence))
			if len(unknown) > 0 {
				msg += fmt.Sprintf(" — note: %s not in the STIX vocab (accepted, but prefer the standard values)", strings.Join(unknown, ", "))
			}
			return msg, nil
		},
	}
}

func writeReportSectionTool(inv *Investigation) *tools.Tool {
	return &tools.Tool{
		Def: tools.Def("write_report_section",
			"Write (or overwrite) a section of the draft report. Ground every claim in recorded findings/IOCs — do not introduce new uncited indicators here.",
			tools.Obj(map[string]any{
				"id":      tools.StrProp("section id, e.g. encryption-scheme, iocs"),
				"title":   tools.StrProp("section title"),
				"content": tools.StrProp("section content in Markdown"),
			}, "id", "title", "content")),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var a struct{ ID, Title, Content string }
			if err := json.Unmarshal(input, &a); err != nil {
				return "", err
			}
			if a.ID == "" || a.Title == "" {
				return "", fmt.Errorf("id and title are required")
			}
			inv.WriteSection(ReportSection{ID: a.ID, Title: a.Title, Content: a.Content})
			return "wrote section " + a.ID, nil
		},
	}
}

func markObjectiveTool(inv *Investigation) *tools.Tool {
	return &tools.Tool{
		Def: tools.Def("mark_objective",
			"Mark a playbook objective as covered once you've established it with evidence. Use the objective id shown in the objectives list.",
			tools.Obj(map[string]any{"id": tools.StrProp("objective id")}, "id")),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var a struct{ ID string }
			if err := json.Unmarshal(input, &a); err != nil {
				return "", err
			}
			if !inv.MarkObjective(a.ID) {
				return fmt.Sprintf("no objective %q (check the objectives list)", a.ID), nil
			}
			c, t := inv.Coverage()
			return fmt.Sprintf("objective %s covered (%d/%d)", a.ID, c, t), nil
		},
	}
}

func highlightFunctionTool(inv *Investigation, client *api.Client, project *api.Project) *tools.Tool {
	return &tools.Tool{
		Def: tools.Def("highlight_function",
			highlightDesc(project),
			tools.Obj(map[string]any{
				"name": tools.StrProp(highlightNameDesc(project)),
				"tag":  tools.StrProp("short tag, e.g. 'crypto', 'c2', 'entry'"),
				"note": tools.StrProp("why this function matters"),
			}, "name")),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var a struct{ Name, Tag, Note string }
			if err := json.Unmarshal(input, &a); err != nil {
				return "", err
			}
			if a.Name == "" {
				return "", fmt.Errorf("name is required")
			}
			if project.IsLocal() {
				// Local projects have no backend Highlights board — note it in
				// the transcript/report instead of 404ing.
				return fmt.Sprintf("noted highlight %s [%s] (local project — no backend board; call it out in the report)", a.Name, a.Tag), nil
			}
			req := api.CreateHighlightRequest{Type: api.HighlightFunction, TargetRef: a.Name, Tag: a.Tag, Note: a.Note}
			what := "function"
			if project.Kind != api.KindBIN {
				// Source-tree projects anchor highlights to a FILE (the UI opens
				// targetRef as a path); a "path:line" ref keeps its line in the note.
				path, line := splitFileLine(a.Name)
				req.Type, req.TargetRef, what = api.HighlightFile, path, "file"
				if line != "" {
					req.Note = strings.TrimSpace("line " + line + ": " + a.Note)
				}
			}
			_, err := client.CreateHighlight(project.ID, req)
			if err != nil {
				return "", fmt.Errorf("create highlight: %w", err)
			}
			return "highlighted " + what + " " + a.Name, nil
		},
	}
}

func suggestRenamesTool(inv *Investigation) *tools.Tool {
	return &tools.Tool{
		Def: tools.Def("suggest_renames",
			"Propose clearer names for functions you've understood (recorded for the analyst to apply). Provide the current name, a suggested name, and a one-line rationale.",
			tools.Obj(map[string]any{
				"original":  tools.StrProp("current function name"),
				"suggested": tools.StrProp("proposed name"),
				"rationale": tools.StrProp("why this name fits"),
			}, "original", "suggested")),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var a struct{ Original, Suggested, Rationale string }
			if err := json.Unmarshal(input, &a); err != nil {
				return "", err
			}
			if a.Original == "" || a.Suggested == "" {
				return "", fmt.Errorf("original and suggested are required")
			}
			inv.AddRename(RenameSuggestion{Original: a.Original, Suggested: a.Suggested, Rationale: a.Rationale})
			return fmt.Sprintf("recorded rename %s → %s", a.Original, a.Suggested), nil
		},
	}
}

// askUserTool defines ask_user for the LLM. The loop INTERCEPTS this by name
// (it suspends the turn and surfaces the question); this handler is only a
// safety net if the loop ever runs it directly.
func askUserTool() *tools.Tool {
	return &tools.Tool{
		Def: tools.Def(AskUserToolName,
			"Ask the human analyst a question and wait for their answer. Use for intel you need, an ambiguous call, or a decision that's the analyst's to make. Keep it to one focused question.",
			tools.Obj(map[string]any{"question": tools.StrProp("the question for the analyst")}, "question")),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var a struct{ Question string }
			_ = json.Unmarshal(input, &a)
			return "", fmt.Errorf("ask_user should be handled by the loop; question was: %s", a.Question)
		},
	}
}

// QuestionFromAskUser extracts the question text from an ask_user tool input.
func QuestionFromAskUser(input json.RawMessage) string {
	var a struct{ Question string }
	_ = json.Unmarshal(input, &a)
	return a.Question
}

func highlightDesc(project *api.Project) string {
	if project.Kind != api.KindBIN {
		return "Add a source file to the project's Highlights board (evidence board) so the analyst captures it for the report. Use for the classes/files that matter most (+ why). Pass the file path, optionally as path:line to point at the pivotal line."
	}
	return "Add a function to the project's Highlights board (evidence board) so the analyst captures a screenshot of it for the report. Use for the functions that matter most (+ why). Creates a FUNCTION-anchored highlight via the existing backend."
}

func highlightNameDesc(project *api.Project) string {
	if project.Kind != api.KindBIN {
		return "file path to highlight, e.g. sources/com/evil/Crypto.java or sources/com/evil/Crypto.java:42"
	}
	return "function name to highlight"
}

// splitFileLine splits "path/File.java:42" into its path and line; a ref
// without a numeric :line suffix comes back whole with an empty line.
func splitFileLine(ref string) (path, line string) {
	i := strings.LastIndexByte(ref, ':')
	if i <= 0 || i == len(ref)-1 {
		return ref, ""
	}
	for _, r := range ref[i+1:] {
		if r < '0' || r > '9' {
			return ref, ""
		}
	}
	return ref[:i], ref[i+1:]
}

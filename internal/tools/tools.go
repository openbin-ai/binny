// Package tools implements BINNY's LLM-callable toolset — the bridge between
// the agent loop and the existing OpenBIN backend. Tools are thin wrappers over
// endpoints that already ship; none of them add backend surface.
//
// Every tool is (1) a definition the LLM sees (name/description/JSON schema)
// and (2) a handler the loop runs when the LLM calls it, returning a string
// that becomes the tool_result. Handlers must be resilient: a bad argument or
// backend error returns an error, which the loop reports back as an error
// result rather than crashing the session.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"openbin.ai/binny/internal/llm"
)

// Handler executes a tool call. `input` is the raw JSON arguments the LLM
// produced. The returned string is fed back as the tool result.
type Handler func(ctx context.Context, input json.RawMessage) (string, error)

// Tool couples an LLM-facing definition with its handler.
type Tool struct {
	Def     llm.Tool
	Handler Handler
}

// Registry is an ordered, name-addressed set of tools.
type Registry struct {
	byName map[string]*Tool
	order  []string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byName: map[string]*Tool{}}
}

// Add registers a tool (later adds override an existing name).
func (r *Registry) Add(t *Tool) {
	if _, ok := r.byName[t.Def.Name]; !ok {
		r.order = append(r.order, t.Def.Name)
	}
	r.byName[t.Def.Name] = t
}

// Defs returns the LLM tool definitions in registration order.
func (r *Registry) Defs() []llm.Tool {
	defs := make([]llm.Tool, 0, len(r.order))
	for _, name := range r.order {
		defs = append(defs, r.byName[name].Def)
	}
	return defs
}

// Names returns the registered tool names (sorted, for display).
func (r *Registry) Names() []string {
	out := append([]string(nil), r.order...)
	sort.Strings(out)
	return out
}

// Has reports whether a tool is registered.
func (r *Registry) Has(name string) bool {
	_, ok := r.byName[name]
	return ok
}

// View returns a registry restricted to the named tools that exist here, in
// this registry's registration order. The tools themselves are shared, so a
// view is a cheap per-role filter over one underlying toolset: a crew member
// sees (and can run) only its role's tools.
func (r *Registry) View(names []string) *Registry {
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	v := NewRegistry()
	for _, name := range r.order {
		if want[name] {
			v.Add(r.byName[name])
		}
	}
	return v
}

// Without returns a registry holding every tool except the named ones.
func (r *Registry) Without(names ...string) *Registry {
	drop := make(map[string]bool, len(names))
	for _, n := range names {
		drop[n] = true
	}
	v := NewRegistry()
	for _, name := range r.order {
		if !drop[name] {
			v.Add(r.byName[name])
		}
	}
	return v
}

// Merge returns a registry holding the tools of every given registry, in
// order (a later registry overrides an earlier tool of the same name). Nil
// registries are skipped.
func Merge(regs ...*Registry) *Registry {
	v := NewRegistry()
	for _, r := range regs {
		if r == nil {
			continue
		}
		for _, name := range r.order {
			v.Add(r.byName[name])
		}
	}
	return v
}

// Run executes a named tool. Returns (result, isError). A missing tool or a
// handler error is surfaced as an error result string (isError=true) so the
// loop can hand it to the LLM to recover from, rather than aborting.
func (r *Registry) Run(ctx context.Context, name string, input json.RawMessage) (string, bool) {
	t, ok := r.byName[name]
	if !ok {
		return fmt.Sprintf("no such tool %q", name), true
	}
	out, err := t.Handler(ctx, input)
	if err != nil {
		return fmt.Sprintf("tool %s failed: %v", name, err), true
	}
	return out, false
}

// Obj builds a JSON-schema object from a property map + required names.
// Exported so the agent package can define its output/control tools with the
// same helpers the read tools use.
func Obj(props map[string]any, required ...string) map[string]any {
	m := map[string]any{
		"type":                 "object",
		"properties":           props,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

// StrProp builds a string schema property with a description.
func StrProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

// ArrProp builds an array-of-strings schema property with a description.
func ArrProp(desc string) map[string]any {
	return map[string]any{
		"type":        "array",
		"items":       map[string]any{"type": "string"},
		"description": desc,
	}
}

// Def builds an LLM tool definition from a name, description, and JSON schema.
func Def(name, desc string, schema map[string]any) llm.Tool {
	return llm.Tool{Name: name, Description: desc, InputSchema: schema}
}

package serve

// Read-only binary panel: when a BIN project is open, the GUI shows a function
// list, strings, and imports/exports (and a decompiled-C viewer) alongside the
// chat. These endpoints read the same cached analysis blob the agent's tools do,
// straight from the toolbox — no agent loop involved.
//
//	GET /api/bin/analysis        compact overview: metadata + functions + strings
//	GET /api/bin/function?name=  one function's signature + decompiled C

import "net/http"

const (
	maxPanelFuncs   = 6000
	maxPanelStrings = 4000
)

func (s *server) handleBinAnalysis(w http.ResponseWriter, r *http.Request) {
	tb := s.binTB()
	if tb == nil {
		writeJSON(w, http.StatusOK, map[string]any{"binary": false})
		return
	}
	a, err := tb.Analysis()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if a == nil {
		writeJSON(w, http.StatusOK, map[string]any{"binary": false})
		return
	}
	type fn struct {
		Name      string `json:"name"`
		Address   string `json:"address"`
		Size      int    `json:"size"`
		Signature string `json:"signature,omitempty"`
		HasCode   bool   `json:"hasCode"`
		External  bool   `json:"external,omitempty"`
		Thunk     bool   `json:"thunk,omitempty"`
	}
	funcs := make([]fn, 0, len(a.Functions))
	for i, f := range a.Functions {
		if i >= maxPanelFuncs {
			break
		}
		funcs = append(funcs, fn{
			Name: f.Name, Address: f.Address, Size: f.Size, Signature: f.Signature,
			HasCode: f.Decompiled != "", External: f.External, Thunk: f.Thunk,
		})
	}
	strs := a.Strings
	strTrunc := false
	if len(strs) > maxPanelStrings {
		strs = strs[:maxPanelStrings]
		strTrunc = true
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"binary":         true,
		"metadata":       a.Metadata,
		"functions":      funcs,
		"functionsTotal": len(a.Functions),
		"strings":        strs,
		"stringsTotal":   len(a.Strings),
		"stringsTrunc":   strTrunc,
		"imports":        a.Imports,
		"exports":        a.Exports,
	})
}

func (s *server) handleBinFunction(w http.ResponseWriter, r *http.Request) {
	tb := s.binTB()
	if tb == nil {
		writeErr(w, http.StatusNotFound, "no binary is open")
		return
	}
	name := r.URL.Query().Get("name")
	addr := r.URL.Query().Get("address")
	if name == "" && addr == "" {
		writeErr(w, http.StatusBadRequest, "missing function name or address")
		return
	}
	a, err := tb.Analysis()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if a == nil {
		writeErr(w, http.StatusNotFound, "analysis not loaded")
		return
	}
	for _, f := range a.Functions {
		if (name != "" && f.Name == name) || (addr != "" && f.Address == addr) {
			dis := make([]string, 0, len(f.Disassembly))
			for _, ins := range f.Disassembly {
				dis = append(dis, ins.Addr+"  "+ins.Text)
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"name": f.Name, "address": f.Address, "signature": f.Signature,
				"decompiled": f.Decompiled, "disassembly": dis,
			})
			return
		}
	}
	writeErr(w, http.StatusNotFound, "no such function")
}

package api

import "strings"

// DTOs mirror the backend Spring records verbatim (Jackson camelCase), EXCEPT
// the binary-analysis blob, which is the Ghidra worker's raw output and uses
// snake_case. Field tags are explicit so the two conventions can't drift.

// ProjectKind is the sample type. Drives which playbook toolset applies.
type ProjectKind string

const (
	KindAPK    ProjectKind = "APK"
	KindBIN    ProjectKind = "BIN"
	KindScript ProjectKind = "SCRIPT"
)

// Project mirrors ProjectResponse (projects/dto/ProjectResponse.java).
type Project struct {
	ID                  string      `json:"id"`
	Kind                ProjectKind `json:"kind"`
	Name                string      `json:"name"`
	OriginalFilename    string      `json:"originalFilename"`
	SizeBytes           int64       `json:"sizeBytes"`
	Sha256              string      `json:"sha256"`
	Status              string      `json:"status"`         // UPLOADED|DECOMPILING|READY|FAILED|INGEST_PENDING
	WorkflowStatus      string      `json:"workflowStatus"` // NEW|TRIAGING|ANALYZING|DRAFTING_REPORT|PUBLISHED
	AnalysisMode        string      `json:"analysisMode"`   // MALWARE|VULN_RESEARCH
	ErrorMessage        string      `json:"errorMessage"`
	PackageName         string      `json:"packageName"`
	Arch                string      `json:"arch"`
	ExecutableFormat    string      `json:"executableFormat"`
	Compiler            string      `json:"compiler"`
	LanguageID          string      `json:"languageId"`
	ImageBase           string      `json:"imageBase"`
	CreatedAt           string      `json:"createdAt"`
	AnalysisDownloadURL string      `json:"analysisDownloadUrl"`
	Role                string      `json:"role"` // OWNER|EDITOR|VIEWER; null → owner
	PublicReadAt        string      `json:"publicReadAt"`
	ForkedFromID        string      `json:"forkedFromId"`
	ForkCount           int         `json:"forkCount"`
}

// Ready reports whether the project has a completed analysis to work over.
func (p Project) Ready() bool { return p.Status == "READY" }

// IsLocal reports whether this is a locally-decompiled project (no backend
// record; analysis lives in the on-disk store, ID is "local:<sha12>").
func (p Project) IsLocal() bool { return strings.HasPrefix(p.ID, "local:") }

// Sample mirrors projects/samples/dto/SampleView.java — one EXTRA sample
// attached to a multi-sample BIN project (the project's own binary is the
// "primary" and is not in this list). Each READY sample has its own analysis
// blob, signed the same way as the project's.
type Sample struct {
	ID                  string `json:"id"`
	Label               string `json:"label"`
	OriginalFilename    string `json:"originalFilename"`
	Sha256              string `json:"sha256"`
	SizeBytes           int64  `json:"sizeBytes"`
	Arch                string `json:"arch"`
	ExecutableFormat    string `json:"executableFormat"`
	Compiler            string `json:"compiler"`
	LanguageID          string `json:"languageId"`
	ImageBase           string `json:"imageBase"`
	Status              string `json:"status"` // INGEST_PENDING|READY|FAILED
	ErrorMessage        string `json:"errorMessage"`
	CreatedAt           string `json:"createdAt"`
	AnalysisDownloadURL string `json:"analysisDownloadUrl"`
}

// Ready reports whether the sample has a completed analysis to work over.
func (s Sample) Ready() bool { return s.Status == "READY" }

// DisplayName is the label, falling back to the original filename.
func (s Sample) DisplayName() string {
	if strings.TrimSpace(s.Label) != "" {
		return s.Label
	}
	return s.OriginalFilename
}

// FileNode mirrors projects/dto/FileNode.java (recursive tree node).
type FileNode struct {
	Name     string     `json:"name"`
	Path     string     `json:"path"`
	Type     string     `json:"type"` // "dir" | "file"
	Size     *int64     `json:"size"`
	Children []FileNode `json:"children"`
}

// FileContent mirrors projects/dto/FileContentResponse.java.
type FileContent struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	Truncated bool   `json:"truncated"`
	Encoding  string `json:"encoding"` // "utf-8" | "binary"
	Content   string `json:"content"`
}

// SourceBundle mirrors projects/dto/SourceBundleResponse.java.
type SourceBundle struct {
	URL             string `json:"url"`
	CompressedBytes int64  `json:"compressedBytes"`
	ETag            string `json:"etag"`
}

// SearchHit mirrors search/dto/SearchHit.java.
type SearchHit struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet"`
}

// Manifest mirrors manifest/dto/AndroidManifestInfo.java.
type Manifest struct {
	PackageName        string              `json:"packageName"`
	VersionCode        *int                `json:"versionCode"`
	VersionName        string              `json:"versionName"`
	MinSdk             *int                `json:"minSdk"`
	TargetSdk          *int                `json:"targetSdk"`
	Permissions        []string            `json:"permissions"`
	DefinedPermissions []string            `json:"definedPermissions"`
	Application        *ManifestComponent  `json:"application"`
	Activities         []ManifestComponent `json:"activities"`
	Services           []ManifestComponent `json:"services"`
	Receivers          []ManifestComponent `json:"receivers"`
	Providers          []ManifestComponent `json:"providers"`
}

// ManifestComponent mirrors manifest/dto/ManifestComponent.java.
type ManifestComponent struct {
	Kind          string         `json:"kind"`
	ClassName     string         `json:"className"`
	Exported      bool           `json:"exported"`
	Enabled       bool           `json:"enabled"`
	Permission    string         `json:"permission"`
	IntentFilters []IntentFilter `json:"intentFilters"`
	Authorities   []string       `json:"authorities"`
	File          string         `json:"file"` // "" when the class isn't in the decompiled tree
	Line          *int           `json:"line"`
}

// IntentFilter mirrors manifest/dto/IntentFilter.java.
type IntentFilter struct {
	Actions     []string `json:"actions"`
	Categories  []string `json:"categories"`
	DataSchemes []string `json:"dataSchemes"`
	Priority    *int     `json:"priority"`
}

// JavaSymbol mirrors symbols/dto/Symbol.java (a declaration in decompiled
// APK source — not the binary blob's named-address Symbol below).
type JavaSymbol struct {
	Kind      string `json:"kind"` // CLASS|INTERFACE|ENUM|METHOD|FIELD|…
	Name      string `json:"name"`
	ClassName string `json:"className"`
	File      string `json:"file"`
	Line      int    `json:"line"`
	Signature string `json:"signature"`
	Modifiers string `json:"modifiers"`
	Pkg       string `json:"pkg"`
}

// SymbolUsage mirrors symbols/dto/SymbolUsage.java.
type SymbolUsage struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet"`
}

// --- Binary analysis blob (Ghidra worker output; snake_case) --------------

// Analysis is the top-level binary-analysis JSON. `strings` and `imports` are
// arrays of plain strings; the rest are object arrays.
type Analysis struct {
	Error        string        `json:"error,omitempty"` // worker-side failure marker
	Functions    []Function    `json:"functions"`
	Strings      []string      `json:"strings"`
	Imports      []string      `json:"imports"`
	Exports      []Symbol      `json:"exports"`
	EntryPoints  []Symbol      `json:"entry_points"`
	TLSCallbacks []Symbol      `json:"tls_callbacks"`
	DataSymbols  []DataSymbol  `json:"data_symbols"`
	MemoryBlocks []MemoryBlock `json:"memory_blocks"`
	Metadata     Metadata      `json:"metadata"`
}

// Function is one decompiled function in the analysis blob.
type Function struct {
	Name        string        `json:"name"`
	Address     string        `json:"address"`
	Size        int           `json:"size"`
	Signature   string        `json:"signature"`
	Decompiled  string        `json:"decompiled"`  // C pseudocode; "" for external/thunk
	Disassembly []Instruction `json:"disassembly"` // nil for external/thunk
	Xrefs       Xrefs         `json:"xrefs"`
	External    bool          `json:"external"`
	Thunk       bool          `json:"thunk"`
	BodySkipped bool          `json:"body_skipped"`
}

// Instruction is one disassembly line.
type Instruction struct {
	Addr string `json:"addr"`
	Text string `json:"text"`
}

// Xrefs holds a function's call graph edges.
type Xrefs struct {
	Callers []string `json:"callers"`
	Callees []string `json:"callees"`
}

// Symbol is a named address (export / entry point / TLS callback).
type Symbol struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

// DataSymbol is a data-section symbol (globals, config blobs).
type DataSymbol struct {
	Name         string `json:"name"`
	Address      string `json:"address"`
	Type         string `json:"type"`
	Size         int    `json:"size"`
	Value        string `json:"value"`
	BytesPreview string `json:"bytes_preview"`
	RefCount     int    `json:"ref_count"`
}

// MemoryBlock is a memory region / section (there is no separate sections key).
type MemoryBlock struct {
	Name        string `json:"name"`
	Start       string `json:"start"`
	End         string `json:"end"`
	Size        int    `json:"size"`
	Permissions string `json:"permissions"` // e.g. "r-x"
	Executable  bool   `json:"executable"`
	Initialized bool   `json:"initialized"`
}

// Metadata mirrors the worker's metadata object. No entropy/sections keys.
type Metadata struct {
	Compiler         string `json:"compiler"`
	Language         string `json:"language"`
	ExecutableFormat string `json:"executable_format"`
	ImageBase        string `json:"image_base"`
	FunctionCount    int    `json:"function_count"`
	StringCount      int    `json:"string_count"`
	ImportCount      int    `json:"import_count"`
	ExportCount      int    `json:"export_count"`
	EntryPointCount  int    `json:"entry_point_count"`
	TLSCallbackCount int    `json:"tls_callback_count"`
	DataSymbolCount  int    `json:"data_symbol_count"`
	MemoryBlockCount int    `json:"memory_block_count"`
}

// --- Highlights (Phase A) -------------------------------------------------

type HighlightType string

const (
	HighlightFunction HighlightType = "FUNCTION"
	HighlightFile     HighlightType = "FILE"
	HighlightVisual   HighlightType = "VISUAL"
)

// CreateHighlightRequest mirrors highlights/dto/CreateHighlightRequest.java.
type CreateHighlightRequest struct {
	Type      HighlightType `json:"type"`
	TargetRef string        `json:"targetRef,omitempty"`
	MediaKey  string        `json:"mediaKey,omitempty"`
	Tag       string        `json:"tag,omitempty"`
	Note      string        `json:"note,omitempty"`
}

// Highlight mirrors highlights/dto/HighlightResponse.java.
type Highlight struct {
	ID        string        `json:"id"`
	Type      HighlightType `json:"type"`
	TargetRef string        `json:"targetRef"`
	MediaKey  string        `json:"mediaKey"`
	Tag       string        `json:"tag"`
	Note      string        `json:"note"`
	Position  int           `json:"position"`
	CreatedBy string        `json:"createdBy"`
	CreatedAt string        `json:"createdAt"`
}

// --- Reports --------------------------------------------------------------

// ReportSection mirrors reports/dto/ReportSection.java.
type ReportSection struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Content string `json:"content"`
}

// Report mirrors reports/dto/ReportResponse.java.
type Report struct {
	ID                   string          `json:"id"`
	ProjectID            string          `json:"projectId"`
	Title                string          `json:"title"`
	Sections             []ReportSection `json:"sections"`
	CreatedAt            string          `json:"createdAt"`
	UpdatedAt            string          `json:"updatedAt"`
	PublishedAt          string          `json:"publishedAt"`
	CommunityPublishedAt string          `json:"communityPublishedAt"`
	MalwareType          string          `json:"malwareType"`
	Tags                 []string        `json:"tags"`
}

// UpdateReportRequest mirrors reports/dto/UpdateReportRequest.java (PUT body).
type UpdateReportRequest struct {
	Title    string          `json:"title"`
	Sections []ReportSection `json:"sections"`
}

// --- Renames --------------------------------------------------------------

// ManualRenameRequest mirrors renames/dto/ManualRenameRequest.java.
type ManualRenameRequest struct {
	Original  string `json:"original"`
	Suggested string `json:"suggested"`
	Scope     string `json:"scope"`
}

// Rename mirrors renames/dto/RenameDto.java.
type Rename struct {
	ID         string `json:"id"`
	Original   string `json:"original"`
	Suggested  string `json:"suggested"`
	Scope      string `json:"scope"`
	Status     string `json:"status"`
	Confidence string `json:"confidence"`
	SourcePath string `json:"sourcePath"`
	Rationale  string `json:"rationale"`
	CreatedAt  string `json:"createdAt"`
}

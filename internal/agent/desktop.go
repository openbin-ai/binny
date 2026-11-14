package agent

import (
	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/tools"
)

// RegisterSampleTooling adds the raw-sample toolset to reg for a host that
// doesn't run the staged engine (BINNY Desktop's chat agent): the extraction
// sandbox (write_file / run / read_artifact) and, for BIN projects with a
// toolbox, decompile_sample. The tools read sess.SamplePath at call time and
// return an actionable error while no sample is attached.
func RegisterSampleTooling(reg *tools.Registry, sess *app.Session, tb *tools.Toolbox, logf func(format string, args ...any)) {
	registerExtractionTools(reg, NewInvestigation(), sess)
	if tb != nil && sess.Project != nil && sess.Project.Kind == api.KindBIN {
		registerDecompileTool(reg, sess, tb, logf)
	}
}

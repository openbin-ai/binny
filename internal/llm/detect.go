package llm

import (
	"context"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Local-model detection — the Open WebUI / AUTOMATIC1111 trick. Every local
// inference server (Ollama, LM Studio, Jan, llama.cpp, LocalAI, vLLM) exposes an
// OpenAI-compatible GET /v1/models, so we probe the well-known ports in parallel
// and list whatever is actually running. BINNY already *speaks* to these
// (openAIProvider with a localhost BaseURL and no key); detection just finds them
// so the picker can offer them with zero config.
//
// This is deliberately read-only and best-effort: a probe that times out or
// refuses is simply "not running". Nothing here mutates config or sends a key.

// LocalRuntime is one detected local inference server and the models it serves.
type LocalRuntime struct {
	Name    string   `json:"name"`    // human label, e.g. "Ollama"
	BaseURL string   `json:"baseURL"` // OpenAI-compatible base, already carries /v1
	Models  []string `json:"models"`  // model ids reported by /v1/models
}

// localCandidate is a runtime we know how to find at a fixed local address.
type localCandidate struct {
	name    string
	baseURL string
}

// knownLocalRuntimes are the default addresses, in rough order of popularity.
// All are probed; llama.cpp/LocalAI share :8080 and vLLM uses :8000 — overlaps
// are harmless since we key results by the responding base URL.
var knownLocalRuntimes = []localCandidate{
	{"Ollama", "http://localhost:11434/v1"},
	{"LM Studio", "http://localhost:1234/v1"},
	{"Jan", "http://localhost:1337/v1"},
	{"llama.cpp / LocalAI", "http://localhost:8080/v1"},
	{"vLLM", "http://localhost:8000/v1"},
}

// DetectLocal probes the known local runtimes in parallel and returns those that
// answered with at least one model. The probe is capped per-candidate so a dead
// port never stalls the whole scan.
func DetectLocal(ctx context.Context) []LocalRuntime {
	return detectLocal(ctx, knownLocalRuntimes)
}

func detectLocal(ctx context.Context, candidates []localCandidate) []LocalRuntime {
	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		out []LocalRuntime
	)
	for _, c := range candidates {
		wg.Add(1)
		go func(c localCandidate) {
			defer wg.Done()
			models := probeLocalModels(ctx, c.baseURL)
			if len(models) == 0 {
				return
			}
			sort.Strings(models)
			mu.Lock()
			out = append(out, LocalRuntime{Name: c.name, BaseURL: c.baseURL, Models: models})
			mu.Unlock()
		}(c)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// probeLocalModels does a short GET {base}/models and returns the model ids, or
// nil if the server isn't there. It reuses the shared /v1/models parser.
func probeLocalModels(ctx context.Context, baseURL string) []string {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/models", nil)
	if err != nil {
		return nil
	}
	resp, err := sharedClient().Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil
	}
	return parseModelList(body)
}

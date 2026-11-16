package serve

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Long local runs (JADX, Ghidra) are jobs that outlive the HTTP request that
// started them, with an event log a client can re-attach to.
//
// They used to run on the request's context, streaming progress on that one
// response. But starting the worker container adds a network interface, and
// Firefox reacts to any network change by aborting its in-flight requests —
// loopback included. So every decompile started from Firefox died a few
// seconds after `docker run`: the browser threw "TypeError: Error in input
// stream", the request context was cancelled, and the worker was torn down.
//
// Now the stream is only a view of the job: it opens with {type:"job",id},
// and when it breaks the page resumes from GET /api/job?id=…&from=<events seen>.

// jobTTL is how long a finished job's events stay available for a late re-attach.
const jobTTL = 10 * time.Minute

type job struct {
	mu     sync.Mutex
	events [][]byte      // marshalled SSE payloads, in order
	done   bool          // no more events will be added
	wake   chan struct{} // closed (and replaced) whenever events or done change
}

func (j *job) emit(ev map[string]any) {
	b, _ := json.Marshal(ev)
	j.mu.Lock()
	j.events = append(j.events, b)
	close(j.wake)
	j.wake = make(chan struct{})
	j.mu.Unlock()
}

func (j *job) finish() {
	j.mu.Lock()
	j.done = true
	close(j.wake)
	j.wake = make(chan struct{})
	j.mu.Unlock()
}

// since returns the events from index from on, whether the job has finished,
// and a channel that closes when there is more to read.
func (j *job) since(from int) ([][]byte, bool, <-chan struct{}) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if from > len(j.events) {
		from = len(j.events)
	}
	return j.events[from:], j.done, j.wake
}

// startJob runs fn in the background, detached from any request, and returns
// the job to stream. fn reports through emit; the job ends when fn returns.
func (s *server) startJob(name string, fn func(ctx context.Context, emit func(map[string]any))) *job {
	var raw [8]byte
	_, _ = rand.Read(raw[:])
	id := hex.EncodeToString(raw[:])
	j := &job{wake: make(chan struct{})}

	s.jobsMu.Lock()
	if s.jobs == nil {
		s.jobs = map[string]*job{}
	}
	s.jobs[id] = j
	s.jobsMu.Unlock()

	j.emit(map[string]any{"type": "job", "id": id})
	go func() {
		defer func() {
			// A panic here would take the whole backend down (net/http only
			// recovers panics on its own handler goroutines).
			if p := recover(); p != nil {
				log.Printf("%s: panic: %v", name, p)
				j.emit(map[string]any{"type": "error", "error": fmt.Sprintf("internal error: %v", p)})
			}
			j.finish()
			time.AfterFunc(jobTTL, func() {
				s.jobsMu.Lock()
				delete(s.jobs, id)
				s.jobsMu.Unlock()
			})
		}()
		fn(context.Background(), j.emit)
	}()
	return j
}

// streamJob writes the job's events from index from as SSE until the job
// finishes or the client goes away. The job itself is unaffected either way.
func streamJob(w http.ResponseWriter, r *http.Request, j *job, from int) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	for {
		evs, done, wake := j.since(from)
		for _, b := range evs {
			if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
				return
			}
		}
		from += len(evs)
		flusher.Flush()
		if done {
			return
		}
		select {
		case <-wake:
		case <-r.Context().Done():
			return
		}
	}
}

// handleJob re-attaches to a running (or recently finished) job:
// GET /api/job?id=<id>&from=<number of events already received>.
func (s *server) handleJob(w http.ResponseWriter, r *http.Request) {
	s.jobsMu.Lock()
	j := s.jobs[r.URL.Query().Get("id")]
	s.jobsMu.Unlock()
	if j == nil {
		writeErr(w, http.StatusNotFound, "no such job — the backend was restarted, or the job finished a while ago")
		return
	}
	from, _ := strconv.Atoi(r.URL.Query().Get("from"))
	if from < 0 {
		from = 0
	}
	streamJob(w, r, j, from)
}

// Package jobs ist eine kleine Job-Queue auf SQLite fuer lang laufende
// Aktionen (Zertifikate): Worker-Pool, Sperre je Ressource, Retry mit Backoff.
package jobs

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store/dbq"
)

const (
	CertIssue  = "cert_issue"
	CertRenew  = "cert_renew"
	CertRevoke = "cert_revoke"

	Queued    = "queued"
	Running   = "running"
	Succeeded = "succeeded"
	Failed    = "failed"

	MaxAttempts = 6
)

// Enqueue legt einen Job in der Transaktion von q an.
func Enqueue(ctx context.Context, q *dbq.Queries, kind, resource, createdBy string) (dbq.Job, error) {
	now := store.Now()
	j := dbq.Job{ID: ulid.Make().String(), Kind: kind, Resource: resource, Status: Queued, CreatedBy: createdBy,
		CreatedAt: now, RunAfter: now}
	err := q.InsertJob(ctx, dbq.InsertJobParams{ID: j.ID, Kind: kind, Resource: resource, CreatedBy: createdBy,
		CreatedAt: now, RunAfter: now})
	return j, err
}

// HasOpen prueft, ob fuer die Ressource bereits ein Job dieser Art offen ist.
func HasOpen(ctx context.Context, q *dbq.Queries, kind, resource string) (bool, error) {
	n, err := q.CountOpenJobsFor(ctx, dbq.CountOpenJobsForParams{Resource: resource, Kind: kind})
	return n > 0, err
}

type Handler func(ctx context.Context, job dbq.Job) error

type Runner struct {
	store    *store.Store
	workers  int
	handlers map[string]Handler
	log      *slog.Logger
	notify   chan struct{}

	mu       sync.Mutex
	inflight map[string]bool // Sperre je Ressource (FQDN)

	// Backoff und Tick sind in Tests ersetzbar.
	Backoff func(attempt int64) time.Duration
	Tick    time.Duration
}

func NewRunner(st *store.Store, workers int, log *slog.Logger) *Runner {
	if workers < 1 {
		workers = 1
	}
	if log == nil {
		log = slog.Default()
	}
	return &Runner{store: st, workers: workers, handlers: map[string]Handler{}, log: log,
		notify: make(chan struct{}, 1), inflight: map[string]bool{}, Backoff: DefaultBackoff, Tick: 10 * time.Second}
}

// DefaultBackoff: 1, 2, 4, ... Minuten, hoechstens eine Stunde.
func DefaultBackoff(attempt int64) time.Duration {
	d := time.Minute << min(max(attempt-1, 0), 6)
	return min(d, time.Hour)
}

func (r *Runner) Handle(kind string, h Handler) { r.handlers[kind] = h }

// Notify weckt den Dispatcher nach dem Commit eines neuen Jobs.
func (r *Runner) Notify() {
	select {
	case r.notify <- struct{}{}:
	default:
	}
}

// Run verteilt faellige Jobs bis ctx endet. Beim Start werden Jobs, die ein
// frueherer Prozess als running hinterlassen hat, wieder eingereiht.
func (r *Runner) Run(ctx context.Context) {
	_ = r.store.Write(ctx, func(q *dbq.Queries) error { return q.ResetRunningJobs(ctx) })
	sem := make(chan struct{}, r.workers)
	var wg sync.WaitGroup
	defer wg.Wait()
	tick := time.NewTicker(r.Tick)
	defer tick.Stop()
	for {
		due, err := r.store.Read().ListDueJobs(ctx, store.Now())
		if err != nil && ctx.Err() == nil {
			r.log.Error("Jobs lesen", "error", err)
		}
		for _, j := range due {
			if !r.lock(j.Resource) {
				continue
			}
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				r.unlock(j.Resource)
				return
			}
			wg.Add(1)
			go func(j dbq.Job) {
				defer wg.Done()
				defer func() { <-sem; r.unlock(j.Resource); r.Notify() }()
				r.execute(ctx, j)
			}(j)
		}
		select {
		case <-ctx.Done():
			return
		case <-r.notify:
		case <-tick.C:
		}
	}
}

func (r *Runner) lock(res string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.inflight[res] {
		return false
	}
	r.inflight[res] = true
	return true
}

func (r *Runner) unlock(res string) {
	r.mu.Lock()
	delete(r.inflight, res)
	r.mu.Unlock()
}

func (r *Runner) execute(ctx context.Context, j dbq.Job) {
	var claimed int64
	now := store.Now()
	err := r.store.Write(ctx, func(q *dbq.Queries) (err error) {
		claimed, err = q.ClaimJob(ctx, dbq.ClaimJobParams{StartedAt: &now, ID: j.ID})
		return err
	})
	if err != nil || claimed == 0 {
		return
	}
	j.Attempts++
	h, ok := r.handlers[j.Kind]
	var runErr error
	if !ok {
		runErr = errUnknownKind(j.Kind)
	} else {
		runErr = h(ctx, j)
	}
	// Abschluss auch bei beendetem ctx festhalten.
	fin, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_ = r.store.Write(fin, func(q *dbq.Queries) error {
		end := store.Now()
		switch {
		case runErr == nil:
			return q.FinishJob(fin, dbq.FinishJobParams{Status: Succeeded, FinishedAt: &end, ID: j.ID})
		case ctx.Err() != nil:
			// Dienst faehrt herunter: beim naechsten Start erneut versuchen.
			msg := "abgebrochen: " + runErr.Error()
			return q.RetryJob(fin, dbq.RetryJobParams{Error: &msg, RunAfter: end, ID: j.ID})
		case !ok || j.Attempts >= MaxAttempts:
			msg := runErr.Error()
			return q.FinishJob(fin, dbq.FinishJobParams{Status: Failed, Error: &msg, FinishedAt: &end, ID: j.ID})
		default:
			msg := runErr.Error()
			next := store.FormatTime(time.Now().Add(r.Backoff(j.Attempts)))
			return q.RetryJob(fin, dbq.RetryJobParams{Error: &msg, RunAfter: next, ID: j.ID})
		}
	})
	if runErr != nil {
		r.log.Warn("Job fehlgeschlagen", "job", j.ID, "kind", j.Kind, "resource", j.Resource, "attempt", j.Attempts, "error", runErr)
	} else {
		r.log.Info("Job erledigt", "job", j.ID, "kind", j.Kind, "resource", j.Resource)
	}
}

type errUnknownKind string

func (e errUnknownKind) Error() string { return "unbekannte Job-Art " + string(e) }

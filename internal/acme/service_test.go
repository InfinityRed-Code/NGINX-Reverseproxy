package acme_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/acme"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/domain"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/jobs"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store/dbq"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/testutil"
)

type fakeIssuer struct {
	t        *testing.T
	mu       sync.Mutex
	failures map[string]int // verbleibende Fehlversuche je FQDN
	issued   map[string]int
	revoked  []string
	renewAt  *time.Time
	active   int
	maxPar   int
}

func (f *fakeIssuer) Obtain(_ context.Context, fqdn string) (*acme.Issued, error) {
	f.mu.Lock()
	f.active++
	f.maxPar = max(f.maxPar, f.active)
	fail := f.failures[fqdn] > 0
	if fail {
		f.failures[fqdn]--
	}
	f.mu.Unlock()
	time.Sleep(30 * time.Millisecond)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.active--
	if fail {
		return nil, errors.New("acme: urn:ietf:params:acme:error:connection")
	}
	f.issued[fqdn]++
	chain, key := testutil.SelfSigned(f.t, fqdn, time.Now().Add(90*24*time.Hour))
	return &acme.Issued{ChainPEM: chain, KeyPEM: key}, nil
}

func (f *fakeIssuer) Revoke(_ context.Context, chain string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, chain)
	return nil
}

func (f *fakeIssuer) RenewAt(context.Context, string) (*time.Time, error) { return f.renewAt, nil }

type env struct {
	st     *store.Store
	svc    *acme.Service
	iss    *fakeIssuer
	runner *jobs.Runner
	change chan struct{}
}

func newEnv(t *testing.T) (*env, context.Context) {
	st, box := testutil.Store(t), testutil.Box(t)
	e := &env{st: st, iss: &fakeIssuer{t: t, failures: map[string]int{}, issued: map[string]int{}}, change: make(chan struct{}, 64)}
	e.runner = jobs.NewRunner(st, 4, nil)
	e.runner.Backoff = func(int64) time.Duration { return 10 * time.Millisecond }
	e.runner.Tick = 20 * time.Millisecond
	e.svc = &acme.Service{Store: st, Box: box, Issuer: e.iss, Notify: e.runner.Notify, OnChange: func() { e.change <- struct{}{} }}
	e.runner.Handle(jobs.CertIssue, e.svc.HandleIssue)
	e.runner.Handle(jobs.CertRenew, e.svc.HandleIssue)
	e.runner.Handle(jobs.CertRevoke, e.svc.HandleRevoke)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.runner.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return e, ctx
}

func (e *env) addHost(t *testing.T, ctx context.Context, fqdn string, enqueue bool) string {
	var id string
	err := e.st.Write(ctx, func(q *dbq.Queries) error {
		now := store.Now()
		if err := q.InsertHost(ctx, dbq.InsertHostParams{Fqdn: fqdn, UpstreamScheme: "http", UpstreamAddress: "10.0.0.1",
			UpstreamPort: 80, ExternalPort: 443, Status: domain.HostPending, CreatedAt: now, UpdatedAt: now}); err != nil {
			return err
		}
		if enqueue {
			j, err := jobs.Enqueue(ctx, q, jobs.CertIssue, fqdn, "test")
			id = j.ID
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	e.runner.Notify()
	return id
}

func (e *env) waitJob(t *testing.T, ctx context.Context, id, want string) dbq.Job {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		j, err := e.st.Read().GetJob(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if j.Status == want {
			return j
		}
		if time.Now().After(deadline) {
			t.Fatalf("Job %s: Status %s (Fehler %v), erwartet %s", id, j.Status, j.Error, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestIssueStoresEncryptedCertificate(t *testing.T) {
	e, ctx := newEnv(t)
	ari := time.Now().Add(60 * 24 * time.Hour)
	e.iss.renewAt = &ari
	id := e.addHost(t, ctx, "app.example.com", true)
	e.waitJob(t, ctx, id, jobs.Succeeded)

	cert, err := e.st.Read().GetCertificate(ctx, "app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cert.Source != "acme" || cert.Issuer != "NRP Test" || cert.AriRenewAt == nil {
		t.Fatalf("Zertifikat: %+v", cert)
	}
	key, err := e.svc.Box.Open(cert.KeyEnc)
	if err != nil || len(key) == 0 || string(cert.KeyEnc) == string(key) {
		t.Fatal("Schluessel liegt nicht verschluesselt in der DB")
	}
	if !acme.RenewalTime(cert).Equal(store.ParseTime(*cert.AriRenewAt)) {
		t.Error("ARI-Zeitpunkt wird nicht bevorzugt")
	}
	h, _ := e.st.Read().GetHost(ctx, "app.example.com")
	if h.Status != domain.HostActive {
		t.Errorf("Host-Status %s", h.Status)
	}
	select {
	case <-e.change:
	case <-time.After(time.Second):
		t.Error("Reconcile wurde nach der Ausstellung nicht angestossen")
	}
	last, _ := e.st.Read().LastAuditEntry(ctx)
	if last.Action != "certificate.issue" || last.ActorType != "system" {
		t.Errorf("Audit: %+v", last)
	}
}

func TestRetryWithBackoffAndHostError(t *testing.T) {
	e, ctx := newEnv(t)
	e.iss.failures["flaky.example.com"] = 2
	id := e.addHost(t, ctx, "flaky.example.com", true)
	j := e.waitJob(t, ctx, id, jobs.Succeeded)
	if j.Attempts != 3 {
		t.Errorf("%d Versuche, erwartet 3", j.Attempts)
	}

	e.iss.failures["dead.example.com"] = 1000
	id = e.addHost(t, ctx, "dead.example.com", true)
	j = e.waitJob(t, ctx, id, jobs.Failed)
	if j.Attempts != jobs.MaxAttempts || j.Error == nil {
		t.Errorf("endgueltig fehlgeschlagen nach %d Versuchen (%v)", j.Attempts, j.Error)
	}
	h, _ := e.st.Read().GetHost(ctx, "dead.example.com")
	if h.Status != domain.HostError || h.StatusDetail == nil || (*h.StatusDetail)[:5] != "ACME:" {
		t.Errorf("Host nach ACME-Fehler: %s %v", h.Status, h.StatusDetail)
	}
}

func TestWorkerPoolRunsInParallelWithLockPerFQDN(t *testing.T) {
	e, ctx := newEnv(t)
	var ids []string
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		ids = append(ids, e.addHost(t, ctx, n+".example.com", true))
	}
	// Zwei Jobs fuer denselben Namen duerfen nie gleichzeitig laufen.
	var dup string
	_ = e.st.Write(ctx, func(q *dbq.Queries) error {
		j, err := jobs.Enqueue(ctx, q, jobs.CertRenew, "a.example.com", "test")
		dup = j.ID
		return err
	})
	e.runner.Notify()
	for _, id := range append(ids, dup) {
		e.waitJob(t, ctx, id, jobs.Succeeded)
	}
	e.iss.mu.Lock()
	defer e.iss.mu.Unlock()
	if e.iss.maxPar < 2 || e.iss.maxPar > 4 {
		t.Errorf("maximale Parallelitaet %d, erwartet 2..4 (Worker-Pool mit 4)", e.iss.maxPar)
	}
	if e.iss.issued["a.example.com"] != 2 {
		t.Errorf("a.example.com %d-mal ausgestellt, erwartet 2", e.iss.issued["a.example.com"])
	}
}

func TestScheduleRenewalsAndRevoke(t *testing.T) {
	e, ctx := newEnv(t)
	// due: Zertifikat laeuft bald ab; fresh: gerade ausgestellt; missing: Host ohne Zertifikat.
	for _, n := range []string{"due.example.com", "fresh.example.com", "missing.example.com"} {
		e.addHost(t, ctx, n, false)
	}
	err := e.st.Write(ctx, func(q *dbq.Queries) error {
		chain, key := testutil.SelfSigned(t, "due.example.com", time.Now().Add(10*time.Minute))
		if _, err := acme.StoreCertificate(ctx, q, e.svc.Box, "due.example.com", chain, key, "imported", nil); err != nil {
			return err
		}
		chain, key = testutil.SelfSigned(t, "fresh.example.com", time.Now().Add(90*24*time.Hour))
		_, err := acme.StoreCertificate(ctx, q, e.svc.Box, "fresh.example.com", chain, key, "acme", nil)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Schedule(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Schedule(ctx); err != nil { // zweiter Lauf darf nichts doppelt einreihen
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		all, _ := e.st.Read().ListJobs(ctx, dbq.ListJobsParams{Lim: 50})
		done := 0
		kinds := map[string]string{}
		for _, j := range all {
			kinds[j.Resource] = j.Kind
			if j.Status == jobs.Succeeded {
				done++
			}
		}
		if len(all) == 2 && done == 2 {
			if kinds["due.example.com"] != jobs.CertRenew || kinds["missing.example.com"] != jobs.CertIssue {
				t.Fatalf("eingereihte Jobs: %v", kinds)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Jobs: %+v", all)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Das importierte Zertifikat wurde per ACME ersetzt.
	if c, _ := e.st.Read().GetCertificate(ctx, "due.example.com"); c.Source != "acme" {
		t.Errorf("importiertes Zertifikat nicht ersetzt: %s", c.Source)
	}

	var id string
	_ = e.st.Write(ctx, func(q *dbq.Queries) error {
		j, err := jobs.Enqueue(ctx, q, jobs.CertRevoke, "fresh.example.com", "test")
		id = j.ID
		return err
	})
	e.runner.Notify()
	e.waitJob(t, ctx, id, jobs.Succeeded)
	if _, err := e.st.Read().GetCertificate(ctx, "fresh.example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Error("widerrufenes Zertifikat wurde nicht entfernt")
	}
	if len(e.iss.revoked) != 1 {
		t.Errorf("%d Widerrufe bei der CA", len(e.iss.revoked))
	}
}

func TestStoreCertificateRejectsWrongName(t *testing.T) {
	st, box := testutil.Store(t), testutil.Box(t)
	ctx := context.Background()
	chain, key := testutil.SelfSigned(t, "other.example.com", time.Now().Add(time.Hour))
	err := st.Write(ctx, func(q *dbq.Queries) error {
		_, err := acme.StoreCertificate(ctx, q, box, "app.example.com", chain, key, "imported", nil)
		return err
	})
	if err == nil {
		t.Fatal("Zertifikat fuer einen anderen Namen wurde gespeichert")
	}
}

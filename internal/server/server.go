// Package server implementiert die REST-API (api/openapi.yaml). Derselbe
// Handler bedient mTLS-Listener, Unix-Socket und den Offline-Modus der CLI.
// Handler schreiben nur in die DB (Zustand + Audit in einer Transaktion); das
// Anwenden uebernimmt der Reconciler.
package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/apigen"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/audit"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/auth"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/config"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/nginx"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/pki"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/reconcile"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/secrets"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store/dbq"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/wireguard"
)

const (
	BasePath       = "/api/v1"
	ModeService    = "service"
	ModeOffline    = "offline"
	maxBodyBytes   = 1 << 20
	idempotencyTTL = 24 * time.Hour
)

type Deps struct {
	Cfg        config.Config
	Store      *store.Store
	Box        *secrets.Box
	Reconciler *reconcile.Reconciler
	Nginx      *nginx.Controller
	// WG ist nil, wenn WireGuard deaktiviert ist oder (offline) nicht gesteuert wird.
	WG        wireguard.Manager
	JobNotify func()
	Version   string
	Mode      string
	Log       *slog.Logger
}

type Server struct {
	d       Deps
	limiter *failLimiter

	touchMu sync.Mutex
	touched map[string]time.Time

	authFailures atomic.Int64
	crsVersion   sync.Once
	crsVer       string
}

func New(d Deps) *Server {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.JobNotify == nil {
		d.JobNotify = func() {}
	}
	if d.Mode == "" {
		d.Mode = ModeService
	}
	return &Server{d: d, limiter: newFailLimiter(10, time.Minute), touched: map[string]time.Time{}}
}

// Handler liefert den vollstaendigen API-Handler inklusive Middleware.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(s.requestContext, s.recoverer, s.authenticate)
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		s.writeError(w, r, errf(http.StatusNotFound, "Pfad %s existiert nicht", r.URL.Path))
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		s.writeError(w, r, errf(http.StatusMethodNotAllowed, "Methode %s ist hier nicht erlaubt", r.Method))
	})
	return apigen.HandlerWithOptions(s, apigen.ChiServerOptions{
		BaseURL:    BasePath,
		BaseRouter: r,
		// Die letzte Middleware laeuft zuerst: erst Rolle pruefen, dann Idempotenz.
		Middlewares: []apigen.MiddlewareFunc{s.idempotency, s.authorize},
		ErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			s.writeError(w, r, errf(http.StatusBadRequest, "%v", err))
		},
	})
}

// ── Fehler und Antworten ────────────────────────────────────────────────────

type apiError struct {
	Status int
	Detail string
}

func (e *apiError) Error() string { return e.Detail }

func errf(status int, format string, a ...any) *apiError {
	return &apiError{Status: status, Detail: fmt.Sprintf(format, a...)}
}

func badRequest(err error) *apiError { return errf(http.StatusBadRequest, "%v", err) }

func notFound(kind, id string) *apiError {
	return errf(http.StatusNotFound, "%s %q nicht gefunden", kind, id)
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	var ae *apiError
	if !errors.As(err, &ae) {
		s.d.Log.Error("interner Fehler", "path", r.URL.Path, "request_id", requestID(r), "error", err)
		ae = errf(http.StatusInternalServerError, "interner Fehler")
	}
	rid := requestID(r)
	p := apigen.Problem{Type: "about:blank", Title: http.StatusText(ae.Status), Status: ae.Status, Detail: &ae.Detail, RequestId: &rid}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(ae.Status)
	_ = json.NewEncoder(w).Encode(p)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decode(r *http.Request, v any) error {
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxBodyBytes))
	if err != nil {
		return errf(http.StatusRequestEntityTooLarge, "Anfrage zu gross oder nicht lesbar")
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errf(http.StatusBadRequest, "ungueltiges JSON: %v", err)
	}
	return nil
}

func etag(version int64) string { return `"` + strconv.FormatInt(version, 10) + `"` }

// checkIfMatch setzt Optimistic Locking durch: If-Match muss die Version nennen.
func checkIfMatch(header *string, version int64) error {
	if header == nil || strings.TrimSpace(*header) == "" {
		return errf(http.StatusPreconditionRequired, "If-Match fehlt (ETag aus einem vorherigen GET angeben)")
	}
	for _, tag := range strings.Split(*header, ",") {
		tag = strings.Trim(strings.TrimPrefix(strings.TrimSpace(tag), "W/"), `"`)
		if tag == "*" || tag == strconv.FormatInt(version, 10) {
			return nil
		}
	}
	return errf(http.StatusPreconditionFailed, "Ressource wurde zwischenzeitlich geaendert (aktuelle Version %d)", version)
}

func flag(p *bool) bool { return p != nil && *p }

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func nilIfEmpty(p *string) *string {
	if p == nil || strings.TrimSpace(*p) == "" {
		return nil
	}
	v := strings.TrimSpace(*p)
	return &v
}

func timePtr(s *string) *time.Time {
	if s == nil {
		return nil
	}
	t := store.ParseTime(*s)
	if t.IsZero() {
		return nil
	}
	return &t
}

func isNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }

// ── Request-Kontext ─────────────────────────────────────────────────────────

type reqInfoKey struct{}

type reqInfo struct {
	id string
	ip string
}

func newRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func requestID(r *http.Request) string {
	if i, ok := r.Context().Value(reqInfoKey{}).(reqInfo); ok {
		return i.id
	}
	return ""
}

func sourceIP(r *http.Request) string {
	if i, ok := r.Context().Value(reqInfoKey{}).(reqInfo); ok {
		return i.ip
	}
	return ""
}

func (s *Server) requestContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := reqInfo{id: newRequestID()}
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			info.ip = host
		}
		w.Header().Set("X-Request-Id", info.id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), reqInfoKey{}, info)))
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil && rec != http.ErrAbortHandler {
				s.writeError(w, r, fmt.Errorf("panic: %v", rec))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// ── Authentifizierung ───────────────────────────────────────────────────────

// failLimiter begrenzt fehlgeschlagene Authentifizierungen je Quell-IP.
type failLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string]*failWindow
}

type failWindow struct {
	start time.Time
	n     int
}

func newFailLimiter(max int, window time.Duration) *failLimiter {
	return &failLimiter{max: max, window: window, hits: map[string]*failWindow{}}
}

func (l *failLimiter) blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.hits[ip]
	if w == nil {
		return false
	}
	if time.Since(w.start) > l.window {
		delete(l.hits, ip)
		return false
	}
	return w.n >= l.max
}

func (l *failLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.hits) > 10000 { // Speicher begrenzen
		for k, w := range l.hits {
			if time.Since(w.start) > l.window {
				delete(l.hits, k)
			}
		}
	}
	w := l.hits[ip]
	if w == nil || time.Since(w.start) > l.window {
		w = &failWindow{start: time.Now()}
		l.hits[ip] = w
	}
	w.n++
}

func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if _, ok := auth.FromContext(ctx); ok { // Unix-Socket oder Offline-Modus
			next.ServeHTTP(w, r)
			return
		}
		ip := sourceIP(r)
		if s.limiter.blocked(ip) {
			w.Header().Set("Retry-After", "60")
			s.writeError(w, r, errf(http.StatusTooManyRequests, "zu viele fehlgeschlagene Anmeldungen"))
			return
		}
		id, err := s.identify(r)
		if err != nil {
			s.limiter.fail(ip)
			s.authFailures.Add(1)
			e := s.entry(r)
			e.ActorType, e.ActorID = authKind(r), "unknown"
			e.Fingerprint = id.Fingerprint
			e.Action, e.ResourceType, e.ResourceID = "auth.failed", "api", r.Method+" "+r.URL.Path
			e.Result, e.Error = audit.Denied, err.Error()
			s.auditOwnTx(ctx, e)
			s.writeError(w, r, errf(http.StatusUnauthorized, "nicht authentifiziert"))
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithIdentity(ctx, id)))
	})
}

func authKind(r *http.Request) string {
	if auth.IsTokenListener(r.Context()) {
		return auth.TypeToken
	}
	return auth.TypeMTLS
}

// identify ordnet die Anfrage einer Identitaet zu. Die Rolle steht nie im
// Zertifikat, sondern wird ueber den Fingerprint in api_clients nachgeschlagen.
func (s *Server) identify(r *http.Request) (auth.Identity, error) {
	ctx := r.Context()
	q := s.d.Store.Read()
	now := time.Now()
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		fp := pki.Fingerprint(r.TLS.PeerCertificates[0])
		id := auth.Identity{Type: auth.TypeMTLS, Fingerprint: fp}
		c, err := q.GetClientByFingerprint(ctx, fp)
		switch {
		case isNoRows(err):
			return id, errors.New("Client-Zertifikat ist nicht registriert")
		case err != nil:
			return id, err
		case c.Disabled != 0:
			return id, fmt.Errorf("Client %s ist widerrufen", c.Name)
		case !store.ParseTime(c.NotAfter).After(now):
			return id, fmt.Errorf("Client %s ist abgelaufen", c.Name)
		}
		id.ID, id.Role = c.Name, auth.Role(c.Role)
		s.touch("c:"+c.ID, func(q *dbq.Queries, ts string) error {
			return q.TouchClient(ctx, dbq.TouchClientParams{LastUsedAt: &ts, ID: c.ID})
		})
		return id, nil
	}
	if auth.IsTokenListener(ctx) && s.d.Cfg.TokensEnabled {
		id := auth.Identity{Type: auth.TypeToken}
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		tid, secret, valid := auth.ParseToken(strings.TrimSpace(raw))
		if !ok || !valid {
			return id, errors.New("Bearer-Token fehlt oder hat ein ungueltiges Format")
		}
		t, err := q.GetToken(ctx, tid)
		switch {
		case isNoRows(err):
			return id, errors.New("Token unbekannt")
		case err != nil:
			return id, err
		case !auth.TokenMatches(secret, t.SecretSha256):
			return id, errors.New("Token-Secret falsch")
		case t.Disabled != 0:
			return id, fmt.Errorf("Token %s ist widerrufen", t.ID)
		case !store.ParseTime(t.ExpiresAt).After(now):
			return id, fmt.Errorf("Token %s ist abgelaufen", t.ID)
		}
		id.ID, id.Role = t.ID, auth.Role(t.Role)
		s.touch("t:"+t.ID, func(q *dbq.Queries, ts string) error {
			return q.TouchToken(ctx, dbq.TouchTokenParams{LastUsedAt: &ts, ID: t.ID})
		})
		return id, nil
	}
	return auth.Identity{Type: authKind(r)}, errors.New("keine Anmeldedaten")
}

// touch aktualisiert last_used_at hoechstens einmal pro Minute und Identitaet.
func (s *Server) touch(key string, fn func(q *dbq.Queries, ts string) error) {
	s.touchMu.Lock()
	recent := time.Since(s.touched[key]) < time.Minute
	if !recent {
		s.touched[key] = time.Now()
	}
	s.touchMu.Unlock()
	if recent {
		return
	}
	_ = s.d.Store.Write(context.Background(), func(q *dbq.Queries) error { return fn(q, store.Now()) })
}

func identity(r *http.Request) auth.Identity {
	id, _ := auth.FromContext(r.Context())
	return id
}

// authorize prueft die Mindestrolle aus dem Security-Scope der Operation.
func (s *Server) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		need := auth.Admin
		if scopes, ok := r.Context().Value(apigen.MtlsScopes).([]string); ok && len(scopes) > 0 {
			need = auth.Role(scopes[0])
		}
		id := identity(r)
		if !id.Role.Allows(need) {
			e := s.entry(r)
			e.Action, e.ResourceType, e.ResourceID = "api.denied", "api", r.Method+" "+chi.RouteContext(r.Context()).RoutePattern()
			e.Result, e.Error = audit.Denied, fmt.Sprintf("Rolle %s erforderlich, vorhanden %s", need, id.Role)
			s.auditOwnTx(r.Context(), e)
			s.writeError(w, r, errf(http.StatusForbidden, "Rolle %s erforderlich", need))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireLocal beschraenkt eine Operation auf Socket bzw. Offline-Modus.
func (s *Server) requireLocal(w http.ResponseWriter, r *http.Request, action string) bool {
	if identity(r).IsLocal() {
		return true
	}
	e := s.entry(r)
	e.Action, e.ResourceType, e.Result, e.Error = action, "api", audit.Denied, "nur lokal erlaubt"
	s.auditOwnTx(r.Context(), e)
	s.writeError(w, r, errf(http.StatusForbidden, "nur lokal erlaubt (docker exec nrp nrp ...)"))
	return false
}

// ── Idempotenz ──────────────────────────────────────────────────────────────

type capture struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (c *capture) WriteHeader(code int) { c.status = code; c.ResponseWriter.WriteHeader(code) }
func (c *capture) Write(b []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	c.body.Write(b)
	return c.ResponseWriter.Write(b)
}

// idempotency liefert bei wiederholtem POST mit gleichem Idempotency-Key die
// gespeicherte Antwort (24 h, je Akteur).
func (s *Server) idempotency(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Idempotency-Key")
		if r.Method != http.MethodPost || key == "" {
			next.ServeHTTP(w, r)
			return
		}
		if len(key) > 128 {
			s.writeError(w, r, errf(http.StatusBadRequest, "Idempotency-Key ist zu lang"))
			return
		}
		ctx := r.Context()
		actor := identity(r).Actor()
		key = r.URL.Path + "|" + key
		saved, err := s.d.Store.Read().GetIdempotencyKey(ctx, dbq.GetIdempotencyKeyParams{Key: key, Actor: actor})
		if err == nil && time.Since(store.ParseTime(saved.CreatedAt)) < idempotencyTTL {
			var hdr map[string]string
			_ = json.Unmarshal([]byte(saved.Headers), &hdr)
			for k, v := range hdr {
				w.Header().Set(k, v)
			}
			w.Header().Set("Idempotent-Replayed", "true")
			w.WriteHeader(int(saved.Status))
			_, _ = w.Write(saved.Response)
			return
		}
		c := &capture{ResponseWriter: w}
		next.ServeHTTP(c, r)
		if c.status == 0 || c.status >= 500 {
			return
		}
		hdr := map[string]string{}
		for _, k := range []string{"Content-Type", "Location", "ETag"} {
			if v := w.Header().Get(k); v != "" {
				hdr[k] = v
			}
		}
		hj, _ := json.Marshal(hdr)
		_ = s.d.Store.Write(ctx, func(q *dbq.Queries) error {
			if err := q.PruneIdempotencyKeys(ctx, store.FormatTime(time.Now().Add(-idempotencyTTL))); err != nil {
				return err
			}
			return q.InsertIdempotencyKey(ctx, dbq.InsertIdempotencyKeyParams{Key: key, Actor: actor,
				Status: int64(c.status), Headers: string(hj), Response: c.body.Bytes(), CreatedAt: store.Now()})
		})
	})
}

// ── Audit und Schreibtransaktionen ──────────────────────────────────────────

func (s *Server) entry(r *http.Request) audit.Entry {
	id := identity(r)
	return audit.Entry{RequestID: requestID(r), ActorType: id.Type, ActorID: id.ID, Fingerprint: id.Fingerprint, SourceIP: sourceIP(r)}
}

func (s *Server) auditOwnTx(ctx context.Context, e audit.Entry) {
	var row dbq.AuditLog
	err := s.d.Store.Write(context.WithoutCancel(ctx), func(q *dbq.Queries) (err error) {
		row, err = audit.Append(ctx, q, e)
		return err
	})
	if err != nil {
		s.d.Log.Error("Audit-Eintrag konnte nicht geschrieben werden", "action", e.Action, "error", err)
		return
	}
	audit.Emit(row)
}

// tx ist der Kontext einer Schreibtransaktion: Zustand und Audit gemeinsam.
type tx struct {
	ctx  context.Context
	q    *dbq.Queries
	base audit.Entry
	rows []dbq.AuditLog
}

func (t *tx) audit(action, resType, resID string, before, after any) error {
	e := t.base
	e.Action, e.ResourceType, e.ResourceID, e.Before, e.After, e.Result = action, resType, resID, before, after, audit.Success
	row, err := audit.Append(t.ctx, t.q, e)
	if err == nil {
		t.rows = append(t.rows, row)
	}
	return err
}

// mutate fuehrt fn in einer Schreibtransaktion aus. Ohne Audit-Eintrag gibt es
// keine Aenderung; Fehlschlaege werden separat als failed protokolliert.
func (s *Server) mutate(w http.ResponseWriter, r *http.Request, action, resType, resID string, fn func(t *tx) error) bool {
	ctx := r.Context()
	t := &tx{ctx: ctx, base: s.entry(r)}
	err := s.d.Store.Write(ctx, func(q *dbq.Queries) error {
		t.q, t.rows = q, nil
		return fn(t)
	})
	if err != nil {
		e := s.entry(r)
		e.Action, e.ResourceType, e.ResourceID, e.Result, e.Error = action, resType, resID, audit.Failed, err.Error()
		s.auditOwnTx(ctx, e)
		s.writeError(w, r, err)
		return false
	}
	audit.Emit(t.rows...)
	s.d.Reconciler.Trigger()
	return true
}

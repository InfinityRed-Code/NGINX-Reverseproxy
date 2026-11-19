package server_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/apigen"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/audit"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/auth"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/config"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/nginx"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/pki"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/reconcile"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/secrets"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/server"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store/dbq"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/testutil"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/wireguard"
)

type fakeNginx struct{}

func (fakeNginx) Test(context.Context, string) (string, error)     { return "", nil }
func (fakeNginx) CheckWAF(context.Context, string) (string, error) { return "", nil }
func (fakeNginx) Reload(context.Context) error                     { return nginx.ErrNotRunning }
func (fakeNginx) Running() bool                                    { return false }

type env struct {
	t   *testing.T
	cfg config.Config
	st  *store.Store
	box *secrets.Box
	srv *server.Server
	h   http.Handler
}

var (
	local    = auth.Identity{Type: auth.TypeLocal, ID: "uid=0", Role: auth.Admin}
	viewer   = auth.Identity{Type: auth.TypeMTLS, ID: "vera", Role: auth.Viewer}
	operator = auth.Identity{Type: auth.TypeMTLS, ID: "otto", Role: auth.Operator}
	admin    = auth.Identity{Type: auth.TypeMTLS, ID: "anna", Role: auth.Admin}
)

func newEnv(t *testing.T, mod func(*config.Config)) *env {
	t.Helper()
	tmp := t.TempDir()
	cfg := config.Config{DBDir: tmp + "/db", BackupDir: tmp + "/backups", RunDir: filepath.ToSlash(tmp) + "/run", LogDir: tmp + "/log",
		CRSDir: tmp + "/crs", HTMLDir: tmp + "/html", NginxBin: "nrp-test-no-nginx", NginxConf: tmp + "/nginx.conf",
		WireGuardEnabled: true, WGOverlayCIDR: "10.240.0.0/16", WGPort: 51820, PublicEndpoint: "proxy.example.com",
		APISANs: []string{"localhost", "127.0.0.1"}}
	if mod != nil {
		mod(&cfg)
	}
	st, box := testutil.Store(t), testutil.Box(t)
	ctx := context.Background()
	if cfg.WireGuardEnabled {
		if _, err := wireguard.EnsureHub(ctx, st, box, cfg.WGOverlayCIDR, cfg.WGPort); err != nil {
			t.Fatal(err)
		}
	}
	rec := reconcile.New(cfg, st, box, fakeNginx{}, nil, nil)
	srv := server.New(server.Deps{Cfg: cfg, Store: st, Box: box, Reconciler: rec, Nginx: nginx.New(cfg.NginxBin, ""), Version: "test"})
	return &env{t: t, cfg: cfg, st: st, box: box, srv: srv, h: srv.Handler()}
}

type resp struct {
	code int
	hdr  http.Header
	body []byte
}

func (r resp) json(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("Antwort nicht lesbar (%d): %s", r.code, r.body)
	}
}

func (e *env) do(id auth.Identity, method, path string, body any, hdr ...string) resp {
	e.t.Helper()
	var rd io.Reader
	if s, ok := body.(string); ok {
		rd = strings.NewReader(s)
	} else if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://nrp"+server.BasePath+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := server.InProcess{Handler: e.h, Identity: id}.RoundTrip(req)
	if err != nil {
		e.t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	return resp{res.StatusCode, res.Header, b}
}

func (e *env) want(r resp, code int) resp {
	e.t.Helper()
	if r.code != code {
		e.t.Fatalf("HTTP %d, erwartet %d: %s", r.code, code, r.body)
	}
	return r
}

func (e *env) auditCount() int64 {
	res, err := audit.Verify(context.Background(), e.st.Read())
	if err != nil || !res.OK {
		e.t.Fatalf("Audit-Kette nicht intakt: %+v %v", res, err)
	}
	return res.Entries
}

func (e *env) lastAudit() dbq.AuditLog {
	row, err := e.st.Read().LastAuditEntry(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	return row
}

func hostBody(fqdn string) map[string]any {
	return map[string]any{"fqdn": fqdn, "upstream": map[string]any{"scheme": "http", "address": "192.168.1.10", "port": 8080}}
}

// ── Rollenmatrix ────────────────────────────────────────────────────────────

// Jede Operation der Spezifikation wird mit jeder Rolle aufgerufen: unterhalb
// der Mindestrolle 403, sonst alles ausser 401/403.
func TestRoleMatrixFromSpec(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.TokensEnabled = true })
	spec, err := apigen.GetSwagger()
	if err != nil {
		t.Fatal(err)
	}
	rank := map[string]int{"viewer": 1, "operator": 2, "admin": 3}
	ids := map[string]auth.Identity{"viewer": viewer, "operator": operator, "admin": admin}
	n := 0
	for path, item := range spec.Paths.Map() {
		for method, op := range item.Operations() {
			need := "viewer"
			sec := spec.Security
			if op.Security != nil {
				sec = *op.Security
			}
			if len(sec) > 0 && len(sec[0]["mtls"]) > 0 {
				need = sec[0]["mtls"][0]
			}
			url := strings.NewReplacer("{fqdn}", "x.example.com", "{name}", "nobody", "{id}", "01HZZZZZZZZZZZZZZZZZZZZZZZ").Replace(path)
			for role, id := range ids {
				r := e.do(id, method, url, "{}", "If-Match", `"1"`)
				n++
				if rank[role] < rank[need] {
					if r.code != http.StatusForbidden {
						t.Errorf("%s %s als %s: HTTP %d, erwartet 403 (Mindestrolle %s)", method, path, role, r.code, need)
					}
				} else if r.code == http.StatusForbidden && !strings.Contains(string(r.body), "nur lokal") || r.code == http.StatusUnauthorized {
					t.Errorf("%s %s als %s: HTTP %d trotz ausreichender Rolle %s: %s", method, path, role, r.code, need, r.body)
				}
			}
		}
	}
	if n < 100 {
		t.Fatalf("nur %d Kombinationen geprueft; Spezifikation unvollstaendig geladen?", n)
	}
}

// Die Tabelle aus rewrite.md 6.6, unabhaengig von der Spezifikation.
func TestRoleMatrixTable(t *testing.T) {
	e := newEnv(t, nil)
	e.want(e.do(local, "POST", "/sites", map[string]any{"name": "home"}), 201)
	e.want(e.do(local, "POST", "/hosts", hostBody("app.example.com")), 201)
	cases := []struct {
		method, path string
		body         any
		min          string
	}{
		{"GET", "/hosts", nil, "viewer"},
		{"GET", "/sites", nil, "viewer"},
		{"GET", "/certificates", nil, "viewer"},
		{"GET", "/status", nil, "viewer"},
		{"GET", "/jobs", nil, "viewer"},
		{"POST", "/hosts", hostBody("new.example.com"), "operator"},
		{"PATCH", "/hosts/app.example.com", map[string]any{"waf": true}, "operator"},
		{"DELETE", "/hosts/missing.example.com", nil, "operator"},
		{"POST", "/certificates/app.example.com/renew", nil, "operator"},
		{"POST", "/sites", map[string]any{"name": "office"}, "admin"},
		{"PATCH", "/sites/home", map[string]any{"notes": "x"}, "admin"},
		{"DELETE", "/sites/missing", nil, "admin"},
		{"PUT", "/sites/home/public-key", map[string]any{"public_key": "x"}, "admin"},
		{"POST", "/sites/home/rotate-psk", nil, "admin"},
		{"GET", "/sites/home/install-script", nil, "admin"},
		{"PUT", "/waf", map[string]any{"mode": "On"}, "admin"},
		{"PATCH", "/settings", map[string]any{"client_max_body_size": "1M"}, "admin"},
		{"GET", "/clients", nil, "admin"},
		{"POST", "/clients", map[string]any{"name": "x", "role": "viewer"}, "admin"},
		{"GET", "/tokens", nil, "admin"},
		{"GET", "/audit", nil, "admin"},
		{"GET", "/audit/verify", nil, "admin"},
		{"POST", "/render/rollback", map[string]any{"generation": 1}, "admin"},
		{"POST", "/render/reconcile", nil, "admin"},
		{"GET", "/render/current", nil, "admin"},
		{"DELETE", "/certificates/app.example.com", nil, "admin"},
	}
	rank := map[string]int{"viewer": 1, "operator": 2, "admin": 3}
	for _, c := range cases {
		for role, id := range map[string]auth.Identity{"viewer": viewer, "operator": operator, "admin": admin} {
			r := e.do(id, c.method, c.path, c.body, "If-Match", "*")
			denied := r.code == http.StatusForbidden
			if denied != (rank[role] < rank[c.min]) {
				t.Errorf("%s %s als %s: HTTP %d (Mindestrolle %s)", c.method, c.path, role, r.code, c.min)
			}
		}
	}
	// Verweigerte Zugriffe stehen im Audit-Log.
	before := e.auditCount()
	e.want(e.do(viewer, "POST", "/hosts", hostBody("denied.example.com")), 403)
	if a := e.lastAudit(); e.auditCount() != before+1 || a.Result != audit.Denied || a.ActorID != "vera" || a.Action != "api.denied" {
		t.Errorf("verweigerter Zugriff nicht protokolliert: %+v", a)
	}
}

// ── Hosts: Ablauf, Optimistic Locking, Idempotenz ───────────────────────────

func TestHostLifecycle(t *testing.T) {
	e := newEnv(t, nil)
	var created apigen.HostCreated
	r := e.want(e.do(operator, "POST", "/hosts", hostBody("App.Example.com.")), 201)
	r.json(t, &created)
	if created.Host.Fqdn != "app.example.com" || created.Host.Status != apigen.PendingCertificate || created.Job == nil ||
		created.Job.Kind != apigen.CertIssue || created.Host.ExternalPort != 443 || created.Host.Version != 1 {
		t.Fatalf("angelegter Host: %s", r.body)
	}
	if loc := r.hdr.Get("Location"); loc != "/api/v1/jobs/"+created.Job.Id {
		t.Errorf("Location = %q", loc)
	}
	if r.hdr.Get("X-Request-Id") == "" {
		t.Error("X-Request-Id fehlt")
	}
	if a := e.lastAudit(); a.Action != "host.create" || a.RequestID != r.hdr.Get("X-Request-Id") || a.ActorType != "mtls" || a.ActorID != "otto" {
		t.Errorf("Audit-Eintrag: %+v", a)
	}
	e.want(e.do(operator, "POST", "/hosts", hostBody("app.example.com")), 409)

	get := e.want(e.do(viewer, "GET", "/hosts/app.example.com", nil), 200)
	tag := get.hdr.Get("ETag")
	if tag != `"1"` {
		t.Fatalf("ETag = %q", tag)
	}
	patch := map[string]any{"waf": true, "upstream": map[string]any{"port": 9090}, "client_max_body_size": "1g"}
	e.want(e.do(operator, "PATCH", "/hosts/app.example.com", patch), 428)
	e.want(e.do(operator, "PATCH", "/hosts/app.example.com", patch, "If-Match", `"7"`), 412)
	var h apigen.Host
	e.want(e.do(operator, "PATCH", "/hosts/app.example.com", patch, "If-Match", tag), 200).json(t, &h)
	if !h.Waf || h.Upstream.Port != 9090 || h.Upstream.Address != "192.168.1.10" || *h.ClientMaxBodySize != "1g" || h.Version != 2 {
		t.Fatalf("PATCH-Ergebnis: %+v", h)
	}
	// Der alte ETag gilt nicht mehr.
	e.want(e.do(operator, "PATCH", "/hosts/app.example.com", map[string]any{"waf": false}, "If-Match", tag), 412)
	// null entfernt optionale Werte (JSON Merge Patch); fqdn ist unveraenderlich.
	e.want(e.do(operator, "PATCH", "/hosts/app.example.com", `{"client_max_body_size":null}`, "If-Match", `"2"`), 200).json(t, &h)
	if h.ClientMaxBodySize != nil {
		t.Errorf("client_max_body_size nicht entfernt: %v", *h.ClientMaxBodySize)
	}
	e.want(e.do(operator, "PATCH", "/hosts/app.example.com", `{"fqdn":"other.example.com"}`, "If-Match", "*"), 400)
	e.want(e.do(operator, "PATCH", "/hosts/app.example.com", `{"bogus":1}`, "If-Match", "*"), 400)

	// PUT ersetzt (--overwrite) bzw. legt an.
	put := hostBody("app.example.com")
	put["websockets"] = true
	e.want(e.do(operator, "PUT", "/hosts/app.example.com", put), 428)
	e.want(e.do(operator, "PUT", "/hosts/app.example.com", put, "If-Match", `"3"`), 200).json(t, &h)
	if h.Waf || !h.Websockets || h.Upstream.Port != 8080 {
		t.Fatalf("PUT-Ergebnis: %+v", h)
	}
	e.want(e.do(operator, "PUT", "/hosts/second.example.com", hostBody("second.example.com")), 201)

	var list apigen.HostList
	e.want(e.do(viewer, "GET", "/hosts?limit=1", nil), 200).json(t, &list)
	if len(list.Items) != 1 || list.NextCursor == nil {
		t.Fatalf("Paginierung: %+v", list)
	}
	e.want(e.do(viewer, "GET", "/hosts?limit=1&cursor="+*list.NextCursor, nil), 200).json(t, &list)
	if len(list.Items) != 1 || list.Items[0].Fqdn != "second.example.com" || list.NextCursor != nil {
		t.Fatalf("zweite Seite: %+v", list)
	}

	e.want(e.do(operator, "DELETE", "/hosts/app.example.com", nil), 428)
	e.want(e.do(operator, "DELETE", "/hosts/app.example.com", nil, "If-Match", `"4"`), 204)
	e.want(e.do(viewer, "GET", "/hosts/app.example.com", nil), 404)
}

func TestHostValidation(t *testing.T) {
	e := newEnv(t, nil)
	bad := []map[string]any{
		{"fqdn": "no-dots", "upstream": map[string]any{"scheme": "http", "address": "10.0.0.1", "port": 80}},
		{"fqdn": "a.example.com", "upstream": map[string]any{"scheme": "ftp", "address": "10.0.0.1", "port": 80}},
		{"fqdn": "a.example.com", "upstream": map[string]any{"scheme": "http", "address": "10.0.0.1; evil", "port": 80}},
		{"fqdn": "a.example.com", "upstream": map[string]any{"scheme": "http", "address": "10.0.0.1", "port": 70000}},
		{"fqdn": "a.example.com", "external_port": 80, "upstream": map[string]any{"scheme": "http", "address": "10.0.0.1", "port": 80}},
		{"fqdn": "a.example.com", "client_max_body_size": "lots", "upstream": map[string]any{"scheme": "http", "address": "10.0.0.1", "port": 80}},
		{"fqdn": "a.example.com", "hsts": map[string]any{"max_age": 10, "include_subdomains": false, "preload": true}, "upstream": map[string]any{"scheme": "http", "address": "10.0.0.1", "port": 80}},
		{"fqdn": "a.example.com", "upstream": map[string]any{"scheme": "http", "address": "10.0.0.1", "port": 80, "site": "missing"}},
		{"upstream": map[string]any{"scheme": "http", "address": "10.0.0.1", "port": 80}},
	}
	for i, b := range bad {
		before := e.auditCount()
		if r := e.do(operator, "POST", "/hosts", b); r.code != 400 {
			t.Errorf("Fall %d: HTTP %d, erwartet 400: %s", i, r.code, r.body)
		}
		if a := e.lastAudit(); e.auditCount() != before+1 || a.Result != audit.Failed {
			t.Errorf("Fall %d: fehlgeschlagene Aktion nicht protokolliert", i)
		}
	}
	var list apigen.HostList
	e.want(e.do(viewer, "GET", "/hosts", nil), 200).json(t, &list)
	if len(list.Items) != 0 {
		t.Fatalf("ungueltige Hosts wurden angelegt: %+v", list.Items)
	}
}

func TestIdempotencyKey(t *testing.T) {
	e := newEnv(t, nil)
	first := e.want(e.do(operator, "POST", "/hosts", hostBody("idem.example.com"), "Idempotency-Key", "k1"), 201)
	again := e.want(e.do(operator, "POST", "/hosts", hostBody("idem.example.com"), "Idempotency-Key", "k1"), 201)
	if !bytes.Equal(first.body, again.body) || again.hdr.Get("Idempotent-Replayed") != "true" || again.hdr.Get("Location") != first.hdr.Get("Location") {
		t.Fatalf("Wiederholung liefert nicht die gespeicherte Antwort: %s", again.body)
	}
	// Ohne Schluessel bzw. fuer einen anderen Akteur gilt die normale Semantik.
	e.want(e.do(operator, "POST", "/hosts", hostBody("idem.example.com")), 409)
	e.want(e.do(admin, "POST", "/hosts", hostBody("idem.example.com"), "Idempotency-Key", "k1"), 409)
	n, _ := e.st.Read().CountOpenJobsFor(context.Background(), dbq.CountOpenJobsForParams{Resource: "idem.example.com", Kind: "cert_issue"})
	if n != 1 {
		t.Fatalf("%d Jobs, erwartet genau einer", n)
	}
}

// ── Sites ───────────────────────────────────────────────────────────────────

func TestSites(t *testing.T) {
	e := newEnv(t, nil)
	var home, office apigen.Site
	e.want(e.do(admin, "POST", "/sites", map[string]any{"name": "home", "targets": 8, "lan_cidr": "192.168.1.5/24"}), 201).json(t, &home)
	if home.Subnet != "10.240.0.0/28" || home.ConnectorIp != "10.240.0.2" || !home.HasPsk || home.Status != apigen.SiteStatusPending || *home.LanCidr != "192.168.1.0/24" {
		t.Fatalf("Site home: %+v", home)
	}
	e.want(e.do(admin, "POST", "/sites", map[string]any{"name": "office", "subnet_prefix": 27}), 201).json(t, &office)
	if office.Subnet != "10.240.0.32/27" {
		t.Fatalf("zweite Site ueberlappt oder liegt falsch: %s", office.Subnet)
	}
	e.want(e.do(admin, "POST", "/sites", map[string]any{"name": "home"}), 409)
	e.want(e.do(admin, "POST", "/sites", map[string]any{"name": "Bad_Name"}), 400)

	// Upstream muss im Netz der Site liegen (Overlay oder LAN).
	in := hostBody("tunnel.example.com")
	up := in["upstream"].(map[string]any)
	up["site"], up["address"] = "home", "10.99.0.1"
	e.want(e.do(operator, "POST", "/hosts", in), 400)
	up["address"] = "192.168.1.20"
	e.want(e.do(operator, "POST", "/hosts", in), 201)
	e.want(e.do(admin, "DELETE", "/sites/home", nil, "If-Match", "*"), 409) // noch in Benutzung

	_, pub, _ := wireguard.GenerateKeyPair()
	e.want(e.do(admin, "PUT", "/sites/home/public-key", map[string]any{"public_key": "kein-schluessel"}), 400)
	e.want(e.do(admin, "PUT", "/sites/home/public-key", map[string]any{"public_key": pub}), 200).json(t, &home)
	if *home.PublicKey != pub || home.Version != 2 {
		t.Fatalf("Public Key nicht gesetzt: %+v", home)
	}
	e.want(e.do(admin, "PUT", "/sites/office/public-key", map[string]any{"public_key": pub}), 409)

	script := e.want(e.do(admin, "GET", "/sites/home/install-script?os=alpine", nil), 200)
	hub, _ := e.st.Read().GetWgHub(context.Background())
	row, _ := e.st.Read().GetSite(context.Background(), "home")
	psk, _ := e.box.Open(row.PskEnc)
	for _, want := range []string{"Address = 10.240.0.2/28", "PublicKey = " + hub.PublicKey, "Endpoint = proxy.example.com:51820",
		"PresharedKey = " + string(psk), "apk add --no-cache wireguard-tools"} {
		if !strings.Contains(string(script.body), want) {
			t.Errorf("Install-Script enthaelt %q nicht", want)
		}
	}
	if a := e.lastAudit(); a.Action != "site.install_script" {
		t.Errorf("Abruf des Install-Scripts (PSK) nicht protokolliert: %s", a.Action)
	}

	e.want(e.do(admin, "POST", "/sites/home/rotate-psk", nil), 200)
	row2, _ := e.st.Read().GetSite(context.Background(), "home")
	psk2, _ := e.box.Open(row2.PskEnc)
	if bytes.Equal(psk, psk2) {
		t.Fatal("PSK wurde nicht ersetzt")
	}
	if a := e.lastAudit(); a.AfterJson == nil || strings.Contains(*a.AfterJson, string(psk2)) || !strings.Contains(*a.AfterJson, "[redacted:sha256:") {
		t.Errorf("PSK steht unredigiert im Audit-Log: %v", a.AfterJson)
	}

	e.want(e.do(admin, "PATCH", "/sites/home", `{"notes":"Keller","lan_cidr":null}`, "If-Match", "*"), 200).json(t, &home)
	if *home.Notes != "Keller" || home.LanCidr != nil {
		t.Fatalf("PATCH Site: %+v", home)
	}
	// keep_config: Datensatz bleibt, Peer entfaellt.
	e.want(e.do(admin, "DELETE", "/sites/office?keep_config=true", nil, "If-Match", "*"), 204)
	e.want(e.do(viewer, "GET", "/sites/office", nil), 200).json(t, &office)
	if office.Enabled || office.Status != apigen.SiteStatusOffline {
		t.Fatalf("keep_config: %+v", office)
	}
	e.want(e.do(admin, "DELETE", "/sites/office", nil, "If-Match", "*"), 204)
	e.want(e.do(viewer, "GET", "/sites/office", nil), 404)
}

func TestWireGuardDisabled(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.WireGuardEnabled = false })
	e.want(e.do(admin, "GET", "/sites", nil), 409)
	e.want(e.do(admin, "POST", "/sites", map[string]any{"name": "home"}), 409)
	in := hostBody("a.example.com")
	in["upstream"].(map[string]any)["site"] = "home"
	e.want(e.do(operator, "POST", "/hosts", in), 409)
}

// ── Jede Mutation hat einen Audit-Eintrag ───────────────────────────────────

func TestEveryMutationIsAudited(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.TokensEnabled = true })
	chainPEM, keyPEM := testutil.SelfSigned(t, "cert.example.com", time.Now().Add(48*time.Hour))
	steps := []struct {
		action, method, path string
		body                 any
		code                 int
	}{
		{"host.create", "POST", "/hosts", hostBody("cert.example.com"), 201},
		{"host.update", "PATCH", "/hosts/cert.example.com", map[string]any{"waf": true}, 200},
		{"host.replace", "PUT", "/hosts/cert.example.com", hostBody("cert.example.com"), 200},
		{"certificate.renew_request", "POST", "/certificates/cert.example.com/renew", nil, 409}, // Ausstellung laeuft noch
		{"site.create", "POST", "/sites", map[string]any{"name": "lab"}, 201},
		{"site.update", "PATCH", "/sites/lab", map[string]any{"notes": "n"}, 200},
		{"site.rotate_psk", "POST", "/sites/lab/rotate-psk", nil, 200},
		{"site.delete", "DELETE", "/sites/lab", nil, 204},
		{"waf.set", "PUT", "/waf", map[string]any{"mode": "On", "overrides": "# eigene Regeln\n"}, 200},
		{"settings.update", "PATCH", "/settings", map[string]any{"client_max_body_size": "200M", "hsts": map[string]any{"max_age": 600}}, 200},
		{"client.issue", "POST", "/clients", map[string]any{"name": "ci", "role": "operator"}, 201},
		{"client.renew", "POST", "/clients/ci/renew", map[string]any{}, 200},
		{"client.revoke", "DELETE", "/clients/ci", nil, 204},
		{"client.purge", "DELETE", "/clients/ci?purge=true", nil, 204},
		{"token.create", "POST", "/tokens", map[string]any{"name": "ci", "role": "viewer"}, 201},
		{"render.reconcile", "POST", "/render/reconcile", nil, 0},
		{"backup.create", "POST", "/backup", map[string]any{"name": "t.db"}, 201},
		{"host.delete", "DELETE", "/hosts/cert.example.com?keep_cert=true", nil, 204},
	}
	if _, _, err := server.EnsurePKI(context.Background(), e.st, e.box, e.cfg.APISANs); err != nil {
		t.Fatal(err)
	}
	_, _ = chainPEM, keyPEM
	for _, s := range steps {
		before := e.auditCount()
		r := e.do(local, s.method, s.path, s.body, "If-Match", "*")
		if s.code != 0 && r.code != s.code {
			t.Fatalf("%s: HTTP %d, erwartet %d: %s", s.action, r.code, s.code, r.body)
		}
		a := e.lastAudit()
		if e.auditCount() <= before || a.Action != s.action {
			t.Errorf("%s %s: kein Audit-Eintrag %q (letzter: %q)", s.method, s.path, s.action, a.Action)
		}
		if a.ActorType != "local" || a.ActorID != "uid=0" {
			t.Errorf("%s: Akteur %s:%s", s.action, a.ActorType, a.ActorID)
		}
	}
	// Lesende Zugriffe erzeugen keine Eintraege.
	before := e.auditCount()
	for _, p := range []string{"/hosts", "/status", "/waf", "/settings", "/audit", "/audit/verify", "/jobs", "/clients"} {
		e.want(e.do(local, "GET", p, nil), 200)
	}
	if e.auditCount() != before {
		t.Error("GET-Anfragen duerfen nichts protokollieren")
	}
	// Settings wirken und sind als Merge Patch teilweise aenderbar.
	var st apigen.Settings
	e.want(e.do(viewer, "GET", "/settings", nil), 200).json(t, &st)
	if st.ClientMaxBodySize != "200M" || st.Hsts.MaxAge != 600 || !st.Hsts.IncludeSubdomains {
		t.Errorf("Settings: %+v", st)
	}
	var list apigen.AuditList
	e.want(e.do(admin, "GET", "/audit?resource=cert.example.com&limit=2", nil), 200).json(t, &list)
	if len(list.Items) != 2 || list.NextCursor == nil || list.Items[0].Action != "host.delete" {
		t.Errorf("Audit-Filter/Paginierung: %+v", list)
	}
}

func TestLocalOnlyOperations(t *testing.T) {
	e := newEnv(t, nil)
	e.want(e.do(local, "POST", "/hosts", hostBody("a.example.com")), 201)
	past := time.Now().Add(-time.Hour).Format(time.RFC3339)
	e.want(e.do(admin, "POST", "/audit/prune", map[string]any{"before": past}), 403)
	e.want(e.do(admin, "POST", "/backup", nil), 403)
	e.want(e.do(local, "POST", "/audit/prune", map[string]any{"before": time.Now().Add(time.Hour).Format(time.RFC3339)}), 400)
	time.Sleep(20 * time.Millisecond)
	var res apigen.AuditPruneResult
	e.want(e.do(local, "POST", "/audit/prune", map[string]any{"before": time.Now().Format(time.RFC3339Nano)}), 200).json(t, &res)
	if res.Deleted == 0 || res.AnchorHash == nil {
		t.Fatalf("prune: %+v", res)
	}
	var v apigen.AuditVerify
	e.want(e.do(admin, "GET", "/audit/verify", nil), 200).json(t, &v)
	if !v.Ok {
		t.Fatalf("Kette nach prune nicht verifizierbar: %+v", v)
	}
	e.want(e.do(local, "POST", "/backup", map[string]any{"name": "../evil.db"}), 400)
}

// ── mTLS und Tokens ueber echte Listener ────────────────────────────────────

func freeAddr(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func waitListen(t *testing.T, addr string) {
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("Listener %s startet nicht", addr)
}

func csrPEM(t *testing.T, cn string) (string, *ecdsa.PrivateKey) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), key
}

func keyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestMTLSAuthentication(t *testing.T) {
	e := newEnv(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ca, serverCert, err := server.EnsurePKI(ctx, e.st, e.box, e.cfg.APISANs)
	if err != nil {
		t.Fatal(err)
	}
	// Zweiter Aufruf nutzt die gespeicherte PKI weiter.
	ca2, _, err := server.EnsurePKI(ctx, e.st, e.box, e.cfg.APISANs)
	if err != nil || pki.Fingerprint(ca2.Cert) != pki.Fingerprint(ca.Cert) {
		t.Fatalf("PKI nicht stabil: %v", err)
	}
	addr := freeAddr(t)
	go func() { _ = e.srv.ServeMTLS(ctx, addr, ca, serverCert) }()
	waitListen(t, addr)

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	client := func(certPEM string, key []byte) *http.Client {
		tc := &tls.Config{RootCAs: pool, ServerName: "localhost"}
		if certPEM != "" {
			pair, err := tls.X509KeyPair([]byte(certPEM), key)
			if err != nil {
				t.Fatal(err)
			}
			tc.Certificates = []tls.Certificate{pair}
		}
		return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}}
	}
	get := func(c *http.Client, method, path string) (int, error) {
		req, _ := http.NewRequest(method, "https://"+addr+server.BasePath+path, strings.NewReader("{}"))
		res, err := c.Do(req)
		if err != nil {
			return 0, err
		}
		defer res.Body.Close()
		_, _ = io.Copy(io.Discard, res.Body)
		return res.StatusCode, nil
	}
	issue := func(name, role string) (string, []byte) {
		csr, key := csrPEM(t, "ignoriert")
		var out apigen.ApiClientIssued
		e.want(e.do(local, "POST", "/clients", map[string]any{"name": name, "role": role, "csr_pem": csr}), 201).json(t, &out)
		if out.KeyPem != nil {
			t.Fatal("mit CSR darf der Server keinen Schluessel liefern")
		}
		return out.CertPem, keyPEM(t, key)
	}

	// Ohne Client-Zertifikat scheitert bereits der TLS-Handshake.
	if code, err := get(client("", nil), "GET", "/hosts"); err == nil {
		t.Fatalf("ohne Zertifikat: HTTP %d, erwartet Handshake-Fehler", code)
	}
	// Zertifikat einer fremden CA: ebenfalls Handshake-Fehler.
	foreignCert, foreignKey, _ := pki.NewCA()
	foreign, _ := pki.LoadCA(foreignCert, foreignKey)
	fc, fk, _, _ := foreign.IssueClient("eve", 30)
	if code, err := get(client(string(fc), fk), "GET", "/hosts"); err == nil {
		t.Fatalf("fremde CA: HTTP %d, erwartet Handshake-Fehler", code)
	}

	vCert, vKey := issue("vera", "viewer")
	aCert, aKey := issue("anna", "admin")
	if code, err := get(client(vCert, vKey), "GET", "/hosts"); err != nil || code != 200 {
		t.Fatalf("viewer GET /hosts: %d %v", code, err)
	}
	// Falsche Rolle: authentifiziert, aber nicht berechtigt.
	if code, _ := get(client(vCert, vKey), "POST", "/sites"); code != 403 {
		t.Fatalf("viewer POST /sites: %d, erwartet 403", code)
	}
	if code, _ := get(client(aCert, aKey), "GET", "/audit"); code != 200 {
		t.Fatalf("admin GET /audit: %d", code)
	}
	if a, _ := e.st.Read().GetClientByName(ctx, "vera"); a.LastUsedAt == nil {
		t.Error("last_used_at wurde nicht gesetzt")
	}

	// Von unserer CA signiert, aber nicht registriert: die Rolle haengt am Fingerprint.
	uc, uk, _, _ := ca.IssueClient("anna", 30)
	if code, _ := get(client(string(uc), uk), "GET", "/hosts"); code != 401 {
		t.Fatalf("unregistriertes Zertifikat: %d, erwartet 401", code)
	}
	if a := e.lastAudit(); a.Action != "auth.failed" || a.Result != audit.Denied || a.ActorFingerprint == nil || a.SourceIp == nil {
		t.Errorf("fehlgeschlagene Anmeldung nicht protokolliert: %+v", a)
	}

	// Widerruf wirkt sofort, ohne CRL.
	e.want(e.do(local, "DELETE", "/clients/vera", nil), 204)
	if code, _ := get(client(vCert, vKey), "GET", "/hosts"); code != 401 {
		t.Fatalf("widerrufener Client: %d, erwartet 401", code)
	}
	// Abgelaufen laut api_clients.
	if err := e.st.Write(ctx, func(q *dbq.Queries) error {
		return q.UpdateClientCert(ctx, dbq.UpdateClientCertParams{CertSha256: fingerprintOf(t, aCert), Serial: "1",
			NotAfter: store.FormatTime(time.Now().Add(-time.Minute)), Name: "anna"})
	}); err != nil {
		t.Fatal(err)
	}
	if code, _ := get(client(aCert, aKey), "GET", "/hosts"); code != 401 {
		t.Fatalf("abgelaufener Client: %d, erwartet 401", code)
	}

	// Erneuerung ersetzt den Fingerprint: das alte Zertifikat gilt nicht mehr.
	oCert, oKey := issue("otto", "operator")
	var renewed apigen.ApiClientIssued
	e.want(e.do(local, "POST", "/clients/otto/renew", map[string]any{}), 200).json(t, &renewed)
	if code, _ := get(client(oCert, oKey), "GET", "/hosts"); code != 401 {
		t.Fatalf("altes Zertifikat nach Erneuerung: %d, erwartet 401", code)
	}
	if code, _ := get(client(renewed.CertPem, []byte(*renewed.KeyPem)), "GET", "/hosts"); code != 200 {
		t.Fatalf("erneuertes Zertifikat: %d", code)
	}

	// Rate-Limit fuer fehlgeschlagene Anmeldungen je Quell-IP.
	last := 0
	for i := 0; i < 12; i++ {
		last, _ = get(client(string(uc), uk), "GET", "/hosts")
	}
	if last != 429 {
		t.Fatalf("nach vielen Fehlversuchen: %d, erwartet 429", last)
	}
	if code, _ := get(client(renewed.CertPem, []byte(*renewed.KeyPem)), "GET", "/hosts"); code != 429 {
		t.Fatalf("gesperrte IP: %d, erwartet 429", code)
	}
}

func fingerprintOf(t *testing.T, certPEM string) string {
	c, err := pki.ParseCert([]byte(certPEM))
	if err != nil {
		t.Fatal(err)
	}
	return pki.Fingerprint(c)
}

func TestTokenListener(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.TokensEnabled = true })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ca, serverCert, err := server.EnsurePKI(ctx, e.st, e.box, e.cfg.APISANs)
	if err != nil {
		t.Fatal(err)
	}
	addr := freeAddr(t)
	go func() { _ = e.srv.ServeTokens(ctx, addr, serverCert) }()
	waitListen(t, addr)
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"}}}
	call := func(method, path, token string) int {
		req, _ := http.NewRequest(method, "https://"+addr+server.BasePath+path, strings.NewReader("{}"))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	var tok apigen.TokenIssued
	e.want(e.do(local, "POST", "/tokens", map[string]any{"name": "ci", "role": "operator", "expires_in_days": 400}), 400)
	e.want(e.do(local, "POST", "/tokens", map[string]any{"name": "ci", "role": "operator"}), 201).json(t, &tok)
	if !strings.HasPrefix(tok.Secret, "nrp_"+tok.Token.Id+"_") {
		t.Fatalf("Token-Format: %s", tok.Secret)
	}
	row, _ := e.st.Read().GetToken(ctx, tok.Token.Id)
	if len(row.SecretSha256) != 32 || strings.Contains(fmt.Sprintf("%x", row.SecretSha256), tok.Secret) {
		t.Fatal("gespeichert wird nur der SHA-256 des Secrets")
	}
	if c := call("GET", "/hosts", tok.Secret); c != 200 {
		t.Fatalf("gueltiges Token: %d", c)
	}
	if c := call("POST", "/sites", tok.Secret); c != 403 {
		t.Fatalf("operator-Token auf admin-Operation: %d", c)
	}
	if c := call("GET", "/hosts", ""); c != 401 {
		t.Fatalf("ohne Token: %d", c)
	}
	if c := call("GET", "/hosts", tok.Secret[:len(tok.Secret)-1]+"x"); c != 401 {
		t.Fatalf("falsches Secret: %d", c)
	}
	e.want(e.do(local, "DELETE", "/tokens/"+tok.Token.Id, nil), 204)
	if c := call("GET", "/hosts", tok.Secret); c != 401 {
		t.Fatalf("widerrufenes Token: %d", c)
	}
	// Ohne Aktivierung liefern die Token-Endpunkte 409.
	off := newEnv(t, nil)
	off.want(off.do(local, "POST", "/tokens", map[string]any{"name": "ci", "role": "viewer"}), 409)
}

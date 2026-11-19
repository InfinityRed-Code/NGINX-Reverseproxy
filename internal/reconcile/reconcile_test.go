package reconcile_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/acme"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/config"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/domain"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/nginx"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/reconcile"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/secrets"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store/dbq"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/testutil"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/wireguard"
)

// fakeNginx lehnt Konfigurationen ab, die einen der reject-Strings enthalten.
type fakeNginx struct {
	mu        sync.Mutex
	reject    []string
	wafReject string
	tests     int
	wafChecks int
	reloads   int
}

func (f *fakeNginx) Test(_ context.Context, conf string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tests++
	dir := filepath.Dir(conf)
	files, _ := filepath.Glob(filepath.Join(dir, "http.d", "*.conf"))
	for _, p := range files {
		b, _ := os.ReadFile(p)
		for _, bad := range f.reject {
			if strings.Contains(string(b), bad) {
				return `nginx: [emerg] host not found in upstream "` + bad + `" in ` + filepath.ToSlash(p) + ":30", errors.New("exit status 1")
			}
		}
	}
	return "", nil
}

func (f *fakeNginx) CheckWAF(_ context.Context, rules string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.wafChecks++
	b, _ := os.ReadFile(filepath.Join(filepath.Dir(rules), "crs-overrides.conf"))
	if f.wafReject != "" && strings.Contains(string(b), f.wafReject) {
		return "coraza: failed to compile rule: " + f.wafReject, errors.New("exit status 1")
	}
	return "", nil
}

func (f *fakeNginx) Reload(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reloads++
	return nil
}
func (f *fakeNginx) Running() bool { return true }

type fakeWG struct{ applied []wireguard.Desired }

func (f *fakeWG) Apply(d wireguard.Desired) error               { f.applied = append(f.applied, d); return nil }
func (f *fakeWG) Stats() (map[string]wireguard.PeerStat, error) { return nil, nil }

type env struct {
	t   *testing.T
	cfg config.Config
	st  *store.Store
	box *secrets.Box
	ng  *fakeNginx
	rec *reconcile.Reconciler
}

func newEnv(t *testing.T, wg wireguard.Manager) *env {
	t.Helper()
	tmp := filepath.ToSlash(t.TempDir())
	if err := os.Symlink(tmp, tmp+"/probe"); err != nil {
		t.Skipf("Symlinks nicht verfuegbar (%v); der Test laeuft unter Linux/CI", err)
	}
	cfg := config.Config{RunDir: tmp + "/run", LogDir: tmp + "/log", CRSDir: tmp + "/crs", HTMLDir: tmp + "/html", NginxConf: tmp + "/missing.conf"}
	if err := os.MkdirAll(cfg.RenderDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, cfg: cfg, st: testutil.Store(t), box: testutil.Box(t), ng: &fakeNginx{}}
	e.rec = reconcile.New(cfg, e.st, e.box, e.ng, wg, nil)
	return e
}

func (e *env) addHost(fqdn, addr string, waf bool, withCert bool) {
	e.t.Helper()
	ctx := context.Background()
	err := e.st.Write(ctx, func(q *dbq.Queries) error {
		now := store.Now()
		w := int64(0)
		if waf {
			w = 1
		}
		if err := q.InsertHost(ctx, dbq.InsertHostParams{Fqdn: fqdn, UpstreamScheme: "http", UpstreamAddress: addr, UpstreamPort: 8080,
			ExternalPort: 443, Waf: w, Status: domain.HostPending, CreatedAt: now, UpdatedAt: now}); err != nil {
			return err
		}
		if !withCert {
			return nil
		}
		chain, key := testutil.SelfSigned(e.t, fqdn, time.Now().Add(72*time.Hour))
		_, err := acme.StoreCertificate(ctx, q, e.box, fqdn, chain, key, "acme", nil)
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) reconcile(force bool) reconcile.Result {
	e.t.Helper()
	res, err := e.rec.Reconcile(context.Background(), force)
	if err != nil {
		e.t.Fatal(err)
	}
	return res
}

func (e *env) status(fqdn string) (string, string) {
	h, err := e.st.Read().GetHost(context.Background(), fqdn)
	if err != nil {
		e.t.Fatal(err)
	}
	detail := ""
	if h.StatusDetail != nil {
		detail = *h.StatusDetail
	}
	return h.Status, detail
}

func (e *env) current(rel string) string {
	b, err := os.ReadFile(filepath.Join(e.cfg.RenderDir(), "current", filepath.FromSlash(rel)))
	if err != nil {
		return ""
	}
	return string(b)
}

func TestReconcileAppliesAndIsIdempotent(t *testing.T) {
	e := newEnv(t, nil)
	e.addHost("app.example.com", "192.168.1.10", false, true)
	e.addHost("pending.example.com", "192.168.1.11", false, false)

	res := e.reconcile(false)
	if res.Generation != 1 || !res.Changed || !res.Reloaded || res.Error != "" {
		t.Fatalf("erstes Reconcile: %+v", res)
	}
	conf := e.current("http.d/host-app.example.com.conf")
	gen1 := e.cfg.RenderDir() + "/gen-1"
	if !strings.Contains(conf, "proxy_pass http://192.168.1.10:8080/;") || !strings.Contains(conf, "include "+gen1+"/snippets/hsts-app.example.com.conf;") {
		t.Fatalf("gerenderte Host-Config:\n%s", conf)
	}
	if e.current("http.d/host-pending.example.com.conf") != "" {
		t.Error("Host ohne Zertifikat wurde gerendert")
	}
	test, _ := os.ReadFile(gen1 + "/nginx.test.conf")
	if !strings.Contains(string(test), "include "+gen1+"/http.d/*.conf;") {
		t.Errorf("nginx.test.conf zeigt nicht auf die neue Generation:\n%s", test)
	}
	// Zertifikat auf tmpfs, Schluessel entschluesselt und nur fuer root lesbar.
	key, err := os.ReadFile(filepath.Join(e.cfg.CertsDir(), "app.example.com", "privkey.pem"))
	if err != nil || !strings.Contains(string(key), "PRIVATE KEY") {
		t.Fatalf("Schluessel nicht materialisiert: %v", err)
	}
	if s, _ := e.status("app.example.com"); s != domain.HostActive {
		t.Errorf("Host mit Zertifikat: Status %s", s)
	}
	if s, _ := e.status("pending.example.com"); s != domain.HostPending {
		t.Errorf("Host ohne Zertifikat: Status %s", s)
	}

	// Ohne Aenderung: kein neuer Test, kein Reload.
	res = e.reconcile(false)
	if res.Changed || res.Generation != 1 || e.ng.reloads != 1 || e.ng.tests != 1 {
		t.Fatalf("unveraendertes Reconcile: %+v (reloads=%d tests=%d)", res, e.ng.reloads, e.ng.tests)
	}
	// Erneuertes Zertifikat aendert den Hash und fuehrt zum Reload.
	ctx := context.Background()
	if err := e.st.Write(ctx, func(q *dbq.Queries) error {
		chain, key := testutil.SelfSigned(t, "app.example.com", time.Now().Add(96*time.Hour))
		_, err := acme.StoreCertificate(ctx, q, e.box, "app.example.com", chain, key, "acme", nil)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if res = e.reconcile(false); !res.Changed || res.Generation != 2 || e.ng.reloads != 2 {
		t.Fatalf("nach Zertifikatserneuerung: %+v", res)
	}
	gens, _ := e.st.Read().ListGenerations(ctx, 10)
	if len(gens) != 2 || gens[0].Status != "applied" {
		t.Fatalf("Generationen in der DB: %+v", gens)
	}
}

func TestRejectedGenerationKeepsOldConfigAndQuarantinesHost(t *testing.T) {
	e := newEnv(t, nil)
	e.addHost("good.example.com", "192.168.1.10", false, true)
	e.reconcile(false)

	e.ng.reject = []string{"unresolvable.internal"}
	e.addHost("bad.example.com", "unresolvable.internal", false, true)
	e.addHost("other.example.com", "192.168.1.12", false, true)
	res := e.reconcile(false)
	if !strings.Contains(res.Error, "host not found in upstream") {
		t.Fatalf("Ablehnung nicht gemeldet: %+v", res)
	}
	// Der defekte Host ist in Quarantaene, die uebrigen Aenderungen wirken trotzdem.
	if s, d := e.status("bad.example.com"); s != domain.HostError || !strings.HasPrefix(d, reconcile.QuarantinePrefix) {
		t.Fatalf("defekter Host: %s %q", s, d)
	}
	if e.current("http.d/host-bad.example.com.conf") != "" {
		t.Error("abgelehnter Host ist aktiv")
	}
	if e.current("http.d/host-other.example.com.conf") == "" || e.current("http.d/host-good.example.com.conf") == "" {
		t.Error("gesunde Hosts wurden nicht angewendet")
	}
	if s, _ := e.status("other.example.com"); s != domain.HostActive {
		t.Errorf("gesunder Host: Status %s", s)
	}
	gens, _ := e.st.Read().ListGenerations(context.Background(), 10)
	if len(gens) != 3 || gens[0].Status != "applied" || gens[1].Status != "rejected" || gens[1].NginxTestOutput == nil {
		t.Fatalf("Generationen: %+v", gens)
	}
	if _, err := os.Stat(e.cfg.RenderDir() + "/gen-2"); err == nil {
		t.Error("abgelehnte Generation liegt noch auf der Platte")
	}
	last, _ := e.st.Read().LastAuditEntry(context.Background())
	if last.Action != "render.rejected" || last.ActorType != "system" || last.Result != "failed" {
		t.Errorf("Ablehnung nicht als Systemaktion protokolliert: %+v", last)
	}
	// Folgende Laeufe bleiben stabil und versuchen den Host nicht erneut.
	tests := e.ng.tests
	if res := e.reconcile(false); res.Changed || e.ng.tests != tests {
		t.Errorf("Quarantaene nicht stabil: %+v", res)
	}
}

func TestBrokenWAFRulesAreRejectedBeforeReload(t *testing.T) {
	e := newEnv(t, nil)
	e.addHost("waf.example.com", "192.168.1.10", true, true)
	if res := e.reconcile(false); res.Error != "" || e.ng.wafChecks != 1 {
		t.Fatalf("erstes Reconcile: %+v, wafChecks=%d", res, e.ng.wafChecks)
	}
	// Unveraenderte Regelkette wird nicht erneut geprueft.
	e.addHost("second.example.com", "192.168.1.11", false, true)
	if res := e.reconcile(false); !res.Changed || e.ng.wafChecks != 1 {
		t.Fatalf("zweites Reconcile: %+v, wafChecks=%d", res, e.ng.wafChecks)
	}
	// nginx -t wuerde eine defekte Regel durchlassen; der Regelcheck faengt sie ab.
	ctx := context.Background()
	e.ng.wafReject = "SecRule BROKEN"
	if err := e.st.Write(ctx, func(q *dbq.Queries) error {
		return store.SaveSetting(ctx, q, domain.KeyWAFOverrides, "SecRule BROKEN\n")
	}); err != nil {
		t.Fatal(err)
	}
	reloads := e.ng.reloads
	res := e.reconcile(false)
	if !strings.Contains(res.Error, "failed to compile rule") || res.Changed || e.ng.reloads != reloads {
		t.Fatalf("defekte WAF-Regel wurde angewendet: %+v", res)
	}
	if strings.Contains(e.current("coraza/crs-overrides.conf"), "BROKEN") {
		t.Error("defekte Regel ist aktiv")
	}
	if s, _ := e.status("waf.example.com"); s != domain.HostActive {
		t.Errorf("ein globaler Regelfehler darf keinen Host in Quarantaene nehmen: %s", s)
	}
}

func TestRollbackPinsUntilForcedReconcile(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	e.addHost("a.example.com", "192.168.1.10", false, true)
	e.reconcile(false)
	e.addHost("b.example.com", "192.168.1.11", false, true)
	if res := e.reconcile(false); res.Generation != 2 {
		t.Fatalf("zweite Generation: %+v", res)
	}
	res, err := e.rec.Rollback(ctx, 1)
	if err != nil || res.Generation != 1 || !res.Reloaded {
		t.Fatalf("Rollback: %+v %v", res, err)
	}
	if e.current("http.d/host-b.example.com.conf") != "" {
		t.Error("nach Rollback ist Generation 2 noch aktiv")
	}
	if gen, pinned, _ := e.rec.State(); gen != 1 || !pinned {
		t.Fatalf("State nach Rollback: gen=%d pinned=%v", gen, pinned)
	}
	// Automatische Laeufe heben den Rollback nicht auf, auch nicht nach Neustart von nrpd.
	e.addHost("c.example.com", "192.168.1.12", false, true)
	if res := e.reconcile(false); res.Changed || res.Generation != 1 {
		t.Fatalf("automatisches Reconcile trotz Pin: %+v", res)
	}
	restarted := reconcile.New(e.cfg, e.st, e.box, e.ng, nil, nil)
	if _, pinned, _ := restarted.State(); !pinned {
		t.Error("Pin ueberlebt den Neustart des Dienstes nicht")
	}
	// Erzwungenes Reconcile (nrp render apply) wendet wieder den DB-Stand an.
	if res := e.reconcile(true); !res.Changed || res.Generation != 3 {
		t.Fatalf("erzwungenes Reconcile: %+v", res)
	}
	if _, pinned, _ := e.rec.State(); pinned || e.current("http.d/host-c.example.com.conf") == "" {
		t.Error("Pin nicht aufgehoben oder DB-Stand nicht angewendet")
	}
	if _, err := e.rec.Rollback(ctx, 99); err == nil {
		t.Error("Rollback auf nicht vorhandene Generation muss fehlschlagen")
	}
}

func TestGenerationsArePruned(t *testing.T) {
	e := newEnv(t, nil)
	e.addHost("a.example.com", "192.168.1.10", false, true)
	for i := 0; i < reconcile.KeepGenerations+4; i++ {
		e.reconcile(true)
	}
	dirs, _ := filepath.Glob(e.cfg.RenderDir() + "/gen-*")
	if len(dirs) != reconcile.KeepGenerations {
		t.Fatalf("%d Generationen auf der Platte, erwartet %d", len(dirs), reconcile.KeepGenerations)
	}
	if gen, _, _ := e.rec.State(); !e.rec.Available(gen) || e.rec.Available(1) {
		t.Error("aktive Generation fehlt oder aelteste wurde nicht entfernt")
	}
}

func TestWireGuardDesiredState(t *testing.T) {
	wg := &fakeWG{}
	e := newEnv(t, wg)
	ctx := context.Background()
	if _, err := wireguard.EnsureHub(ctx, e.st, e.box, "10.240.0.0/16", 51820); err != nil {
		t.Fatal(err)
	}
	_, pub, _ := wireguard.GenerateKeyPair()
	psk, _ := wireguard.GeneratePSK()
	pskEnc, _ := e.box.Seal([]byte(psk))
	lan := "192.168.1.0/24"
	err := e.st.Write(ctx, func(q *dbq.Queries) error {
		now := store.Now()
		for _, s := range []dbq.InsertSiteParams{
			{Name: "home", Subnet: "10.240.0.0/28", ConnectorIp: "10.240.0.2", LanCidr: &lan, PublicKey: &pub, PskEnc: pskEnc, Enabled: 1, Status: "pending"},
			{Name: "nokey", Subnet: "10.240.0.16/28", ConnectorIp: "10.240.0.18", Enabled: 1, Status: "pending"},
			{Name: "off", Subnet: "10.240.0.32/28", ConnectorIp: "10.240.0.34", PublicKey: &pub, Enabled: 0, Status: "offline"},
		} {
			s.CreatedAt, s.UpdatedAt = now, now
			if err := q.InsertSite(ctx, s); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	e.reconcile(false)
	if len(wg.applied) != 1 {
		t.Fatalf("WireGuard %d-mal angewendet", len(wg.applied))
	}
	d := wg.applied[0]
	if d.Address != "10.240.0.1/16" || d.ListenPort != 51820 || wireguard.ValidateKey(d.PrivateKey) != nil {
		t.Fatalf("Hub: %+v", d)
	}
	// Nur aktive Sites mit Public Key werden zu Peers.
	if len(d.Peers) != 1 || d.Peers[0].Name != "home" || d.Peers[0].PSK != psk ||
		strings.Join(d.Peers[0].AllowedIPs, ",") != "10.240.0.0/28,192.168.1.0/24" || strings.Join(d.Routes, ",") != lan {
		t.Fatalf("Peers: %+v Routes: %v", d.Peers, d.Routes)
	}
}

var _ reconcile.Nginx = (*nginx.Controller)(nil)

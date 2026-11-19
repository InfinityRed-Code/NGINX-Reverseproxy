package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/apigen"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/config"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store"
)

type cliEnv struct {
	t   *testing.T
	cfg config.Config
}

// newCLI richtet ein leeres Datenverzeichnis wie im Container ein.
func newCLI(t *testing.T) *cliEnv {
	t.Helper()
	tmp := filepath.ToSlash(t.TempDir())
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	if err := os.WriteFile(tmp+"/master.key", key, 0o600); err != nil {
		t.Fatal(err)
	}
	return &cliEnv{t: t, cfg: config.Config{DBDir: tmp + "/db", BackupDir: tmp + "/backups", RunDir: tmp + "/run", LogDir: tmp + "/log",
		MasterKeyFile: tmp + "/master.key", CRSDir: tmp + "/crs", HTMLDir: tmp + "/html", NginxBin: "nrp-test-no-nginx",
		NginxConf: tmp + "/nginx.conf", WGOverlayCIDR: "10.240.0.0/16", WGPort: 51820}}
}

// run fuehrt einen Befehl wie 'docker exec nrp nrp --offline ...' aus (ohne TTY).
func (e *cliEnv) run(args ...string) (stdout, stderr string, err error) {
	var out, errOut bytes.Buffer
	a := &app{version: "test", cfg: e.cfg, out: &out, errOut: &errOut, in: strings.NewReader("")}
	root := a.rootCmd()
	root.SetArgs(append([]string{"--offline"}, args...))
	root.SetOut(&out)
	root.SetErr(&errOut)
	err = root.Execute()
	for i := len(a.cleanup) - 1; i >= 0; i-- {
		a.cleanup[i]()
	}
	return out.String(), errOut.String(), err
}

func (e *cliEnv) ok(args ...string) string {
	e.t.Helper()
	out, errOut, err := e.run(args...)
	if err != nil {
		e.t.Fatalf("nrp --offline %s: %v\n%s%s", strings.Join(args, " "), err, out, errOut)
	}
	return out
}

func (e *cliEnv) fails(want string, args ...string) {
	e.t.Helper()
	out, _, err := e.run(args...)
	if err == nil || !strings.Contains(err.Error(), want) {
		e.t.Fatalf("nrp --offline %s: Fehler %v, erwartet %q\n%s", strings.Join(args, " "), err, want, out)
	}
}

func TestOfflineHostWorkflow(t *testing.T) {
	e := newCLI(t)
	// v2-Flags funktionieren unveraendert.
	out := e.ok("host", "add", "app.example.com", "-i", "192.168.1.10", "-p", "8080", "-w", "--waf")
	if !strings.Contains(out, "app.example.com") || !strings.Contains(out, "pending_certificate") {
		t.Fatalf("host add:\n%s", out)
	}
	// Ohne TTY sind fehlende Pflichtangaben ein Fehler statt einer Rueckfrage.
	e.fails("kein TTY", "host", "add", "other.example.com")
	e.fails("existiert bereits", "host", "add", "app.example.com", "-i", "192.168.1.10", "-p", "8080")
	e.ok("host", "add", "app.example.com", "-i", "192.168.1.20", "-p", "9090", "--overwrite")

	var hosts []apigen.Host
	if err := json.Unmarshal([]byte(e.ok("list", "-o", "json")), &hosts); err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].Upstream.Address != "192.168.1.20" || hosts[0].Websockets || hosts[0].Version != 2 {
		t.Fatalf("Hosts nach --overwrite: %+v", hosts)
	}
	// host set setzt If-Match automatisch aus dem vorherigen GET.
	out = e.ok("host", "set", "app.example.com", "--waf", "--client-max-body-size", "1g", "-o", "yaml")
	if !strings.Contains(out, "waf: true") || !strings.Contains(out, "client_max_body_size: 1g") || !strings.Contains(out, "version: 3") {
		t.Fatalf("host set:\n%s", out)
	}
	e.fails("keine Aenderung", "host", "set", "app.example.com")
	e.fails("nicht gefunden", "host", "show", "missing.example.com")

	e.ok("settings", "set", "client_max_body_size=250M", "hsts.max_age=600")
	if out := e.ok("settings", "show"); !strings.Contains(out, "250M") || !strings.Contains(out, "600") {
		t.Fatalf("settings:\n%s", out)
	}
	if out := e.ok("waf", "set", "on"); !strings.Contains(out, "On") {
		t.Fatalf("waf set:\n%s", out)
	}
	e.fails("unbekannter Modus", "waf", "set", "banana")
	if out := e.ok("status"); !strings.Contains(out, "offline") || !strings.Contains(out, "Hosts:") {
		t.Fatalf("status:\n%s", out)
	}
	if out := e.ok("job", "list"); !strings.Contains(out, "cert_issue") || !strings.Contains(out, "queued") {
		t.Fatalf("job list:\n%s", out)
	}

	// Offline-Aktionen stehen mit actor_type=offline im Audit-Log; die Kette ist intakt.
	if out := e.ok("audit", "list", "--limit", "3"); !strings.Contains(out, "offline:uid=") || !strings.Contains(out, "waf.set") {
		t.Fatalf("audit list:\n%s", out)
	}
	if out := e.ok("audit", "verify"); !strings.Contains(out, "intakt") {
		t.Fatalf("audit verify:\n%s", out)
	}
	if out := e.ok("backup", "--out", "snap.db"); !strings.Contains(out, "snap.db") {
		t.Fatalf("backup:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(e.cfg.BackupDir, "snap.db")); err != nil {
		t.Fatal(err)
	}
	e.ok("host", "remove", "app.example.com")
	if out := e.ok("list"); !strings.Contains(out, "Keine Hosts") {
		t.Fatalf("list nach remove:\n%s", out)
	}
	e.fails("WireGuard ist deaktiviert", "site", "list")
}

func TestOfflineRefusesWhileServiceHoldsLock(t *testing.T) {
	e := newCLI(t)
	e.ok("status")
	release, err := store.AcquireLock(e.cfg.LockPath()) // nrpd haelt die Sperre dauerhaft
	if err != nil {
		t.Fatal(err)
	}
	e.fails("Dienst laeuft - ohne --offline verwenden", "host", "list")
	release()
	e.ok("host", "list")
}

func TestOfflineNeedsMasterKey(t *testing.T) {
	e := newCLI(t)
	if err := os.Remove(e.cfg.MasterKeyFile); err != nil {
		t.Fatal(err)
	}
	e.fails("Master-Key", "status")
}

func TestExportApplyRoundtrip(t *testing.T) {
	src := newCLI(t)
	src.ok("host", "add", "a.example.com", "-i", "10.0.0.1", "-p", "80")
	src.ok("host", "add", "b.example.com", "-i", "10.0.0.2", "-p", "443", "-s", "https", "-e", "8444", "--waf", "--hsts-max-age", "63072000", "--hsts-preload")
	src.ok("settings", "set", "client_max_body_size=300M")
	src.ok("waf", "set", "detection-only")
	doc := src.ok("export")
	if !strings.Contains(doc, "fqdn: b.example.com") || !strings.Contains(doc, "preload: true") || !strings.Contains(doc, "client_max_body_size: 300M") {
		t.Fatalf("export:\n%s", doc)
	}
	file := filepath.Join(t.TempDir(), "hosts.yaml")
	if err := os.WriteFile(file, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	dst := newCLI(t)
	dst.ok("host", "add", "stale.example.com", "-i", "10.0.0.9", "-p", "80")
	dst.ok("host", "add", "a.example.com", "-i", "10.9.9.9", "-p", "81")
	if out := dst.ok("apply", "-f", file, "--dry-run", "--prune"); !strings.Contains(out, "(dry-run) host b.example.com: anlegen") ||
		!strings.Contains(out, "host a.example.com: ersetzen") || !strings.Contains(out, "host stale.example.com: entfernen") {
		t.Fatalf("dry-run:\n%s", out)
	}
	if out := dst.ok("list"); !strings.Contains(out, "stale.example.com") || strings.Contains(out, "b.example.com") {
		t.Fatalf("--dry-run hat geschrieben:\n%s", out)
	}
	dst.ok("apply", "-f", file, "--prune")
	if got := dst.ok("export"); got != doc {
		t.Fatalf("Export nach apply weicht ab.\n--- Quelle ---\n%s--- Ziel ---\n%s", doc, got)
	}
	// Erneutes Anwenden ist idempotent.
	if out := dst.ok("apply", "-f", file); strings.Contains(out, "ersetzen") || strings.Contains(out, "anlegen") {
		t.Fatalf("zweites apply aendert etwas:\n%s", out)
	}
}

func TestParseWhen(t *testing.T) {
	for _, ok := range []string{"2026-11-18T10:00:00Z", "2026-11-18", "24h", "7d", "90d"} {
		if _, err := parseWhen(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "gestern", "-5d", "7w"} {
		if _, err := parseWhen(bad); err == nil {
			t.Errorf("%q sollte abgelehnt werden", bad)
		}
	}
}

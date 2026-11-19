// Package reconcile gleicht den tatsaechlichen Zustand (nginx-Konfiguration,
// Zertifikate auf tmpfs, WireGuard) mit dem DB-Zustand ab. API-Handler schreiben
// nur in die DB; genau ein Reconciler rendert, testet und laedt neu.
package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/audit"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/config"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/domain"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/nginx"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/render"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/secrets"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store/dbq"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/wireguard"
)

const (
	Debounce        = 300 * time.Millisecond
	KeepGenerations = 10
)

// Nginx ist die vom Reconciler benoetigte Steuerung (in Tests ersetzbar).
type Nginx interface {
	Test(ctx context.Context, conf string) (string, error)
	CheckWAF(ctx context.Context, rules string) (string, error)
	Reload(ctx context.Context) error
	Running() bool
}

type Result struct {
	Generation int64
	Changed    bool
	Reloaded   bool
	Error      string
}

type Reconciler struct {
	cfg   config.Config
	store *store.Store
	box   *secrets.Box
	nginx Nginx
	wg    wireguard.Manager // nil = WireGuard deaktiviert
	log   *slog.Logger

	mu      sync.Mutex // serialisiert Reconcile und Rollback
	trigger chan struct{}
	running bool

	stateMu sync.RWMutex
	pinned  bool
	lastErr string
}

func New(cfg config.Config, st *store.Store, box *secrets.Box, ng Nginx, wg wireguard.Manager, log *slog.Logger) *Reconciler {
	if log == nil {
		log = slog.Default()
	}
	r := &Reconciler{cfg: cfg, store: st, box: box, nginx: ng, wg: wg, log: log, trigger: make(chan struct{}, 1)}
	_, err := os.Stat(r.pinFile())
	r.pinned = err == nil
	return r
}

func (r *Reconciler) pinFile() string     { return filepath.Join(r.cfg.RenderDir(), "pinned") }
func (r *Reconciler) currentLink() string { return filepath.Join(r.cfg.RenderDir(), "current") }
func (r *Reconciler) genDir(n int64) string {
	return r.cfg.RenderDir() + "/gen-" + strconv.FormatInt(n, 10)
}
func (r *Reconciler) Available(n int64) bool { _, err := os.Stat(r.genDir(n)); return err == nil }

// Trigger meldet eine Aenderung. Im Offline-Modus (kein Run) ohne Wirkung.
func (r *Reconciler) Trigger() {
	select {
	case r.trigger <- struct{}{}:
	default:
	}
}

// Run verarbeitet Trigger bis ctx endet. Viele Aenderungen werden per Debounce
// zu einem Reload gebuendelt.
func (r *Reconciler) Run(ctx context.Context) {
	r.running = true
	retry := time.NewTimer(time.Hour)
	retry.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-retry.C:
		case <-r.trigger:
			select {
			case <-ctx.Done():
				return
			case <-time.After(Debounce):
			}
			select { // waehrend des Debounce eingetroffene Trigger zusammenfassen
			case <-r.trigger:
			default:
			}
		}
		if _, err := r.Reconcile(ctx, false); err != nil {
			r.log.Error("reconcile fehlgeschlagen", "error", err)
			retry.Reset(15 * time.Second)
		}
	}
}

// State liefert aktuelle Generation, Pin-Zustand und letzten Fehler.
func (r *Reconciler) State() (gen int64, pinned bool, lastErr string) {
	r.stateMu.RLock()
	defer r.stateMu.RUnlock()
	return r.currentGen(), r.pinned, r.lastErr
}

func (r *Reconciler) setState(pinned *bool, lastErr *string) {
	r.stateMu.Lock()
	defer r.stateMu.Unlock()
	if pinned != nil {
		r.pinned = *pinned
		if *pinned {
			_ = os.WriteFile(r.pinFile(), []byte("rollback\n"), 0o600)
		} else {
			_ = os.Remove(r.pinFile())
		}
	}
	if lastErr != nil {
		r.lastErr = *lastErr
	}
}

var genRe = regexp.MustCompile(`gen-([0-9]+)$`)

func (r *Reconciler) currentGen() int64 {
	target, err := os.Readlink(r.currentLink())
	if err != nil {
		return 0
	}
	if m := genRe.FindStringSubmatch(filepath.ToSlash(target)); m != nil {
		n, _ := strconv.ParseInt(m[1], 10, 64)
		return n
	}
	return 0
}

func (r *Reconciler) diskGens() []int64 {
	entries, _ := os.ReadDir(r.cfg.RenderDir())
	var out []int64
	for _, e := range entries {
		if m := genRe.FindStringSubmatch(e.Name()); m != nil && e.IsDir() {
			n, _ := strconv.ParseInt(m[1], 10, 64)
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// CurrentFiles liest die aktive Generation (Debug-Ausgabe, ohne Schluessel).
func (r *Reconciler) CurrentFiles() (int64, map[string]string, error) {
	gen := r.currentGen()
	files := map[string]string{}
	if gen == 0 {
		return 0, files, nil
	}
	root := r.genDir(gen)
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(d.Name(), ".") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		files[filepath.ToSlash(rel)] = string(b)
		return nil
	})
	return gen, files, err
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type snapshot struct {
	settings domain.Settings
	hosts    []dbq.Host
	certs    map[string]dbq.Certificate
	sites    []dbq.Site
}

func (r *Reconciler) snapshot(ctx context.Context) (snapshot, error) {
	q := r.store.Read()
	var s snapshot
	var err error
	if s.settings, err = store.LoadSettings(ctx, q); err != nil {
		return s, err
	}
	all, err := q.ListHosts(ctx)
	if err != nil {
		return s, err
	}
	for _, h := range all {
		if !quarantined(h) {
			s.hosts = append(s.hosts, h)
		}
	}
	certs, err := q.ListCertificates(ctx)
	if err != nil {
		return s, err
	}
	s.certs = make(map[string]dbq.Certificate, len(certs))
	for _, c := range certs {
		s.certs[c.Fqdn] = c
	}
	s.sites, err = q.ListSites(ctx)
	return s, err
}

func certFingerprint(chainPEM string) string {
	block, _ := pem.Decode([]byte(chainPEM))
	if block == nil {
		return ""
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

// materializeCerts schreibt Kette und Schluessel der genutzten Zertifikate nach
// tmpfs und entfernt Verzeichnisse nicht mehr vorhandener Hosts.
func (r *Reconciler) materializeCerts(s snapshot) (map[string]string, error) {
	fps := map[string]string{}
	dir := r.cfg.CertsDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	for _, h := range s.hosts {
		c, ok := s.certs[h.Fqdn]
		if !ok || store.ParseTime(c.NotAfter).Before(time.Now()) {
			continue
		}
		key, err := r.box.Open(c.KeyEnc)
		if err != nil {
			return nil, fmt.Errorf("Zertifikat %s: %w", h.Fqdn, err)
		}
		fp := certFingerprint(c.ChainPem)
		if fp == "" {
			return nil, fmt.Errorf("Zertifikat %s: Kette nicht lesbar", h.Fqdn)
		}
		marker := filepath.Join(dir, h.Fqdn, ".fingerprint")
		if cur, err := os.ReadFile(marker); err != nil || string(cur) != fp {
			if err := os.MkdirAll(filepath.Join(dir, h.Fqdn), 0o700); err != nil {
				return nil, err
			}
			if err := writeAtomic(filepath.Join(dir, h.Fqdn, "fullchain.pem"), []byte(c.ChainPem), 0o600); err != nil {
				return nil, err
			}
			if err := writeAtomic(filepath.Join(dir, h.Fqdn, "privkey.pem"), key, 0o600); err != nil {
				return nil, err
			}
			if err := writeAtomic(marker, []byte(fp), 0o600); err != nil {
				return nil, err
			}
		}
		fps[h.Fqdn] = fp
	}
	return fps, nil
}

func (r *Reconciler) cleanupCerts(keep map[string]string) {
	entries, _ := os.ReadDir(r.cfg.CertsDir())
	for _, e := range entries {
		if _, ok := keep[e.Name()]; !ok && e.IsDir() {
			_ = os.RemoveAll(filepath.Join(r.cfg.CertsDir(), e.Name()))
		}
	}
}

func (r *Reconciler) renderInput(s snapshot, fps map[string]string) render.Input {
	in := render.Input{
		WAFMode:      s.settings.WAFMode,
		WAFOverrides: s.settings.WAFOverrides,
		Paths: render.Paths{
			CertsDir: r.cfg.CertsDir(), AcmeDir: r.cfg.AcmeDir(), HTMLDir: r.cfg.HTMLDir, CRSDir: r.cfg.CRSDir,
			CorazaAuditLog: r.cfg.LogDir + "/coraza/audit.log",
		},
	}
	if b, err := os.ReadFile(filepath.Join(r.cfg.CRSDir, "crs-setup.conf.example")); err == nil {
		in.CRSSetup = string(b)
	}
	for _, h := range s.hosts {
		rh := render.Host{
			FQDN: h.Fqdn, Scheme: h.UpstreamScheme, Address: h.UpstreamAddress, Port: int(h.UpstreamPort),
			ExternalPort: int(h.ExternalPort), Websockets: h.Websockets != 0, WAF: h.Waf != 0,
			ClientMaxBodySize: s.settings.ClientMaxBodySize, HSTS: s.settings.HSTS, CertFingerprint: fps[h.Fqdn],
		}
		if h.ClientMaxBodySize != nil {
			rh.ClientMaxBodySize = *h.ClientMaxBodySize
		}
		if h.HstsJson != nil {
			_ = json.Unmarshal([]byte(*h.HstsJson), &rh.HSTS)
		}
		in.Hosts = append(in.Hosts, rh)
	}
	return in
}

const fallbackNginxConf = `user nginx;
worker_processes auto;
pid /run/nginx.pid;
events { worker_connections 4096; }
http {
    include       /etc/nginx/mime.types;
    server_tokens off;
    map $http_upgrade $connection_upgrade { default upgrade; '' close; }
    include /run/nrp/render/current/http.d/*.conf;
}
`

// testConf ist /etc/nginx/nginx.conf mit dem Include auf die neue Generation.
func (r *Reconciler) testConf(genDir string) string {
	base := fallbackNginxConf
	if b, err := os.ReadFile(r.cfg.NginxConf); err == nil {
		base = string(b)
	}
	return strings.ReplaceAll(base, "/run/nrp/render/current/", genDir+"/")
}

func (r *Reconciler) switchTo(gen int64) error {
	tmp := r.currentLink() + ".tmp"
	_ = os.Remove(tmp)
	if err := os.Symlink(r.genDir(gen), tmp); err != nil {
		return err
	}
	err := os.Rename(tmp, r.currentLink())
	if err != nil && runtime.GOOS == "windows" {
		// Windows ersetzt keinen Verzeichnis-Symlink per rename (nur Entwicklung).
		_ = os.Remove(r.currentLink())
		err = os.Rename(tmp, r.currentLink())
	}
	return err
}

func (r *Reconciler) reload(ctx context.Context) (bool, error) {
	err := r.nginx.Reload(ctx)
	if errors.Is(err, nginx.ErrNotRunning) {
		// nginx liest beim Start ohnehin die aktuelle Generation.
		return false, nil
	}
	return err == nil, err
}

var hostFileRe = regexp.MustCompile(`http\.d/host-([a-z0-9.-]+)\.conf`)

// Reconcile bringt nginx und WireGuard auf den DB-Stand. force erzwingt das
// Anwenden auch ohne Inhaltsaenderung und hebt einen Rollback-Pin auf.
func (r *Reconciler) Reconcile(ctx context.Context, force bool) (Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reconcile(ctx, force, 0)
}

// QuarantinePrefix kennzeichnet in status_detail Hosts, deren Konfiguration
// nginx -t abgelehnt hat. Sie werden nicht gerendert, bis der Host geaendert wird;
// so blockiert ein einzelner defekter Host (z. B. nicht aufloesbarer Upstream)
// nicht alle anderen Aenderungen.
const QuarantinePrefix = "nginx -t: "

func quarantined(h dbq.Host) bool {
	return h.Status == domain.HostError && h.StatusDetail != nil && strings.HasPrefix(*h.StatusDetail, QuarantinePrefix)
}

func (r *Reconciler) reconcile(ctx context.Context, force bool, depth int) (Result, error) {
	s, err := r.snapshot(ctx)
	if err != nil {
		return Result{}, err
	}
	var wgErr error
	if r.wg != nil {
		wgErr = r.syncWireGuard(ctx, s)
		if wgErr != nil {
			r.log.Error("WireGuard-Abgleich fehlgeschlagen", "error", wgErr)
		}
	}

	cur := r.currentGen()
	_, pinned, _ := r.State()
	if pinned && !force {
		return Result{Generation: cur}, wgErr
	}
	if force && pinned {
		f := false
		r.setState(&f, nil)
	}

	fps, err := r.materializeCerts(s)
	if err != nil {
		return Result{Generation: cur}, err
	}
	files, err := render.Render(r.renderInput(s, fps))
	if err != nil {
		return Result{Generation: cur}, err
	}
	hash := render.Hash(files)
	if cur != 0 && !force {
		if b, err := os.ReadFile(filepath.Join(r.genDir(cur), ".sha256")); err == nil && string(b) == hash {
			r.cleanupCerts(fps)
			r.markActive(ctx, s, fps)
			if wgErr == nil {
				empty := ""
				r.setState(nil, &empty)
			}
			return Result{Generation: cur}, wgErr
		}
	}

	maxID, err := r.store.Read().MaxGenerationID(ctx)
	if err != nil {
		return Result{Generation: cur}, err
	}
	gen := maxID + 1
	if d := r.diskGens(); len(d) > 0 && d[len(d)-1] >= gen {
		gen = d[len(d)-1] + 1
	}
	dir := r.genDir(gen)
	for name, content := range render.Materialize(files, dir) {
		if err := writeAtomic(filepath.Join(dir, filepath.FromSlash(name)), []byte(content), 0o644); err != nil {
			return Result{Generation: cur}, err
		}
	}
	testConf := filepath.Join(dir, "nginx.test.conf")
	if err := os.WriteFile(testConf, []byte(r.testConf(dir)), 0o644); err != nil {
		return Result{Generation: cur}, err
	}
	if err := os.WriteFile(filepath.Join(dir, ".sha256"), []byte(hash), 0o644); err != nil {
		return Result{Generation: cur}, err
	}

	out, testErr := r.nginx.Test(ctx, testConf)
	corazaHash := subsetHash(files, "coraza/")
	if testErr == nil && wafInUse(files) && !r.corazaChecked(cur, corazaHash) {
		// nginx -t validiert die Coraza-Regeln nicht; eine defekte Regeldatei
		// wuerde nach dem Reload alle Worker beenden.
		out, testErr = r.nginx.CheckWAF(ctx, dir+"/coraza/main.conf")
	}
	if testErr != nil {
		msg := strings.TrimSpace(out)
		if msg == "" {
			msg = testErr.Error()
		}
		_ = os.RemoveAll(dir)
		if r.rejected(ctx, gen, hash, msg) && depth < 25 {
			// Verursacher ist in Quarantaene: den Rest trotzdem anwenden.
			res, err := r.reconcile(ctx, force, depth+1)
			if res.Error == "" {
				res.Error = msg
			}
			r.setState(nil, &res.Error)
			return res, err
		}
		r.setState(nil, &msg)
		return Result{Generation: cur, Error: msg}, nil
	}

	_ = os.WriteFile(filepath.Join(dir, ".coraza-sha256"), []byte(corazaHash), 0o644)
	if err := r.switchTo(gen); err != nil {
		return Result{Generation: cur}, fmt.Errorf("Generation aktivieren: %w", err)
	}
	reloaded, reloadErr := r.reload(ctx)
	now := store.Now()
	_ = r.store.Write(ctx, func(q *dbq.Queries) error {
		if err := q.InsertGeneration(ctx, dbq.InsertGenerationParams{ID: gen, ContentSha256: hash, Status: "applied",
			NginxTestOutput: nil, CreatedAt: now}); err != nil {
			return err
		}
		return q.PruneGenerations(ctx, gen-200)
	})
	r.pruneDisk(gen)
	r.cleanupCerts(fps)
	r.markActive(ctx, s, fps)

	msg := ""
	if reloadErr != nil {
		msg = reloadErr.Error()
	} else if wgErr != nil {
		msg = wgErr.Error()
	}
	r.setState(nil, &msg)
	r.log.Info("Generation angewendet", "generation", gen, "reloaded", reloaded, "hosts", len(fps))
	return Result{Generation: gen, Changed: true, Reloaded: reloaded, Error: msg}, reloadErr
}

// rejected protokolliert eine von nginx -t abgelehnte Generation. Laesst sich
// der verursachende Host aus der Ausgabe ablesen, erhaelt er den Status error.
func (r *Reconciler) rejected(ctx context.Context, gen int64, hash, output string) (hostIdentified bool) {
	r.log.Error("nginx -t hat die Generation abgelehnt; alte Konfiguration bleibt aktiv", "generation", gen, "output", output)
	var row dbq.AuditLog
	err := r.store.Write(ctx, func(q *dbq.Queries) error {
		if err := q.InsertGeneration(ctx, dbq.InsertGenerationParams{ID: gen, ContentSha256: hash, Status: "rejected",
			NginxTestOutput: &output, CreatedAt: store.Now()}); err != nil {
			return err
		}
		resID := strconv.FormatInt(gen, 10)
		if m := hostFileRe.FindStringSubmatch(output); m != nil {
			detail := QuarantinePrefix + output
			hostIdentified = true
			if err := q.SetHostStatus(ctx, dbq.SetHostStatusParams{Status: domain.HostError, StatusDetail: &detail, Fqdn: m[1]}); err != nil {
				return err
			}
		}
		var err error
		row, err = audit.Append(ctx, q, audit.Entry{RequestID: "system", ActorType: audit.ActorSystem, ActorID: "nrpd",
			Action: "render.rejected", ResourceType: "generation", ResourceID: resID, Result: audit.Failed, Error: output})
		return err
	})
	if err == nil {
		audit.Emit(row)
	}
	return hostIdentified && err == nil
}

// markActive setzt Hosts mit ausgeliefertem Zertifikat auf active.
func (r *Reconciler) markActive(ctx context.Context, s snapshot, fps map[string]string) {
	for _, h := range s.hosts {
		if _, ok := fps[h.Fqdn]; ok && h.Status != domain.HostActive {
			_ = r.store.Write(ctx, func(q *dbq.Queries) error {
				return q.SetHostStatus(ctx, dbq.SetHostStatusParams{Status: domain.HostActive, Fqdn: h.Fqdn})
			})
		}
	}
}

func (r *Reconciler) pruneDisk(current int64) {
	gens := r.diskGens()
	for i := 0; i < len(gens)-KeepGenerations; i++ {
		if gens[i] != current {
			_ = os.RemoveAll(r.genDir(gens[i]))
		}
	}
}

func (r *Reconciler) syncWireGuard(ctx context.Context, s snapshot) error {
	hub, err := r.store.Read().GetWgHub(ctx)
	if err != nil {
		return fmt.Errorf("WireGuard-Hub: %w", err)
	}
	d, err := wireguard.BuildDesired(hub, s.sites, r.box)
	if err != nil {
		return err
	}
	return r.wg.Apply(d)
}

// Rollback schaltet auf eine fruehere Generation zurueck und pinnt sie, bis ein
// erzwungenes Reconcile (nrp render apply) wieder den DB-Stand anwendet.
func (r *Reconciler) Rollback(ctx context.Context, gen int64) (Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cur := r.currentGen()
	if !r.Available(gen) {
		return Result{Generation: cur}, fmt.Errorf("Generation %d ist nicht mehr vorhanden", gen)
	}
	if gen == cur {
		return Result{Generation: cur}, nil
	}
	if err := r.switchTo(gen); err != nil {
		return Result{Generation: cur}, err
	}
	reloaded, err := r.reload(ctx)
	_ = r.store.Write(ctx, func(q *dbq.Queries) error {
		return q.SetGenerationStatus(ctx, dbq.SetGenerationStatusParams{Status: "rolled_back", ID: cur})
	})
	t := true
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	r.setState(&t, &msg)
	return Result{Generation: gen, Changed: true, Reloaded: reloaded, Error: msg}, err
}

// subsetHash ist der Inhalts-Hash aller Dateien unter prefix.
func subsetHash(files map[string]string, prefix string) string {
	sub := map[string]string{}
	for n, c := range files {
		if strings.HasPrefix(n, prefix) {
			sub[n] = c
		}
	}
	return render.Hash(sub)
}

// wafInUse: mindestens ein gerenderter Host bindet die Coraza-Regelkette ein.
func wafInUse(files map[string]string) bool {
	for n, c := range files {
		if strings.HasPrefix(n, "http.d/host-") && strings.Contains(c, "coraza on;") {
			return true
		}
	}
	return false
}

// corazaChecked: die Regelkette der aktiven Generation ist identisch und wurde
// bereits geprueft.
func (r *Reconciler) corazaChecked(cur int64, hash string) bool {
	if cur == 0 {
		return false
	}
	b, err := os.ReadFile(filepath.Join(r.genDir(cur), ".coraza-sha256"))
	return err == nil && string(b) == hash
}

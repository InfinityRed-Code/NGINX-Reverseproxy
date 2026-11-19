package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/acme"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/apigen"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/audit"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/auth"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/jobs"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/nginx"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/reconcile"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/secrets"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/server"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/wireguard"
)

// core sind die Bausteine, die Dienst und Offline-Modus teilen.
type core struct {
	store *store.Store
	box   *secrets.Box
	ngx   *nginx.Controller
	close func()
}

// openCore nimmt die exklusive Sperre, laedt den Master-Key, oeffnet die DB und
// migriert sie. Der Offline-Modus bricht hier ab, wenn nrpd laeuft.
func (a *app) openCore(ctx context.Context) (*core, error) {
	release, err := store.AcquireLock(a.cfg.LockPath())
	if errors.Is(err, store.ErrLocked) {
		return nil, errors.New("Dienst laeuft - ohne --offline verwenden")
	} else if err != nil {
		return nil, fmt.Errorf("Sperre %s: %w", a.cfg.LockPath(), err)
	}
	box, err := secrets.Load(a.cfg.MasterKeyFile)
	if err != nil {
		release()
		return nil, err
	}
	st, err := store.Open(a.cfg.DBPath())
	if err != nil {
		release()
		return nil, err
	}
	closeAll := func() { _ = st.Close(); release() }
	if err := st.Migrate(ctx); err != nil {
		closeAll()
		return nil, err
	}
	return &core{store: st, box: box, ngx: nginx.New(a.cfg.NginxBin, a.cfg.WAFCheckBin), close: closeAll}, nil
}

func (a *app) logger() *slog.Logger {
	lvl := slog.LevelInfo
	_ = lvl.UnmarshalText([]byte(a.cfg.LogLevel))
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}

// offlineTransport baut den API-Handler direkt auf der Datenbank auf.
func (a *app) offlineTransport() (http.RoundTripper, error) {
	c, err := a.openCore(context.Background())
	if err != nil {
		return nil, err
	}
	a.cleanup = append(a.cleanup, c.close)
	audit.Output = io.Discard
	log := slog.New(slog.NewTextHandler(a.errOut, &slog.HandlerOptions{Level: slog.LevelWarn}))
	var wg wireguard.Manager
	if a.cfg.WireGuardEnabled {
		wg = wireguard.NewManager()
	}
	rec := reconcile.New(a.cfg, c.store, c.box, c.ngx, wg, log)
	srv := server.New(server.Deps{Cfg: a.cfg, Store: c.store, Box: c.box, Reconciler: rec, Nginx: c.ngx, WG: wg,
		Version: a.version, Mode: server.ModeOffline, Log: log})
	id := auth.Identity{Type: auth.TypeOffline, ID: "uid=" + strconv.Itoa(os.Geteuid()), Role: auth.Admin}
	return server.InProcess{Handler: srv.Handler(), Identity: id}, nil
}

func (a *app) serveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Startet den NRP-Dienst (nrpd); wird im Container von s6 gestartet",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.serve(ctxOf(cmd))
		},
	}
}

func (a *app) serve(parent context.Context) error {
	log := a.logger()
	slog.SetDefault(log)
	ctx, stop := signal.NotifyContext(parent, syscall.SIGTERM, os.Interrupt)
	defer stop()

	c, err := a.openCore(ctx)
	if err != nil {
		return err
	}
	defer c.close()
	cfg := a.cfg
	for _, dir := range []string{cfg.RunDir, cfg.RenderDir(), cfg.AcmeDir()} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	for _, dir := range []string{cfg.LogDir + "/nginx", cfg.LogDir + "/coraza", cfg.BackupDir} {
		_ = os.MkdirAll(dir, 0o750)
	}

	var wg wireguard.Manager
	if cfg.WireGuardEnabled {
		hub, err := wireguard.EnsureHub(ctx, c.store, c.box, cfg.WGOverlayCIDR, cfg.WGPort)
		if err != nil {
			return fmt.Errorf("WireGuard-Hub: %w", err)
		}
		if int(hub.ListenPort) != cfg.WGPort {
			log.Warn("NRP_WG_PORT weicht vom gespeicherten Hub-Port ab; es gilt der Port aus der Datenbank (Portfreigabe in compose.yaml anpassen)",
				"env", cfg.WGPort, "db", hub.ListenPort)
		}
		wg = wireguard.NewManager()
		if cfg.PublicEndpoint == "" {
			log.Warn("NRP_PUBLIC_ENDPOINT ist nicht gesetzt; Install-Scripts fuer Sites koennen nicht erzeugt werden")
		}
	}
	ca, serverCert, err := server.EnsurePKI(ctx, c.store, c.box, cfg.APISANs)
	if err != nil {
		return fmt.Errorf("API-PKI: %w", err)
	}

	rec := reconcile.New(cfg, c.store, c.box, c.ngx, wg, log)
	runner := jobs.NewRunner(c.store, cfg.ACMEWorkers, log)
	email := cfg.ACMEEmail
	if st, err := store.LoadSettings(ctx, c.store.Read()); err == nil && st.ACMEEmail != "" {
		email = st.ACMEEmail
	}
	certs := &acme.Service{Store: c.store, Box: c.box, Log: log, OnChange: rec.Trigger, Notify: runner.Notify,
		Issuer: &acme.LegoIssuer{Directory: cfg.ACMEDirectory, Email: email, Webroot: cfg.AcmeDir(),
			CAFile: cfg.ACMECAFile, Store: c.store, Box: c.box}}
	runner.Handle(jobs.CertIssue, certs.HandleIssue)
	runner.Handle(jobs.CertRenew, certs.HandleIssue)
	runner.Handle(jobs.CertRevoke, certs.HandleRevoke)

	srv := server.New(server.Deps{Cfg: cfg, Store: c.store, Box: c.box, Reconciler: rec, Nginx: c.ngx, WG: wg,
		JobNotify: runner.Notify, Version: a.version, Mode: server.ModeService, Log: log})

	errCh := make(chan error, 8)
	run := func(name string, fn func() error) {
		go func() {
			if err := fn(); err != nil && ctx.Err() == nil {
				errCh <- fmt.Errorf("%s: %w", name, err)
			}
		}()
	}
	bg := func(fn func(context.Context)) { go fn(ctx) }

	bg(rec.Run)
	bg(runner.Run)
	bg(certs.Run)
	run("socket", func() error { return srv.ServeUnix(ctx, cfg.SocketPath()) })
	run("api", func() error { return srv.ServeMTLS(ctx, cfg.APIListen, ca, serverCert) })
	if cfg.TokensEnabled {
		if cfg.APITokenListen == "" {
			log.Warn("NRP_API_TOKENS_ENABLED=true, aber NRP_API_TOKEN_LISTEN fehlt: kein Token-Listener")
		} else {
			run("token-api", func() error { return srv.ServeTokens(ctx, cfg.APITokenListen, serverCert) })
		}
	}
	if cfg.MetricsListen != "" {
		run("metrics", func() error {
			mux := http.NewServeMux()
			mux.Handle("/metrics", srv.MetricsHandler())
			ms := &http.Server{Addr: cfg.MetricsListen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
			go func() { <-ctx.Done(); _ = ms.Close() }()
			if err := ms.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		})
	}
	bg(func(ctx context.Context) { a.housekeeping(ctx, c, wg, log) })

	rec.Trigger() // tmpfs ist nach einem Neustart leer: immer aus der DB rendern
	log.Info("nrpd gestartet", "version", a.version, "api", cfg.APIListen, "socket", cfg.SocketPath(),
		"wireguard", cfg.WireGuardEnabled, "acme", cfg.ACMEDirectory, "key_id", c.box.KeyID())
	select {
	case <-ctx.Done():
		log.Info("nrpd wird beendet")
		time.Sleep(200 * time.Millisecond)
		return nil
	case err := <-errCh:
		log.Error("nrpd beendet sich", "error", err)
		return err
	}
}

// housekeeping: Site-Status aus Handshakes und groessenbasierte Log-Rotation.
func (a *app) housekeeping(ctx context.Context, c *core, wg wireguard.Manager, log *slog.Logger) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if wg != nil {
			if err := wireguard.UpdateStatuses(ctx, c.store, wg); err != nil && ctx.Err() == nil {
				log.Debug("Site-Status", "error", err)
			}
		}
		reopen := false
		for _, sub := range []string{"nginx", "coraza"} {
			r, err := nginx.Rotate(filepath.Join(a.cfg.LogDir, sub), a.cfg.LogMaxBytes, a.cfg.LogKeep)
			if err != nil {
				log.Warn("Log-Rotation", "dir", sub, "error", err)
			}
			reopen = reopen || r
		}
		if reopen {
			if err := c.ngx.Reopen(ctx); err != nil {
				log.Warn("nginx -s reopen", "error", err)
			}
		}
	}
}

func (a *app) healthCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "health",
		Short: "Healthcheck fuer Docker: Dienst erreichbar und nginx laeuft",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(ctxOf(cmd), 4*time.Second)
			defer cancel()
			c, err := a.api()
			if err != nil {
				return err
			}
			st, _, err := do[apigen.Status](c.GetStatus(ctx))
			if err != nil {
				return err
			}
			if !st.Nginx.Running {
				return errors.New("nginx laeuft nicht")
			}
			// Nach einem Neustart ist tmpfs leer: bereit erst, wenn aus der DB gerendert wurde.
			if st.Render.Generation == 0 {
				return errors.New("noch keine Konfiguration angewendet: " + deref(st.Render.LastError))
			}
			fmt.Fprintln(a.out, "ok")
			return nil
		},
	}
}

func (a *app) doctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Prueft DB, Master-Key, nginx, Coraza-Modul, wg0 und Ports",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if a.doctor(ctxOf(cmd)) > 0 {
				return exitError(1)
			}
			return nil
		},
	}
}

func (a *app) doctor(ctx context.Context) (failed int) {
	cfg := a.cfg
	check := func(name string, err error, okDetail string) bool {
		if err != nil {
			failed++
			fmt.Fprintf(a.out, "[FEHLER] %-22s %v\n", name, err)
			return false
		}
		fmt.Fprintf(a.out, "[ok]     %-22s %s\n", name, okDetail)
		return true
	}
	warn := func(name, detail string) { fmt.Fprintf(a.out, "[warn]   %-22s %s\n", name, detail) }

	box, err := secrets.Load(cfg.MasterKeyFile)
	keyID := ""
	if box != nil {
		keyID = "Key-ID " + box.KeyID()
	}
	check("Master-Key", err, keyID)

	st, err := store.Open(cfg.DBPath())
	if check("Datenbank", err, cfg.DBPath()) {
		defer st.Close()
		check("DB-Integritaet", st.IntegrityCheck(ctx), "quick_check ok")
		cur, target, err := st.SchemaVersion(ctx)
		if err == nil && cur != target {
			err = fmt.Errorf("Schema %d, erwartet %d (Dienst starten oder nrp --offline status)", cur, target)
		}
		check("Schema", err, fmt.Sprintf("Version %d", cur))
		if box != nil {
			if row, err := st.Read().GetPki(ctx); err == nil {
				_, err = box.Open(row.CaKeyEnc)
				check("Master-Key passt", err, "Geheimnisse entschluesselbar")
			}
		}
	}
	probe := filepath.Join(cfg.DBDir, ".doctor")
	err = os.WriteFile(probe, nil, 0o600)
	_ = os.Remove(probe)
	check("DB-Verzeichnis", err, "beschreibbar")

	ngx := nginx.New(cfg.NginxBin, cfg.WAFCheckBin)
	info, err := ngx.BuildInfo(ctx)
	if check("nginx", err, "Version "+ngx.Version(ctx)) {
		var merr error
		if !strings.Contains(info, "coraza") {
			merr = errors.New("nginx wurde ohne coraza-nginx gebaut")
		}
		check("Coraza-Modul", merr, "einkompiliert")
	}
	rules, _ := filepath.Glob(filepath.Join(cfg.CRSDir, "rules", "*.conf"))
	var crsErr error
	if len(rules) == 0 {
		crsErr = fmt.Errorf("keine Regeln unter %s/rules", cfg.CRSDir)
	}
	check("OWASP CRS", crsErr, fmt.Sprintf("%s, %d Regeldateien", server.CRSVersion(cfg.CRSDir, cfg.VersionsFile), len(rules)))
	var runErr error
	if !ngx.Running() {
		runErr = errors.New("Master-Prozess laeuft nicht")
	}
	check("nginx-Prozess", runErr, "laeuft")
	if _, err := os.Stat(cfg.RenderDir() + "/current"); err == nil {
		out, err := ngx.Test(ctx, cfg.NginxConf)
		if err != nil {
			err = fmt.Errorf("%v: %s", err, out)
		}
		check("nginx -t", err, "aktive Konfiguration gueltig")
	} else {
		warn("nginx -t", "noch keine Generation gerendert")
	}

	if conn, err := net.DialTimeout("unix", cfg.SocketPath(), 2*time.Second); check("Dienst (Socket)", err, cfg.SocketPath()) {
		conn.Close()
	}
	for _, p := range []string{"80", "443"} {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+p, 2*time.Second)
		if err == nil {
			conn.Close()
		}
		check("Port "+p, err, "nimmt Verbindungen an")
	}
	if conn, err := net.DialTimeout("tcp", strings.Replace(cfg.APIListen, "0.0.0.0", "127.0.0.1", 1), 2*time.Second); check("API-Listener", err, cfg.APIListen) {
		conn.Close()
	}

	if cfg.WireGuardEnabled {
		stats, err := wireguard.NewManager().Stats()
		check("WireGuard wg0", err, fmt.Sprintf("%d Peer(s)", len(stats)))
		if cfg.PublicEndpoint == "" {
			warn("NRP_PUBLIC_ENDPOINT", "nicht gesetzt: Install-Scripts koennen nicht erzeugt werden")
		}
	} else {
		warn("WireGuard", "deaktiviert (NRP_WIREGUARD_ENABLED=false)")
	}
	if failed > 0 {
		fmt.Fprintf(a.out, "\n%d Pruefung(en) fehlgeschlagen.\n", failed)
	} else {
		fmt.Fprintln(a.out, "\nAlle Pruefungen bestanden.")
	}
	return failed
}

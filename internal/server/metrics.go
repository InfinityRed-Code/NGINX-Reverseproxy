package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store"
)

// MetricsHandler liefert Prometheus-Textformat (NRP_METRICS_LISTEN, Standard aus).
func (s *Server) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		st, err := s.BuildStatus(ctx)
		if err != nil {
			http.Error(w, "status nicht verfuegbar", http.StatusInternalServerError)
			return
		}
		var b strings.Builder
		metric := func(name, help, typ string, value any, labels ...string) {
			if help != "" {
				fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
			}
			lbl := ""
			if len(labels) == 2 {
				lbl = fmt.Sprintf("{%s=%q}", labels[0], labels[1])
			}
			fmt.Fprintf(&b, "%s%s %v\n", name, lbl, value)
		}
		bi := func(v bool) int {
			if v {
				return 1
			}
			return 0
		}
		metric("nrp_nginx_up", "nginx-Master laeuft", "gauge", bi(st.Nginx.Running))
		metric("nrp_render_generation", "Aktive Konfigurationsgeneration", "gauge", st.Render.Generation)
		metric("nrp_render_error", "Letztes Reconcile fehlgeschlagen", "gauge", bi(st.Render.LastError != nil))
		metric("nrp_render_pinned", "Rollback aktiv (Generation gepinnt)", "gauge", bi(st.Render.Pinned))
		metric("nrp_hosts", "Hosts nach Status", "gauge", st.Hosts.Active, "status", "active")
		metric("nrp_hosts", "", "", st.Hosts.PendingCertificate, "status", "pending_certificate")
		metric("nrp_hosts", "", "", st.Hosts.Error, "status", "error")
		metric("nrp_jobs", "Jobs nach Status", "gauge", st.Jobs.Queued, "status", "queued")
		metric("nrp_jobs", "", "", st.Jobs.Running, "status", "running")
		metric("nrp_jobs", "", "", st.Jobs.Failed, "status", "failed")
		metric("nrp_sites", "WireGuard-Sites", "gauge", st.Wireguard.SitesTotal, "state", "total")
		metric("nrp_sites", "", "", st.Wireguard.SitesOnline, "state", "online")
		metric("nrp_auth_failures_total", "Fehlgeschlagene API-Authentifizierungen", "counter", s.authFailures.Load())
		if certs, err := s.d.Store.Read().ListCertificates(ctx); err == nil {
			for i, c := range certs {
				help := ""
				if i == 0 {
					help = "Ablaufzeitpunkt des Zertifikats (Unix-Zeit)"
				}
				metric("nrp_certificate_not_after_seconds", help, "gauge", store.ParseTime(c.NotAfter).Unix(), "fqdn", c.Fqdn)
			}
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(b.String()))
	})
}

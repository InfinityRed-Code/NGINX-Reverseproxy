package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/apigen"
)

// ── Zertifikate ─────────────────────────────────────────────────────────────

func (a *app) certCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "cert", Short: "Zertifikate anzeigen, erneuern, entfernen"}
	list := &cobra.Command{
		Use: "list", Aliases: []string{"ls"}, Short: "Zertifikate mit Ablaufdatum", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			l, _, err := do[apigen.CertificateList](c.ListCertificates(ctxOf(cmd)))
			if err != nil {
				return err
			}
			return a.print(l.Items, func(w *tabwriter.Writer) {
				if len(l.Items) == 0 {
					fmt.Fprintln(w, "Keine Zertifikate vorhanden.")
					return
				}
				fmt.Fprintln(w, "FQDN\tGUELTIG BIS\tTAGE\tERNEUERUNG AB\tAUSSTELLER\tQUELLE")
				for _, ct := range l.Items {
					fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\n", ct.Fqdn, ts(&ct.NotAfter), ct.DaysLeft, ts(ct.AriRenewAt), ct.Issuer, ct.Source)
				}
			})
		},
	}
	var pemOut bool
	show := &cobra.Command{
		Use: "show FQDN", Short: "Details eines Zertifikats (ohne privaten Schluessel)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			ct, _, err := do[apigen.Certificate](c.GetCertificate(ctxOf(cmd), args[0]))
			if err != nil {
				return err
			}
			if pemOut {
				_, err := io.WriteString(a.out, deref(ct.ChainPem))
				return err
			}
			return a.print(ct, func(w *tabwriter.Writer) {
				fmt.Fprintf(w, "FQDN:\t%s\nGueltig ab:\t%s\nGueltig bis:\t%s (%d Tage)\nErneuerung ab:\t%s\nAussteller:\t%s\nQuelle:\t%s\n",
					ct.Fqdn, ts(&ct.NotBefore), ts(&ct.NotAfter), ct.DaysLeft, ts(ct.AriRenewAt), ct.Issuer, ct.Source)
			})
		},
	}
	show.Flags().BoolVar(&pemOut, "pem", false, "Zertifikatskette als PEM ausgeben")
	var wait bool
	renew := &cobra.Command{
		Use: "renew FQDN", Short: "Erneuerung erzwingen", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			j, _, err := do[apigen.Job](c.RenewCertificate(ctxOf(cmd), args[0], nil))
			if err != nil {
				return err
			}
			if wait {
				if j, err = a.waitJob(ctxOf(cmd), j.Id, 5*time.Minute); err != nil {
					return err
				}
			}
			return a.printJob(*j)
		},
	}
	renew.Flags().BoolVar(&wait, "wait", false, "Auf den Abschluss warten")
	var revoke bool
	rm := &cobra.Command{
		Use: "remove FQDN", Aliases: []string{"rm"}, Short: "Zertifikat entfernen (optional widerrufen)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			if _, _, err := readResp(c.DeleteCertificate(ctxOf(cmd), args[0], &apigen.DeleteCertificateParams{Revoke: &revoke})); err != nil {
				return err
			}
			fmt.Fprintf(a.out, "Zertifikat %s entfernt%s.\n", args[0], map[bool]string{true: " (Widerruf laeuft als Job)"}[revoke])
			return nil
		},
	}
	rm.Flags().BoolVar(&revoke, "revoke", false, "Bei der CA widerrufen")
	cmd.AddCommand(list, show, renew, rm)
	return cmd
}

// ── Jobs ────────────────────────────────────────────────────────────────────

func (a *app) printJob(j apigen.Job) error {
	return a.print(j, func(w *tabwriter.Writer) {
		fmt.Fprintf(w, "Job:\t%s\nArt:\t%s\nRessource:\t%s\nStatus:\t%s\nVersuche:\t%d\nFehler:\t%s\nErstellt:\t%s von %s\nBeendet:\t%s\n",
			j.Id, j.Kind, j.Resource, j.Status, j.Attempts, str(j.Error, "-"), ts(&j.CreatedAt), j.CreatedBy, ts(j.FinishedAt))
	})
}

func (a *app) jobCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "job", Short: "Lang laufende Aktionen (Zertifikate) verfolgen"}
	var status string
	var limit int
	list := &cobra.Command{
		Use: "list", Aliases: []string{"ls"}, Short: "Jobs auflisten", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			p := &apigen.ListJobsParams{Limit: &limit}
			if status != "" {
				p.Status = ptr(apigen.ListJobsParamsStatus(status))
			}
			l, _, err := do[apigen.JobList](c.ListJobs(ctxOf(cmd), p))
			if err != nil {
				return err
			}
			return a.print(l.Items, func(w *tabwriter.Writer) {
				fmt.Fprintln(w, "ID\tART\tRESSOURCE\tSTATUS\tVERSUCHE\tERSTELLT\tFEHLER")
				for _, j := range l.Items {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n", j.Id, j.Kind, j.Resource, j.Status, j.Attempts, ts(&j.CreatedAt), short(str(j.Error, ""), 60))
				}
			})
		},
	}
	list.Flags().StringVar(&status, "status", "", "queued, running, succeeded oder failed")
	list.Flags().IntVar(&limit, "limit", 50, "Anzahl")
	show := &cobra.Command{
		Use: "show ID", Short: "Job anzeigen", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			j, _, err := do[apigen.Job](c.GetJob(ctxOf(cmd), args[0]))
			if err != nil {
				return err
			}
			return a.printJob(*j)
		},
	}
	var timeout time.Duration
	wait := &cobra.Command{
		Use: "wait ID", Short: "Auf den Abschluss eines Jobs warten", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			j, err := a.waitJob(ctxOf(cmd), args[0], timeout)
			if j != nil {
				_ = a.printJob(*j)
			}
			return err
		},
	}
	wait.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "Maximale Wartezeit")
	cmd.AddCommand(list, show, wait)
	return cmd
}

func short(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

// ── WAF ─────────────────────────────────────────────────────────────────────

func (a *app) printWaf(w apigen.Waf) error {
	return a.print(w, func(tw *tabwriter.Writer) {
		fmt.Fprintf(tw, "Modus:\t%s\nOWASP CRS:\t%s\nHosts mit WAF:\t%d\n", w.Mode, w.CrsVersion, len(w.Hosts))
		for _, h := range w.Hosts {
			fmt.Fprintf(tw, "\t%s\n", h)
		}
		fmt.Fprintf(tw, "Eigene Regeln:\t%s\n", map[bool]string{true: "keine", false: fmt.Sprintf("%d Zeile(n), nrp waf rules show", strings.Count(w.Overrides, "\n")+1)}[strings.TrimSpace(w.Overrides) == ""])
	})
}

func (a *app) wafCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "waf", Short: "Coraza WAF: globaler Modus und eigene Regeln"}
	set := &cobra.Command{
		Use: "set on|detection-only|off", Short: "Globalen Modus setzen (pro Host: nrp host set FQDN --waf)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			mode, ok := map[string]apigen.WafMode{"on": apigen.On, "detection-only": apigen.DetectionOnly, "detectiononly": apigen.DetectionOnly, "off": apigen.Off}[strings.ToLower(args[0])]
			if !ok {
				return fmt.Errorf("unbekannter Modus %q (on, detection-only, off)", args[0])
			}
			c, err := a.api()
			if err != nil {
				return err
			}
			w, _, err := do[apigen.Waf](c.PutWaf(ctxOf(cmd), apigen.WafInput{Mode: &mode}))
			if err != nil {
				return err
			}
			return a.printWaf(*w)
		},
	}
	status := &cobra.Command{
		Use: "status", Short: "Modus, CRS-Version und Hosts mit WAF", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			w, _, err := do[apigen.Waf](c.GetWaf(ctxOf(cmd)))
			if err != nil {
				return err
			}
			return a.printWaf(*w)
		},
	}
	rules := &cobra.Command{Use: "rules", Short: "Eigene Anpassungen (Paranoia Level, SecRuleRemoveById)",
		Long: "Die Datei wird nach crs-setup.conf und vor den CRS-Regeln eingebunden. Alles nach einer Zeile\n'# nrp:after-rules' wird nach den CRS-Regeln eingebunden (noetig fuer SecRuleRemoveById)."}
	var file string
	rulesSet := &cobra.Command{
		Use: "set --file overrides.conf", Short: "Anpassungen ersetzen ('-' liest von stdin)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var raw []byte
			var err error
			if file == "-" {
				raw, err = io.ReadAll(a.in)
			} else {
				raw, err = os.ReadFile(file)
			}
			if err != nil {
				return err
			}
			c, err := a.api()
			if err != nil {
				return err
			}
			w, _, err := do[apigen.Waf](c.PutWaf(ctxOf(cmd), apigen.WafInput{Overrides: ptr(string(raw))}))
			if err != nil {
				return err
			}
			return a.printWaf(*w)
		},
	}
	rulesSet.Flags().StringVar(&file, "file", "", "Datei mit Coraza-Direktiven")
	_ = rulesSet.MarkFlagRequired("file")
	rulesShow := &cobra.Command{
		Use: "show", Short: "Anpassungen ausgeben", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			w, _, err := do[apigen.Waf](c.GetWaf(ctxOf(cmd)))
			if err != nil {
				return err
			}
			_, err = io.WriteString(a.out, w.Overrides)
			return err
		},
	}
	rules.AddCommand(rulesSet, rulesShow)
	cmd.AddCommand(set, status, rules)
	return cmd
}

// ── Settings ────────────────────────────────────────────────────────────────

func (a *app) printSettings(s apigen.Settings) error {
	return a.print(s, func(w *tabwriter.Writer) {
		fmt.Fprintf(w, "client_max_body_size:\t%s\nhsts.max_age:\t%d\nhsts.include_subdomains:\t%t\nhsts.preload:\t%t\nacme_email:\t%s\n",
			s.ClientMaxBodySize, s.Hsts.MaxAge, s.Hsts.IncludeSubdomains, s.Hsts.Preload, str(s.AcmeEmail, "-"))
	})
}

func (a *app) settingsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "settings", Short: "Globale Defaults (ersetzt config.py)"}
	show := &cobra.Command{
		Use: "show", Short: "Defaults anzeigen", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			s, _, err := do[apigen.Settings](c.GetSettings(ctxOf(cmd)))
			if err != nil {
				return err
			}
			return a.printSettings(*s)
		},
	}
	set := &cobra.Command{
		Use:     "set KEY=VALUE...",
		Short:   "Defaults aendern",
		Example: "  nrp settings set client_max_body_size=200M\n  nrp settings set hsts.max_age=63072000 hsts.preload=false\n  nrp settings set acme_email=ops@example.com",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			patch := map[string]any{}
			hsts := map[string]any{}
			for _, kv := range args {
				k, v, ok := strings.Cut(kv, "=")
				if !ok {
					return fmt.Errorf("%q: KEY=VALUE erwartet", kv)
				}
				switch k {
				case "client_max_body_size":
					patch[k] = v
				case "acme_email":
					if v == "" {
						patch[k] = nil
					} else {
						patch[k] = v
					}
				case "hsts.max_age":
					n, err := strconv.ParseInt(v, 10, 64)
					if err != nil {
						return fmt.Errorf("%s: Zahl erwartet", k)
					}
					hsts["max_age"] = n
				case "hsts.include_subdomains", "hsts.preload":
					b, err := strconv.ParseBool(v)
					if err != nil {
						return fmt.Errorf("%s: true oder false erwartet", k)
					}
					hsts[strings.TrimPrefix(k, "hsts.")] = b
				default:
					return fmt.Errorf("unbekannte Einstellung %q", k)
				}
			}
			if len(hsts) > 0 {
				patch["hsts"] = hsts
			}
			c, err := a.api()
			if err != nil {
				return err
			}
			s, _, err := do[apigen.Settings](c.PatchSettingsWithBody(ctxOf(cmd), mergePatchType, jsonBody(patch)))
			if err != nil {
				return err
			}
			return a.printSettings(*s)
		},
	}
	cmd.AddCommand(show, set)
	return cmd
}

// ── Status ──────────────────────────────────────────────────────────────────

func (a *app) statusCmd() *cobra.Command {
	var detailed bool
	cmd := &cobra.Command{
		Use: "status", Short: "Zustand von nginx, Konfiguration, Zertifikaten, WireGuard und Jobs", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := ctxOf(cmd)
			c, err := a.api()
			if err != nil {
				return err
			}
			st, _, err := do[apigen.Status](c.GetStatus(ctx))
			if err != nil {
				return err
			}
			if err := a.print(st, func(w *tabwriter.Writer) {
				fmt.Fprintf(w, "NRP:\t%s (%s)\n", st.Version, st.Mode)
				fmt.Fprintf(w, "nginx:\t%s %s\n", map[bool]string{true: "laeuft", false: "LAEUFT NICHT"}[st.Nginx.Running], deref(st.Nginx.Version))
				fmt.Fprintf(w, "Konfiguration:\tGeneration %d%s\n", st.Render.Generation, map[bool]string{true: " (Rollback aktiv: nrp render apply hebt ihn auf)"}[st.Render.Pinned])
				if st.Render.LastError != nil {
					fmt.Fprintf(w, "Letzter Fehler:\t%s\n", short(*st.Render.LastError, 200))
				}
				fmt.Fprintf(w, "Hosts:\t%d (aktiv %d, Zertifikat ausstehend %d, Fehler %d)\n", st.Hosts.Total, st.Hosts.Active, st.Hosts.PendingCertificate, st.Hosts.Error)
				fmt.Fprintf(w, "Zertifikate:\t%d (in 30 Tagen ablaufend %d, naechster Ablauf %s)\n", st.Certificates.Total, st.Certificates.Expiring30d, ts(st.Certificates.NextExpiry))
				fmt.Fprintf(w, "WAF:\t%s, %d Host(s)\n", st.Waf.Mode, st.Waf.Hosts)
				if st.Wireguard.Enabled {
					fmt.Fprintf(w, "WireGuard:\t%s, Port %d, Sites %d/%d online\n", deref(st.Wireguard.Address), deref(st.Wireguard.ListenPort), st.Wireguard.SitesOnline, st.Wireguard.SitesTotal)
					fmt.Fprintf(w, "Hub Public Key:\t%s\n", deref(st.Wireguard.PublicKey))
				} else {
					fmt.Fprintf(w, "WireGuard:\tdeaktiviert\n")
				}
				fmt.Fprintf(w, "Jobs:\t%d wartend, %d laufend, %d fehlgeschlagen\n", st.Jobs.Queued, st.Jobs.Running, st.Jobs.Failed)
				if st.Crowdsec != nil {
					fmt.Fprintf(w, "CrowdSec:\t%s\n", map[bool]string{true: "erreichbar", false: "NICHT erreichbar"}[st.Crowdsec.Reachable])
				}
			}); err != nil {
				return err
			}
			if detailed && a.output == "table" {
				hosts, err := a.allHosts(ctx)
				if err != nil {
					return err
				}
				fmt.Fprintln(a.out)
				return a.printHosts(hosts)
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&detailed, "detailed", "d", false, "Zusaetzlich alle Hosts ausgeben")
	return cmd
}

// ── Audit ───────────────────────────────────────────────────────────────────

func (a *app) auditCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "audit", Short: "Audit-Log lesen, pruefen und aufraeumen"}
	var since, actor, resource string
	var limit int
	list := &cobra.Command{
		Use: "list", Aliases: []string{"ls"}, Short: "Eintraege anzeigen (neueste zuerst)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			p := &apigen.ListAuditParams{Limit: &limit}
			if since != "" {
				t, err := parseWhen(since)
				if err != nil {
					return err
				}
				p.Since = &t
			}
			if actor != "" {
				p.Actor = &actor
			}
			if resource != "" {
				p.Resource = &resource
			}
			c, err := a.api()
			if err != nil {
				return err
			}
			l, _, err := do[apigen.AuditList](c.ListAudit(ctxOf(cmd), p))
			if err != nil {
				return err
			}
			return a.print(l.Items, func(w *tabwriter.Writer) {
				fmt.Fprintln(w, "SEQ\tZEIT\tAKTEUR\tAKTION\tRESSOURCE\tERGEBNIS\tFEHLER")
				for _, e := range l.Items {
					fmt.Fprintf(w, "%d\t%s\t%s:%s\t%s\t%s\t%s\t%s\n", e.Seq, e.Ts.Local().Format("2006-01-02 15:04:05"), e.ActorType, e.ActorId,
						e.Action, short(str(e.ResourceId, e.ResourceType), 40), e.Result, short(str(e.Error, ""), 50))
				}
			})
		},
	}
	list.Flags().StringVar(&since, "since", "", "Ab Zeitpunkt (RFC 3339, YYYY-MM-DD) oder Dauer (24h, 7d)")
	list.Flags().StringVar(&actor, "actor", "", "Nur dieser Akteur (Client-Name, Token-ID, uid=0)")
	list.Flags().StringVar(&resource, "resource", "", "Nur diese Ressource (ID oder Typ)")
	list.Flags().IntVar(&limit, "limit", 50, "Anzahl")

	verify := &cobra.Command{
		Use: "verify", Short: "Hash-Kette pruefen", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			v, _, err := do[apigen.AuditVerify](c.VerifyAudit(ctxOf(cmd)))
			if err != nil {
				return err
			}
			if err := a.print(v, func(w *tabwriter.Writer) {
				if v.Ok {
					fmt.Fprintf(w, "Hash-Kette intakt: %d Eintraege (seq %d bis %d).\n", v.Entries, deref(v.FirstSeq), deref(v.LastSeq))
				} else {
					fmt.Fprintf(w, "HASH-KETTE BESCHAEDIGT bei seq %d: %s\n", deref(v.BrokenAtSeq), deref(v.Error))
				}
			}); err != nil {
				return err
			}
			if !v.Ok {
				return exitError(2)
			}
			return nil
		},
	}

	var before string
	var yes bool
	prune := &cobra.Command{
		Use: "prune --before DATUM", Short: "Alte Eintraege loeschen (nur lokal; wird selbst protokolliert)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			t, err := parseWhen(before)
			if err != nil {
				return err
			}
			if err := a.confirm(fmt.Sprintf("Audit-Eintraege vor %s endgueltig loeschen?", t.Format(time.RFC3339)), yes); err != nil {
				return err
			}
			c, err := a.api()
			if err != nil {
				return err
			}
			r, _, err := do[apigen.AuditPruneResult](c.PruneAudit(ctxOf(cmd), apigen.AuditPruneInput{Before: t}))
			if err != nil {
				return err
			}
			return a.print(r, func(w *tabwriter.Writer) {
				fmt.Fprintf(w, "%d Eintraege geloescht. Anker: %s\n", r.Deleted, str(r.AnchorHash, "-"))
			})
		},
	}
	prune.Flags().StringVar(&before, "before", "", "Zeitpunkt (RFC 3339, YYYY-MM-DD) oder Alter (90d)")
	prune.Flags().BoolVarP(&yes, "yes", "y", false, "Ohne Rueckfrage")
	_ = prune.MarkFlagRequired("before")
	cmd.AddCommand(list, verify, prune)
	return cmd
}

// parseWhen akzeptiert RFC 3339, ein Datum oder ein Alter wie 24h bzw. 7d.
func parseWhen(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.ParseInLocation("2006-01-02", s, time.Local); err == nil {
		return t, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		if n, err := strconv.Atoi(days); err == nil && n >= 0 {
			return time.Now().Add(-time.Duration(n) * 24 * time.Hour), nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d >= 0 {
		return time.Now().Add(-d), nil
	}
	return time.Time{}, fmt.Errorf("Zeitangabe %q nicht verstanden (RFC 3339, YYYY-MM-DD, 24h oder 7d)", s)
}

// ── Render ──────────────────────────────────────────────────────────────────

func (a *app) printReconcile(r apigen.ReconcileResult) error {
	if err := a.print(r, func(w *tabwriter.Writer) {
		fmt.Fprintf(w, "Generation:\t%d\nGeaendert:\t%s\nnginx neu geladen:\t%s\n", r.Generation, yesNo(r.Changed), yesNo(r.Reloaded))
		if r.Error != nil {
			fmt.Fprintf(w, "Fehler:\t%s\n", *r.Error)
		}
	}); err != nil {
		return err
	}
	if r.Error != nil {
		return exitError(1)
	}
	return nil
}

func (a *app) renderCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "render", Short: "Gerenderte nginx-Konfiguration, Generationen, Rollback"}
	var fileName string
	show := &cobra.Command{
		Use: "show", Short: "Aktive Generation ausgeben", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			rc, _, err := do[apigen.RenderCurrent](c.GetRenderCurrent(ctxOf(cmd)))
			if err != nil {
				return err
			}
			if a.output != "table" {
				return a.print(rc, nil)
			}
			names := make([]string, 0, len(rc.Files))
			for n := range rc.Files {
				names = append(names, n)
			}
			sort.Strings(names)
			if fileName != "" {
				content, ok := rc.Files[fileName]
				if !ok {
					return fmt.Errorf("Datei %q nicht in Generation %d (vorhanden: %s)", fileName, rc.Generation, strings.Join(names, ", "))
				}
				_, err := io.WriteString(a.out, content)
				return err
			}
			fmt.Fprintf(a.out, "# Generation %d\n", rc.Generation)
			for _, n := range names {
				if n == "coraza/crs-setup.conf" || n == "nginx.test.conf" {
					fmt.Fprintf(a.out, "\n# ===== %s (%d Bytes, mit --file anzeigen) =====\n", n, len(rc.Files[n]))
					continue
				}
				fmt.Fprintf(a.out, "\n# ===== %s =====\n%s", n, rc.Files[n])
			}
			return nil
		},
	}
	show.Flags().StringVar(&fileName, "file", "", "Nur diese Datei ausgeben, z. B. http.d/host-app.example.com.conf")
	gens := &cobra.Command{
		Use: "generations", Aliases: []string{"gens"}, Short: "Historie der Generationen", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			l, _, err := do[apigen.GenerationList](c.ListGenerations(ctxOf(cmd)))
			if err != nil {
				return err
			}
			return a.print(l.Items, func(w *tabwriter.Writer) {
				fmt.Fprintln(w, "GEN\tSTATUS\tAKTIV\tROLLBACK MOEGLICH\tERSTELLT\tSHA256\tnginx -t")
				for _, g := range l.Items {
					fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", g.Id, g.Status, map[bool]string{true: "*"}[g.Current],
						yesNo(deref(g.Available)), ts(&g.CreatedAt), g.ContentSha256[:12], short(str(g.NginxTestOutput, ""), 60))
				}
			})
		},
	}
	rollback := &cobra.Command{
		Use: "rollback GEN", Short: "Auf eine fruehere Generation zurueckschalten (bis 'render apply')", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			gen, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("ungueltige Generation %q", args[0])
			}
			c, err := a.api()
			if err != nil {
				return err
			}
			r, _, err := do[apigen.ReconcileResult](c.RollbackRender(ctxOf(cmd), apigen.RollbackInput{Generation: gen}))
			if err != nil {
				return err
			}
			return a.printReconcile(*r)
		},
	}
	apply := &cobra.Command{
		Use: "apply", Aliases: []string{"reconcile"}, Short: "Aus der DB rendern, testen und nginx neu laden (hebt einen Rollback auf)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			r, _, err := do[apigen.ReconcileResult](c.ReconcileRender(ctxOf(cmd)))
			if err != nil {
				return err
			}
			return a.printReconcile(*r)
		},
	}
	cmd.AddCommand(show, gens, rollback, apply)
	return cmd
}

// ── Clients, Tokens, CA ─────────────────────────────────────────────────────

func writeSecretFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

func (a *app) emitIssued(i apigen.ApiClientIssued, out string) error {
	if a.output != "table" {
		return a.print(i, nil)
	}
	bundle := i.CertPem + deref(i.KeyPem)
	switch out {
	case "", "-", "/dev/stdout":
		// Mit CSR nur das Zertifikat, sonst Zertifikat + Schluessel (einmalig).
		_, err := io.WriteString(a.out, bundle)
		return err
	}
	if err := writeSecretFile(out, bundle); err != nil {
		return err
	}
	fmt.Fprintf(a.errOut, "Client %s (%s) ausgestellt, gueltig bis %s. Geschrieben nach %s.\n", i.Client.Name, i.Client.Role, ts(&i.Client.NotAfter), out)
	return nil
}

func readInput(a *app, path string) (*string, error) {
	if path == "" {
		return nil, nil
	}
	var raw []byte
	var err error
	if path == "-" {
		raw, err = io.ReadAll(a.in)
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	s := string(raw)
	return &s, nil
}

func (a *app) clientCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "client", Short: "mTLS-Clients der API verwalten (ersetzt remote-setup)"}
	var role, csr, out string
	var days int
	issue := &cobra.Command{
		Use:   "issue NAME --role viewer|operator|admin",
		Short: "Client-Zertifikat ausstellen",
		Long:  "Mit --csr bleibt der private Schluessel beim Client (empfohlen); ausgegeben wird nur das Zertifikat.\nOhne --csr erzeugt der Server das Schluesselpaar und gibt Zertifikat und Schluessel einmalig aus.",
		Example: "  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout alice.key -subj /CN=alice -out alice.csr\n" +
			"  docker exec -i nrp nrp client issue alice --role admin --csr - < alice.csr > alice.crt\n  docker exec nrp nrp ca show > nrp-ca.crt",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			csrPEM, err := readInput(a, csr)
			if err != nil {
				return err
			}
			c, err := a.api()
			if err != nil {
				return err
			}
			i, _, err := do[apigen.ApiClientIssued](c.CreateClient(ctxOf(cmd), apigen.ApiClientInput{Name: args[0], Role: apigen.Role(role), CsrPem: csrPEM, Days: &days}))
			if err != nil {
				return err
			}
			return a.emitIssued(*i, out)
		},
	}
	renew := &cobra.Command{
		Use: "renew NAME", Short: "Client-Zertifikat erneuern (das alte wird sofort ungueltig)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			csrPEM, err := readInput(a, csr)
			if err != nil {
				return err
			}
			c, err := a.api()
			if err != nil {
				return err
			}
			i, _, err := do[apigen.ApiClientIssued](c.RenewClient(ctxOf(cmd), args[0], apigen.ApiClientRenewInput{CsrPem: csrPEM, Days: &days}))
			if err != nil {
				return err
			}
			return a.emitIssued(*i, out)
		},
	}
	for _, c := range []*cobra.Command{issue, renew} {
		c.Flags().StringVar(&csr, "csr", "", "CSR-Datei (PEM), '-' fuer stdin")
		c.Flags().StringVar(&out, "out", "", "Ausgabedatei (Standard: stdout)")
		c.Flags().IntVar(&days, "days", 90, "Laufzeit in Tagen")
	}
	issue.Flags().StringVar(&role, "role", "", "viewer, operator oder admin")
	_ = issue.MarkFlagRequired("role")

	list := &cobra.Command{
		Use: "list", Aliases: []string{"ls"}, Short: "Clients auflisten", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			l, _, err := do[apigen.ApiClientList](c.ListClients(ctxOf(cmd)))
			if err != nil {
				return err
			}
			return a.print(l.Items, func(w *tabwriter.Writer) {
				fmt.Fprintln(w, "NAME\tROLLE\tGUELTIG BIS\tWIDERRUFEN\tZULETZT GENUTZT\tFINGERPRINT")
				for _, cl := range l.Items {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", cl.Name, cl.Role, ts(&cl.NotAfter), yesNo(cl.Disabled), ts(cl.LastUsedAt), cl.CertSha256[:16])
				}
			})
		},
	}
	var purge bool
	revoke := &cobra.Command{
		Use: "revoke NAME", Short: "Client widerrufen (wirkt sofort)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			if _, _, err := readResp(c.DeleteClient(ctxOf(cmd), args[0], &apigen.DeleteClientParams{Purge: &purge})); err != nil {
				return err
			}
			fmt.Fprintf(a.out, "Client %s widerrufen.\n", args[0])
			return nil
		},
	}
	revoke.Flags().BoolVar(&purge, "purge", false, "Eintrag vollstaendig entfernen (Name wird wieder frei)")
	cmd.AddCommand(issue, renew, list, revoke)
	return cmd
}

func (a *app) tokenCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "token", Short: "API-Tokens (optional, NRP_API_TOKENS_ENABLED=true)"}
	var role string
	var days int
	create := &cobra.Command{
		Use: "create NAME --role ROLE", Short: "Token erstellen (wird nur einmal angezeigt)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			t, _, err := do[apigen.TokenIssued](c.CreateToken(ctxOf(cmd), apigen.TokenInput{Name: args[0], Role: apigen.Role(role), ExpiresInDays: &days}))
			if err != nil {
				return err
			}
			return a.print(t, func(w *tabwriter.Writer) {
				fmt.Fprintf(w, "ID:\t%s\nRolle:\t%s\nGueltig bis:\t%s\nToken:\t%s\n", t.Token.Id, t.Token.Role, ts(&t.Token.ExpiresAt), t.Secret)
			})
		},
	}
	create.Flags().StringVar(&role, "role", "", "viewer, operator oder admin")
	create.Flags().IntVar(&days, "days", 90, "Laufzeit in Tagen (max. 365)")
	_ = create.MarkFlagRequired("role")
	list := &cobra.Command{
		Use: "list", Aliases: []string{"ls"}, Short: "Tokens auflisten", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			l, _, err := do[apigen.TokenList](c.ListTokens(ctxOf(cmd)))
			if err != nil {
				return err
			}
			return a.print(l.Items, func(w *tabwriter.Writer) {
				fmt.Fprintln(w, "ID\tNAME\tROLLE\tGUELTIG BIS\tWIDERRUFEN\tZULETZT GENUTZT")
				for _, t := range l.Items {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", t.Id, t.Name, t.Role, ts(&t.ExpiresAt), yesNo(t.Disabled), ts(t.LastUsedAt))
				}
			})
		},
	}
	revoke := &cobra.Command{
		Use: "revoke ID", Short: "Token widerrufen", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			if _, _, err := readResp(c.DeleteToken(ctxOf(cmd), args[0])); err != nil {
				return err
			}
			fmt.Fprintf(a.out, "Token %s widerrufen.\n", args[0])
			return nil
		},
	}
	cmd.AddCommand(create, list, revoke)
	return cmd
}

func (a *app) caCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "ca", Short: "Interne CA der API"}
	cmd.AddCommand(&cobra.Command{
		Use: "show", Short: "CA-Zertifikat ausgeben (fuer --ca bzw. curl --cacert)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			ca, _, err := do[apigen.Ca](c.GetCa(ctxOf(cmd)))
			if err != nil {
				return err
			}
			_, err = io.WriteString(a.out, ca.CaPem)
			return err
		},
	})
	return cmd
}

func (a *app) backupCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use: "backup", Short: "Konsistentes DB-Backup (VACUUM INTO) im Backup-Verzeichnis; nur lokal", Args: cobra.NoArgs,
		Long: "Schreibt nach /var/lib/nrp/backups (Host: ./data/backups). Zum Wiederherstellen gehoert zusaetzlich secrets/master.key.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			var in apigen.BackupInput
			if out != "" {
				in.Name = &out
			}
			b, _, err := do[apigen.BackupResult](c.CreateBackup(ctxOf(cmd), in))
			if err != nil {
				return err
			}
			return a.print(b, func(w *tabwriter.Writer) { fmt.Fprintf(w, "Backup geschrieben: %s\n", b.Path) })
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "Dateiname im Backup-Verzeichnis (Standard: nrp-<zeit>.db)")
	return cmd
}

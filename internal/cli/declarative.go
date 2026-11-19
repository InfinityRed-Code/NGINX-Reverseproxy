package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/apigen"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/audit"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/auth"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/domain"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/importer"
)

// document ist das Format von 'nrp export' / 'nrp apply -f' (GitOps).
type document struct {
	Settings *apigen.Settings   `json:"settings,omitempty"`
	Waf      *apigen.WafInput   `json:"waf,omitempty"`
	Hosts    []apigen.HostInput `json:"hosts"`
}

func (a *app) exportCmd() *cobra.Command {
	return &cobra.Command{
		Use: "export", Short: "Settings, WAF und Hosts deklarativ ausgeben (YAML; -o json fuer JSON)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := ctxOf(cmd)
			c, err := a.api()
			if err != nil {
				return err
			}
			st, _, err := do[apigen.Settings](c.GetSettings(ctx))
			if err != nil {
				return err
			}
			waf, _, err := do[apigen.Waf](c.GetWaf(ctx))
			if err != nil {
				return err
			}
			hosts, err := a.allHosts(ctx)
			if err != nil {
				return err
			}
			doc := document{Settings: st, Waf: &apigen.WafInput{Mode: &waf.Mode, Overrides: &waf.Overrides}, Hosts: []apigen.HostInput{}}
			for _, h := range hosts {
				doc.Hosts = append(doc.Hosts, apigen.HostInput{Fqdn: ptr(h.Fqdn), Upstream: h.Upstream, ExternalPort: ptr(h.ExternalPort),
					Websockets: ptr(h.Websockets), Waf: ptr(h.Waf), ClientMaxBodySize: h.ClientMaxBodySize, Hsts: h.Hsts, AcmeEmail: h.AcmeEmail})
			}
			if a.output == "json" {
				return a.print(doc, nil)
			}
			return a.printYAML(doc)
		},
	}
}

func (a *app) applyCmd() *cobra.Command {
	var file string
	var prune, dryRun bool
	cmd := &cobra.Command{
		Use: "apply -f hosts.yaml", Short: "Deklarative Datei anwenden: fehlende Hosts anlegen, abweichende ersetzen", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := ctxOf(cmd)
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
			// YAML -> generisch -> JSON, damit die API-Feldnamen und -Typen gelten.
			var generic any
			if err := yaml.Unmarshal(raw, &generic); err != nil {
				return fmt.Errorf("%s: %w", file, err)
			}
			js, err := json.Marshal(generic)
			if err != nil {
				return err
			}
			var doc document
			if err := json.Unmarshal(js, &doc); err != nil {
				return fmt.Errorf("%s: %w", file, err)
			}
			return a.applyDoc(ctx, doc, prune, dryRun)
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "YAML- oder JSON-Datei ('-' fuer stdin)")
	cmd.Flags().BoolVar(&prune, "prune", false, "Hosts entfernen, die nicht in der Datei stehen (Zertifikate bleiben erhalten)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Nur anzeigen, was geaendert wuerde")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

func sameHost(cur apigen.Host, want apigen.HostInput) bool {
	a, _ := json.Marshal(apigen.HostInput{Upstream: cur.Upstream, ExternalPort: ptr(cur.ExternalPort), Websockets: ptr(cur.Websockets),
		Waf: ptr(cur.Waf), ClientMaxBodySize: cur.ClientMaxBodySize, Hsts: cur.Hsts, AcmeEmail: cur.AcmeEmail})
	want.Fqdn = nil
	if want.ExternalPort == nil {
		want.ExternalPort = ptr(443)
	}
	if want.Websockets == nil {
		want.Websockets = ptr(false)
	}
	if want.Waf == nil {
		want.Waf = ptr(false)
	}
	b, _ := json.Marshal(want)
	return string(a) == string(b)
}

func (a *app) applyDoc(ctx context.Context, doc document, prune, dryRun bool) error {
	c, err := a.api()
	if err != nil {
		return err
	}
	note := func(format string, args ...any) {
		prefix := ""
		if dryRun {
			prefix = "(dry-run) "
		}
		fmt.Fprintf(a.out, prefix+format+"\n", args...)
	}
	if doc.Settings != nil {
		note("settings: anwenden")
		if !dryRun {
			if _, _, err := do[apigen.Settings](c.PatchSettingsWithBody(ctx, mergePatchType, jsonBody(doc.Settings))); err != nil {
				return fmt.Errorf("settings: %w", err)
			}
		}
	}
	if doc.Waf != nil && (doc.Waf.Mode != nil || doc.Waf.Overrides != nil) {
		note("waf: anwenden")
		if !dryRun {
			if _, _, err := do[apigen.Waf](c.PutWaf(ctx, *doc.Waf)); err != nil {
				return fmt.Errorf("waf: %w", err)
			}
		}
	}
	current, err := a.allHosts(ctx)
	if err != nil {
		return err
	}
	byName := map[string]apigen.Host{}
	for _, h := range current {
		byName[h.Fqdn] = h
	}
	wanted := map[string]bool{}
	for _, h := range doc.Hosts {
		if h.Fqdn == nil || *h.Fqdn == "" {
			return errors.New("hosts: Eintrag ohne fqdn")
		}
		fqdn := domain.NormalizeFQDN(*h.Fqdn)
		wanted[fqdn] = true
		cur, exists := byName[fqdn]
		switch {
		case !exists:
			note("host %s: anlegen", fqdn)
			if !dryRun {
				if _, _, err := do[apigen.HostCreated](c.CreateHost(ctx, nil, h)); err != nil {
					return fmt.Errorf("host %s: %w", fqdn, err)
				}
			}
		case sameHost(cur, h):
			note("host %s: unveraendert", fqdn)
		default:
			note("host %s: ersetzen", fqdn)
			if !dryRun {
				if _, _, err := do[apigen.Host](c.PutHost(ctx, fqdn, &apigen.PutHostParams{IfMatch: ptr(`"` + strconv.FormatInt(cur.Version, 10) + `"`)}, h)); err != nil {
					return fmt.Errorf("host %s: %w", fqdn, err)
				}
			}
		}
	}
	if prune {
		for _, cur := range current {
			if wanted[cur.Fqdn] {
				continue
			}
			note("host %s: entfernen", cur.Fqdn)
			if !dryRun {
				keep := true
				if _, _, err := readResp(c.DeleteHost(ctx, cur.Fqdn, &apigen.DeleteHostParams{KeepCert: &keep,
					IfMatch: ptr(`"` + strconv.FormatInt(cur.Version, 10) + `"`)})); err != nil {
					return fmt.Errorf("host %s: %w", cur.Fqdn, err)
				}
			}
		}
	}
	return nil
}

func (a *app) importCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "import", Short: "Daten aus aelteren Installationen uebernehmen"}
	var opt importer.Options
	var dryRun bool
	v2 := &cobra.Command{
		Use:   "v2",
		Short: "v2-Installation (Python-CLI) importieren; nur mit --offline",
		Long: "Liest sites.json, wg0.conf, Host-Configs und certbot-Zertifikate einer v2-Installation.\nDie Quellen werden nicht veraendert. Erst mit --dry-run pruefen.\n\n" +
			"  docker compose run --rm -v /etc/nginx/conf.d:/import/conf.d:ro -v /etc/letsencrypt:/import/letsencrypt:ro \\\n" +
			"    -v /var/lib/nrp:/import/nrp:ro -v /etc/wireguard:/import/wireguard:ro --entrypoint nrp nrp --offline import v2 \\\n" +
			"    --conf-dir /import/conf.d --letsencrypt /import/letsencrypt --sites /import/nrp/sites.json \\\n" +
			"    --wg-conf /import/wireguard/wg0.conf --dry-run",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if opt.ConfDir == "" && opt.SitesFile == "" && opt.WGConf == "" {
				return errors.New("mindestens --conf-dir, --sites oder --wg-conf angeben")
			}
			opt.OverlayCIDR = a.cfg.WGOverlayCIDR
			plan, err := importer.Analyze(opt)
			if err != nil {
				return err
			}
			if err := a.print(plan, func(w *tabwriter.Writer) {
				fmt.Fprintf(w, "WireGuard-Hub:\t%s\n", map[bool]string{true: "gefunden (Schluessel und Port werden uebernommen)", false: "nicht angegeben"}[plan.HubFound])
				fmt.Fprintf(w, "Sites:\t%d\n", len(plan.Sites))
				for _, s := range plan.Sites {
					fmt.Fprintf(w, "\t%s %s\n", s.Name, s.Subnet)
				}
				fmt.Fprintf(w, "Hosts:\t%d (davon %d mit Zertifikat)\n", len(plan.Hosts), len(plan.Certs))
				for _, h := range plan.Hosts {
					fmt.Fprintf(w, "\t%s -> %s://%s:%d  port=%d ws=%s waf=%s site=%s cert=%s\n", h.FQDN, h.Scheme, h.Address, h.Port,
						h.ExternalPort, yesNo(h.Websockets), yesNo(h.WAF), str(&h.Site, "-"), yesNo(h.HasCertificate))
				}
				if len(plan.Skipped) > 0 {
					fmt.Fprintf(w, "Nicht importierbar (manuell anlegen):\t%d\n", len(plan.Skipped))
					for k, v := range plan.Skipped {
						fmt.Fprintf(w, "\t%s: %s\n", k, v)
					}
				}
				for _, warn := range plan.Warnings {
					fmt.Fprintf(w, "Warnung:\t%s\n", warn)
				}
			}); err != nil {
				return err
			}
			if dryRun {
				fmt.Fprintln(a.errOut, "\n--dry-run: nichts geschrieben.")
				return nil
			}
			if !a.offline {
				return errors.New("der Import schreibt direkt in die Datenbank: mit --offline ausfuehren (Dienst gestoppt)")
			}
			core, err := a.openCore(ctxOf(cmd))
			if err != nil {
				return err
			}
			defer core.close()
			audit.Output = io.Discard
			actor := audit.Entry{RequestID: "import-v2", ActorType: auth.TypeOffline, ActorID: "uid=" + strconv.Itoa(os.Geteuid())}
			res, err := plan.Apply(ctxOf(cmd), core.store, core.box, opt, actor)
			if err != nil {
				return err
			}
			fmt.Fprintf(a.errOut, "\nImportiert: Hub %d, Sites %d, Hosts %d, Zertifikate %d, Zertifikatsjobs %d.\n", res.Hub, res.Sites, res.Hosts, res.Certs, res.Jobs)
			for _, e := range res.Existing {
				fmt.Fprintf(a.errOut, "  bereits vorhanden, unveraendert: %s\n", e)
			}
			fmt.Fprintln(a.errOut, "Naechster Schritt: docker compose up -d, dann nrp doctor und nrp render show.")
			return nil
		},
	}
	v2.Flags().StringVar(&opt.ConfDir, "conf-dir", "", "Verzeichnis mit den v2-Host-Configs (/etc/nginx/conf.d)")
	v2.Flags().StringVar(&opt.Letsencrypt, "letsencrypt", "", "certbot-Verzeichnis (/etc/letsencrypt)")
	v2.Flags().StringVar(&opt.SitesFile, "sites", "", "sites.json der v2-Installation (/var/lib/nrp/sites.json)")
	v2.Flags().StringVar(&opt.WGConf, "wg-conf", "", "wg0.conf des Hubs (/etc/wireguard/wg0.conf)")
	v2.Flags().BoolVar(&dryRun, "dry-run", false, "Nur analysieren, nichts schreiben")
	cmd.AddCommand(v2)
	return cmd
}

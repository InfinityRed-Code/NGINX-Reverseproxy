package cli

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/apigen"
)

func hostRow(w *tabwriter.Writer, h apigen.Host) {
	up := fmt.Sprintf("%s://%s:%d", h.Upstream.Scheme, h.Upstream.Address, h.Upstream.Port)
	if h.Upstream.Site != nil {
		up += " (" + *h.Upstream.Site + ")"
	}
	cert := "-"
	if h.Certificate != nil {
		cert = h.Certificate.NotAfter.Local().Format("2006-01-02")
	}
	fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\n", h.Fqdn, up, h.ExternalPort, yesNo(h.Websockets), yesNo(h.Waf), h.Status, cert)
}

func (a *app) printHosts(hosts []apigen.Host) error {
	return a.print(hosts, func(w *tabwriter.Writer) {
		if len(hosts) == 0 {
			fmt.Fprintln(w, "Keine Hosts konfiguriert.")
			return
		}
		fmt.Fprintln(w, "FQDN\tUPSTREAM\tPORT\tWS\tWAF\tSTATUS\tZERTIFIKAT BIS")
		for _, h := range hosts {
			hostRow(w, h)
		}
	})
}

func (a *app) printHost(h apigen.Host) error {
	return a.print(h, func(w *tabwriter.Writer) {
		fmt.Fprintf(w, "FQDN:\t%s\n", h.Fqdn)
		fmt.Fprintf(w, "Upstream:\t%s://%s:%d\n", h.Upstream.Scheme, h.Upstream.Address, h.Upstream.Port)
		fmt.Fprintf(w, "Site:\t%s\n", str(h.Upstream.Site, "-"))
		fmt.Fprintf(w, "Externer Port:\t%d\n", h.ExternalPort)
		fmt.Fprintf(w, "WebSockets:\t%s\n", yesNo(h.Websockets))
		fmt.Fprintf(w, "WAF:\t%s\n", yesNo(h.Waf))
		fmt.Fprintf(w, "Max. Body:\t%s\n", str(h.ClientMaxBodySize, "(Standard)"))
		if h.Hsts != nil {
			fmt.Fprintf(w, "HSTS:\tmax-age=%d subdomains=%s preload=%s\n", h.Hsts.MaxAge, yesNo(h.Hsts.IncludeSubdomains), yesNo(h.Hsts.Preload))
		} else {
			fmt.Fprintf(w, "HSTS:\t(Standard)\n")
		}
		fmt.Fprintf(w, "Status:\t%s\n", h.Status)
		if h.StatusDetail != nil {
			fmt.Fprintf(w, "Detail:\t%s\n", *h.StatusDetail)
		}
		if h.Certificate != nil {
			fmt.Fprintf(w, "Zertifikat:\tbis %s (%s)\n", ts(&h.Certificate.NotAfter), h.Certificate.Issuer)
		}
		fmt.Fprintf(w, "Version:\t%d\n", h.Version)
	})
}

func (a *app) allHosts(ctx context.Context) ([]apigen.Host, error) {
	c, err := a.api()
	if err != nil {
		return nil, err
	}
	var all []apigen.Host
	var cursor *string
	for {
		page, _, err := do[apigen.HostList](c.ListHosts(ctx, &apigen.ListHostsParams{Limit: ptr(500), Cursor: cursor}))
		if err != nil {
			return nil, err
		}
		all = append(all, page.Items...)
		if page.NextCursor == nil {
			return all, nil
		}
		cursor = page.NextCursor
	}
}

// waitJob wartet auf den Abschluss eines Jobs (--wait).
func (a *app) waitJob(ctx context.Context, id string, timeout time.Duration) (*apigen.Job, error) {
	c, err := a.api()
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	for {
		j, _, err := do[apigen.Job](c.GetJob(ctx, id))
		if err != nil {
			return nil, err
		}
		switch j.Status {
		case apigen.JobStatusSucceeded:
			return j, nil
		case apigen.JobStatusFailed:
			return j, fmt.Errorf("Job %s fehlgeschlagen: %s", id, str(j.Error, "unbekannter Fehler"))
		}
		if time.Now().After(deadline) {
			return j, fmt.Errorf("Job %s nach %s noch %s (letzter Fehler: %s)", id, timeout, j.Status, str(j.Error, "-"))
		}
		select {
		case <-ctx.Done():
			return j, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

type hostFlags struct {
	ip, protocol, email, site, bodySize string
	port, externalPort                  int
	websockets, noWebsockets            bool
	waf, noWaf                          bool
	overwrite, interactive, wait        bool
	hstsMaxAge                          int64
	hstsPreload, hstsNoSubdomains       bool
	waitTimeout                         time.Duration
}

func (f *hostFlags) register(cmd *cobra.Command, forSet bool) {
	fl := cmd.Flags()
	fl.StringVarP(&f.ip, "internal-ip", "i", "", "Interne Adresse des Servers (IP oder Hostname)")
	fl.IntVarP(&f.port, "internal-port", "p", 0, "Interner Port des Servers")
	fl.IntVarP(&f.externalPort, "external-port", "e", 443, "Externer Port")
	fl.StringVarP(&f.protocol, "protocol", "s", "http", "Schema zum Upstream: http oder https")
	fl.BoolVarP(&f.websockets, "websockets", "w", false, "WebSockets aktivieren")
	fl.BoolVar(&f.noWebsockets, "no-websockets", false, "WebSockets deaktivieren")
	fl.BoolVar(&f.waf, "waf", false, "Coraza WAF fuer diesen Host aktivieren")
	fl.BoolVar(&f.noWaf, "no-waf", false, "Coraza WAF fuer diesen Host deaktivieren")
	fl.StringVar(&f.email, "email", "", "Kontakt-E-Mail (optional)")
	fl.StringVar(&f.site, "site", "", "WireGuard-Site, ueber die der Upstream erreichbar ist")
	fl.StringVar(&f.bodySize, "client-max-body-size", "", "Maximale Request-Groesse, z. B. 100M (leer = Standard)")
	fl.Int64Var(&f.hstsMaxAge, "hsts-max-age", -1, "HSTS max-age in Sekunden (ohne Angabe: Standard aus den Settings)")
	fl.BoolVar(&f.hstsPreload, "hsts-preload", false, "HSTS preload setzen (kaum rueckgaengig zu machen)")
	fl.BoolVar(&f.hstsNoSubdomains, "hsts-no-subdomains", false, "HSTS ohne includeSubDomains")
	if !forSet {
		fl.BoolVar(&f.overwrite, "overwrite", false, "Bestehenden Host ersetzen (PUT)")
		fl.BoolVarP(&f.interactive, "full-interactive", "f", false, "Alle Optionen interaktiv abfragen")
		fl.BoolVar(&f.wait, "wait", false, "Auf das Zertifikat warten")
		fl.DurationVar(&f.waitTimeout, "wait-timeout", 5*time.Minute, "Maximale Wartezeit fuer --wait")
	}
}

func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "j", "ja", "y", "yes", "true", "1":
		return true
	}
	return false
}

func (a *app) hostAdd(cmd *cobra.Command, args []string, f *hostFlags) error {
	ctx := ctxOf(cmd)
	fqdn := ""
	if len(args) > 0 {
		fqdn = args[0]
	}
	var err error
	ask := func(dst *string, label, def string, always bool) {
		if err == nil && (*dst == "" || always) {
			if always && *dst != "" {
				def = *dst
			}
			*dst, err = a.prompt(label, def)
		}
	}
	// Fehlende Pflichtangaben werden nur mit TTY abgefragt.
	ask(&fqdn, "FQDN (z. B. app.example.com)", "", false)
	ask(&f.ip, "Interne Adresse", "", false)
	portStr := ""
	if f.port > 0 {
		portStr = strconv.Itoa(f.port)
	}
	ask(&portStr, "Interner Port", "", false)
	if err != nil {
		return err
	}
	if f.port, err = strconv.Atoi(portStr); err != nil {
		return fmt.Errorf("ungueltiger Port %q", portStr)
	}
	if f.interactive {
		ext := strconv.Itoa(f.externalPort)
		ws, waf := yesNo(f.websockets), yesNo(f.waf)
		ask(&f.protocol, "Schema zum Upstream (http/https)", "http", true)
		ask(&ext, "Externer Port", "443", true)
		ask(&ws, "WebSockets (ja/nein)", "nein", true)
		ask(&waf, "WAF (ja/nein)", "nein", true)
		ask(&f.site, "WireGuard-Site (leer = keine)", "", true)
		ask(&f.bodySize, "client_max_body_size (leer = Standard)", "", true)
		if err != nil {
			return err
		}
		if f.externalPort, err = strconv.Atoi(ext); err != nil {
			return fmt.Errorf("ungueltiger Port %q", ext)
		}
		f.websockets, f.waf = parseBool(ws), parseBool(waf)
	}

	in := apigen.HostInput{
		Fqdn:         &fqdn,
		Upstream:     apigen.Upstream{Scheme: apigen.UpstreamScheme(strings.ToLower(f.protocol)), Address: f.ip, Port: f.port},
		ExternalPort: &f.externalPort,
		Websockets:   ptr(f.websockets && !f.noWebsockets),
		Waf:          ptr(f.waf && !f.noWaf),
	}
	if f.site != "" {
		in.Upstream.Site = &f.site
	}
	if f.bodySize != "" {
		in.ClientMaxBodySize = &f.bodySize
	}
	if f.email != "" {
		in.AcmeEmail = &f.email
	}
	if f.hstsMaxAge >= 0 {
		in.Hsts = &apigen.Hsts{MaxAge: f.hstsMaxAge, IncludeSubdomains: !f.hstsNoSubdomains, Preload: f.hstsPreload}
	}

	c, err := a.api()
	if err != nil {
		return err
	}
	var host apigen.Host
	var jobID string
	created, hdr, err := do[apigen.HostCreated](c.CreateHost(ctx, nil, in))
	var ae *apiErr
	switch {
	case err == nil:
		host = created.Host
		if created.Job != nil {
			jobID = created.Job.Id
		}
	case errors.As(err, &ae) && ae.Status == 409 && f.overwrite:
		_, h, gerr := do[apigen.Host](c.GetHost(ctx, fqdn))
		if gerr != nil {
			return gerr
		}
		replaced, _, perr := do[apigen.Host](c.PutHost(ctx, fqdn, &apigen.PutHostParams{IfMatch: ptr(h.Get("ETag"))}, in))
		if perr != nil {
			return perr
		}
		host = *replaced
	default:
		return err
	}
	_ = hdr
	if jobID != "" && f.wait {
		fmt.Fprintf(a.errOut, "Warte auf Zertifikat fuer %s (Job %s)...\n", fqdn, jobID)
		if _, err := a.waitJob(ctx, jobID, f.waitTimeout); err != nil {
			return err
		}
		if h, _, err := do[apigen.Host](c.GetHost(ctx, fqdn)); err == nil {
			host = *h
		}
	}
	if err := a.printHost(host); err != nil {
		return err
	}
	if jobID != "" && !f.wait && strings.ToLower(a.output) == "table" {
		fmt.Fprintf(a.errOut, "\nZertifikat wird ausgestellt (Job %s). Verfolgen: nrp job wait %s\n", jobID, jobID)
	}
	return nil
}

func (a *app) hostSet(cmd *cobra.Command, fqdn string, f *hostFlags) error {
	ctx := ctxOf(cmd)
	fl := cmd.Flags()
	patch := map[string]any{}
	up := map[string]any{}
	if fl.Changed("internal-ip") {
		up["address"] = f.ip
	}
	if fl.Changed("internal-port") {
		up["port"] = f.port
	}
	if fl.Changed("protocol") {
		up["scheme"] = strings.ToLower(f.protocol)
	}
	if fl.Changed("site") {
		if f.site == "" {
			up["site"] = nil
		} else {
			up["site"] = f.site
		}
	}
	if len(up) > 0 {
		patch["upstream"] = up
	}
	if fl.Changed("external-port") {
		patch["external_port"] = f.externalPort
	}
	if fl.Changed("websockets") || fl.Changed("no-websockets") {
		patch["websockets"] = f.websockets && !f.noWebsockets
	}
	if fl.Changed("waf") || fl.Changed("no-waf") {
		patch["waf"] = f.waf && !f.noWaf
	}
	if fl.Changed("client-max-body-size") {
		if f.bodySize == "" {
			patch["client_max_body_size"] = nil
		} else {
			patch["client_max_body_size"] = f.bodySize
		}
	}
	if fl.Changed("email") {
		if f.email == "" {
			patch["acme_email"] = nil
		} else {
			patch["acme_email"] = f.email
		}
	}
	if fl.Changed("hsts-max-age") || fl.Changed("hsts-preload") || fl.Changed("hsts-no-subdomains") {
		if f.hstsMaxAge < 0 {
			patch["hsts"] = nil
		} else {
			patch["hsts"] = apigen.Hsts{MaxAge: f.hstsMaxAge, IncludeSubdomains: !f.hstsNoSubdomains, Preload: f.hstsPreload}
		}
	}
	if len(patch) == 0 {
		return errors.New("keine Aenderung angegeben")
	}
	c, err := a.api()
	if err != nil {
		return err
	}
	_, hdr, err := do[apigen.Host](c.GetHost(ctx, fqdn))
	if err != nil {
		return err
	}
	host, _, err := do[apigen.Host](c.PatchHostWithApplicationMergePatchPlusJSONBody(ctx, fqdn,
		&apigen.PatchHostParams{IfMatch: ptr(hdr.Get("ETag"))}, patch))
	if err != nil {
		return err
	}
	return a.printHost(*host)
}

func (a *app) hostListRun(cmd *cobra.Command, _ []string) error {
	hosts, err := a.allHosts(ctxOf(cmd))
	if err != nil {
		return err
	}
	return a.printHosts(hosts)
}

func (a *app) hostCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "host", Short: "Proxy-Hosts verwalten"}

	var add hostFlags
	addCmd := &cobra.Command{
		Use:   "add [FQDN]",
		Short: "Host anlegen und Zertifikat anfordern",
		Example: "  nrp host add app.example.com -i 192.168.1.10 -p 8080\n" +
			"  nrp host add app.example.com -i 10.240.0.18 -p 443 -s https --site home --waf --wait",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error { return a.hostAdd(cmd, args, &add) },
	}
	add.register(addCmd, false)

	var set hostFlags
	setCmd := &cobra.Command{
		Use:     "set FQDN",
		Short:   "Host aendern, ohne ihn neu anzulegen",
		Example: "  nrp host set app.example.com --waf --no-websockets",
		Args:    cobra.ExactArgs(1),
		RunE:    func(cmd *cobra.Command, args []string) error { return a.hostSet(cmd, args[0], &set) },
	}
	set.register(setCmd, true)

	var keepCert, revoke bool
	rmCmd := &cobra.Command{
		Use:     "remove FQDN",
		Aliases: []string{"rm", "delete"},
		Short:   "Host entfernen",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := ctxOf(cmd)
			c, err := a.api()
			if err != nil {
				return err
			}
			_, hdr, err := do[apigen.Host](c.GetHost(ctx, args[0]))
			if err != nil {
				return err
			}
			if _, _, err := readResp(c.DeleteHost(ctx, args[0], &apigen.DeleteHostParams{KeepCert: &keepCert, Revoke: &revoke,
				IfMatch: ptr(hdr.Get("ETag"))})); err != nil {
				return err
			}
			fmt.Fprintf(a.out, "Host %s entfernt.\n", args[0])
			return nil
		},
	}
	rmCmd.Flags().BoolVar(&keepCert, "keep-cert", false, "Zertifikat behalten")
	rmCmd.Flags().BoolVar(&revoke, "revoke", false, "Zertifikat bei der CA widerrufen")

	listCmd := &cobra.Command{Use: "list", Aliases: []string{"ls"}, Short: "Hosts auflisten", Args: cobra.NoArgs, RunE: a.hostListRun}
	showCmd := &cobra.Command{
		Use: "show FQDN", Short: "Details eines Hosts", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			h, _, err := do[apigen.Host](c.GetHost(ctxOf(cmd), args[0]))
			if err != nil {
				return err
			}
			return a.printHost(*h)
		},
	}
	cmd.AddCommand(addCmd, setCmd, rmCmd, listCmd, showCmd)
	return cmd
}

// listAliasCmd: 'nrp list' wie in v2.
func (a *app) listAliasCmd() *cobra.Command {
	return &cobra.Command{Use: "list", Short: "Hosts auflisten (Alias fuer 'host list')", Args: cobra.NoArgs, RunE: a.hostListRun}
}

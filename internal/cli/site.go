package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/apigen"
)

const mergePatchType = "application/merge-patch+json"

func jsonBody(v any) io.Reader {
	b, _ := json.Marshal(v)
	return bytes.NewReader(b)
}

func (a *app) printSite(s apigen.Site) error {
	return a.print(s, func(w *tabwriter.Writer) {
		fmt.Fprintf(w, "Name:\t%s\n", s.Name)
		fmt.Fprintf(w, "Subnetz:\t%s\n", s.Subnet)
		fmt.Fprintf(w, "Connector-IP:\t%s\n", s.ConnectorIp)
		fmt.Fprintf(w, "LAN-CIDR:\t%s\n", str(s.LanCidr, "-"))
		fmt.Fprintf(w, "Public Key:\t%s\n", str(s.PublicKey, "(ausstehend: nrp site install-script)"))
		fmt.Fprintf(w, "Preshared Key:\t%s\n", yesNo(s.HasPsk))
		fmt.Fprintf(w, "Aktiv:\t%s\n", yesNo(s.Enabled))
		fmt.Fprintf(w, "Status:\t%s\n", s.Status)
		fmt.Fprintf(w, "Zuletzt gesehen:\t%s\n", ts(s.LastSeenAt))
		if s.Live != nil {
			fmt.Fprintf(w, "Live:\tonline=%s, Handshake %s, Endpoint %s, rx %d B, tx %d B\n", yesNo(s.Live.Online),
				ts(s.Live.LastHandshake), str(s.Live.Endpoint, "-"), s.Live.RxBytes, s.Live.TxBytes)
		}
		fmt.Fprintf(w, "OS-Hinweis:\t%s\n", str(s.OsHint, "-"))
		fmt.Fprintf(w, "E-Mail:\t%s\n", str(s.Email, "-"))
		fmt.Fprintf(w, "Notizen:\t%s\n", str(s.Notes, "-"))
	})
}

func (a *app) siteCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "site", Short: "WireGuard-Sites (Hub-and-Spoke) verwalten",
		Long: "Sites verbinden entfernte Netze per WireGuard mit dem Hub. Upstreams im Site-Netz\nlassen sich mit 'nrp host add --site NAME' veroeffentlichen.\n\n" +
			"  nrp site create home --targets 8\n  nrp site install-script home > install-home.sh\n  nrp site set-pubkey home <KEY>\n  nrp site show home --live"}

	var in apigen.SiteInput
	var targets, prefix int
	var email, osHint, lan, notes string
	create := &cobra.Command{
		Use: "create NAME", Short: "Site anlegen (Subnetz-Vergabe)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			in = apigen.SiteInput{Name: args[0]}
			if cmd.Flags().Changed("targets") {
				in.Targets = &targets
			}
			if cmd.Flags().Changed("subnet-prefix") {
				in.SubnetPrefix = &prefix
			}
			if email != "" {
				in.Email = &email
			}
			if osHint != "" {
				in.OsHint = ptr(apigen.SiteInputOsHint(osHint))
			}
			if lan != "" {
				in.LanCidr = &lan
			}
			if notes != "" {
				in.Notes = &notes
			}
			c, err := a.api()
			if err != nil {
				return err
			}
			s, _, err := do[apigen.Site](c.CreateSite(ctxOf(cmd), nil, in))
			if err != nil {
				return err
			}
			if err := a.printSite(*s); err != nil {
				return err
			}
			if a.output == "table" {
				fmt.Fprintf(a.errOut, "\nNaechster Schritt:\n  nrp site install-script %s > install-%s.sh\n", s.Name, s.Name)
			}
			return nil
		},
	}
	create.Flags().IntVar(&targets, "targets", 0, "Geschaetzte Anzahl interner Dienste (bestimmt den Praefix)")
	create.Flags().IntVar(&prefix, "subnet-prefix", 0, "Expliziter Praefix, z. B. 28 (hat Vorrang vor --targets)")
	create.Flags().StringVar(&email, "email", "", "Kontakt-E-Mail (Metadaten)")
	create.Flags().StringVar(&osHint, "os", "", "OS-Hinweis fuer das Install-Script: debian, ubuntu, alpine")
	create.Flags().StringVar(&lan, "lan-cidr", "", "LAN hinter der Site, z. B. 192.168.1.0/24 (AllowedIPs und Route)")
	create.Flags().StringVar(&notes, "notes", "", "Notizen")

	list := &cobra.Command{
		Use: "list", Aliases: []string{"ls"}, Short: "Sites auflisten", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			l, _, err := do[apigen.SiteList](c.ListSites(ctxOf(cmd)))
			if err != nil {
				return err
			}
			return a.print(l.Items, func(w *tabwriter.Writer) {
				if len(l.Items) == 0 {
					fmt.Fprintln(w, "Keine Sites konfiguriert.")
					return
				}
				fmt.Fprintln(w, "NAME\tSUBNETZ\tCONNECTOR-IP\tLAN\tSTATUS\tZULETZT GESEHEN")
				for _, s := range l.Items {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", s.Name, s.Subnet, s.ConnectorIp, str(s.LanCidr, "-"), s.Status, ts(s.LastSeenAt))
				}
			})
		},
	}

	var live bool
	show := &cobra.Command{
		Use: "show NAME", Short: "Details einer Site", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			s, _, err := do[apigen.Site](c.GetSite(ctxOf(cmd), args[0], &apigen.GetSiteParams{Live: &live}))
			if err != nil {
				return err
			}
			return a.printSite(*s)
		},
	}
	show.Flags().BoolVar(&live, "live", false, "Live-Zustand aus dem WireGuard-Handshake")

	var keepConfig, yes bool
	del := &cobra.Command{
		Use: "delete NAME", Aliases: []string{"rm", "remove"}, Short: "Site loeschen", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := ctxOf(cmd)
			c, err := a.api()
			if err != nil {
				return err
			}
			_, hdr, err := do[apigen.Site](c.GetSite(ctx, args[0], nil))
			if err != nil {
				return err
			}
			if err := a.confirm(fmt.Sprintf("Site %s wirklich loeschen?", args[0]), yes); err != nil {
				return err
			}
			if _, _, err := readResp(c.DeleteSite(ctx, args[0], &apigen.DeleteSiteParams{KeepConfig: &keepConfig,
				IfMatch: ptr(hdr.Get("ETag"))})); err != nil {
				return err
			}
			if keepConfig {
				fmt.Fprintf(a.out, "Site %s deaktiviert (Peer entfernt, Metadaten behalten).\n", args[0])
			} else {
				fmt.Fprintf(a.out, "Site %s geloescht.\n", args[0])
			}
			return nil
		},
	}
	del.Flags().BoolVar(&keepConfig, "keep-config", false, "Peer entfernen, Metadaten behalten")
	del.Flags().BoolVarP(&yes, "yes", "y", false, "Ohne Rueckfrage loeschen")

	var scriptOS string
	script := &cobra.Command{
		Use: "install-script NAME", Short: "Install-Script fuer den Site-Host ausgeben (enthaelt den PSK)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			var p apigen.GetSiteInstallScriptParams
			if scriptOS != "" {
				p.Os = ptr(apigen.GetSiteInstallScriptParamsOs(scriptOS))
			}
			body, _, err := readResp(c.GetSiteInstallScript(ctxOf(cmd), args[0], &p))
			if err != nil {
				return err
			}
			_, err = a.out.Write(body)
			return err
		},
	}
	script.Flags().StringVar(&scriptOS, "os", "", "debian, ubuntu, alpine oder auto")

	pubkey := &cobra.Command{
		Use: "set-pubkey NAME KEY", Short: "Public Key der Site hinterlegen", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			s, _, err := do[apigen.Site](c.SetSitePublicKey(ctxOf(cmd), args[0], apigen.PublicKeyInput{PublicKey: args[1]}))
			if err != nil {
				return err
			}
			return a.printSite(*s)
		},
	}

	rotate := &cobra.Command{
		Use: "rotate-psk NAME", Short: "Neuen Preshared Key erzeugen (danach Install-Script neu ausrollen)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := a.api()
			if err != nil {
				return err
			}
			s, _, err := do[apigen.Site](c.RotateSitePsk(ctxOf(cmd), args[0]))
			if err != nil {
				return err
			}
			fmt.Fprintf(a.errOut, "PSK der Site %s ersetzt. Der Tunnel steht erst wieder, wenn die Site den neuen PSK kennt:\n  nrp site install-script %s\n\n", s.Name, s.Name)
			return a.printSite(*s)
		},
	}

	var setLan, setNotes, setEmail, setOS string
	var enable, disable bool
	set := &cobra.Command{
		Use: "set NAME", Short: "Metadaten einer Site aendern (leerer Wert loescht)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := ctxOf(cmd)
			patch := map[string]any{}
			for flagName, v := range map[string]struct {
				key string
				val string
			}{"lan-cidr": {"lan_cidr", setLan}, "notes": {"notes", setNotes}, "email": {"email", setEmail}, "os": {"os_hint", setOS}} {
				if cmd.Flags().Changed(flagName) {
					if v.val == "" {
						patch[v.key] = nil
					} else {
						patch[v.key] = v.val
					}
				}
			}
			if enable || disable {
				patch["enabled"] = enable && !disable
			}
			if len(patch) == 0 {
				return errors.New("keine Aenderung angegeben")
			}
			c, err := a.api()
			if err != nil {
				return err
			}
			_, hdr, err := do[apigen.Site](c.GetSite(ctx, args[0], nil))
			if err != nil {
				return err
			}
			s, _, err := do[apigen.Site](c.PatchSiteWithBody(ctx, args[0], &apigen.PatchSiteParams{IfMatch: ptr(hdr.Get("ETag"))},
				mergePatchType, jsonBody(patch)))
			if err != nil {
				return err
			}
			return a.printSite(*s)
		},
	}
	set.Flags().StringVar(&setLan, "lan-cidr", "", "LAN hinter der Site")
	set.Flags().StringVar(&setNotes, "notes", "", "Notizen")
	set.Flags().StringVar(&setEmail, "email", "", "Kontakt-E-Mail")
	set.Flags().StringVar(&setOS, "os", "", "OS-Hinweis")
	set.Flags().BoolVar(&enable, "enable", false, "Deaktivierte Site wieder aktivieren")
	set.Flags().BoolVar(&disable, "disable", false, "Site deaktivieren (Peer entfernen)")

	cmd.AddCommand(create, list, show, del, script, pubkey, rotate, set)
	return cmd
}

// Package importer uebernimmt eine v2-Installation (Python-CLI auf dem Host):
// sites.json, wg0.conf, Host-Configs aus conf.d und certbot-Zertifikate.
package importer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/acme"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/audit"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/domain"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/jobs"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/secrets"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store/dbq"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/wireguard"
)

type Options struct {
	ConfDir     string
	Letsencrypt string
	SitesFile   string
	WGConf      string
	OverlayCIDR string
}

type Site struct {
	Name        string  `json:"name"`
	Subnet      string  `json:"subnet"`
	ConnectorIP string  `json:"connector_ip"`
	PublicKey   *string `json:"public_key"`
	PSK         string  `json:"preshared_key"`
	Status      string  `json:"status"`
	Email       *string `json:"email"`
	OSHint      *string `json:"os_hint"`
	LANCIDR     *string `json:"lan_cidr"`
	CreatedAt   string  `json:"created_at"`
	LastSeenAt  *string `json:"last_seen_at"`
	Notes       *string `json:"notes"`
}

type Hub struct {
	PrivateKey string
	ListenPort int
	Address    string
}

type Host struct {
	FQDN              string       `json:"fqdn"`
	Scheme            string       `json:"scheme"`
	Address           string       `json:"address"`
	Port              int          `json:"port"`
	ExternalPort      int          `json:"external_port"`
	Websockets        bool         `json:"websockets"`
	WAF               bool         `json:"waf"`
	ClientMaxBodySize string       `json:"client_max_body_size,omitempty"`
	HSTS              *domain.HSTS `json:"hsts,omitempty"`
	Site              string       `json:"site,omitempty"`
	File              string       `json:"file"`
	HasCertificate    bool         `json:"has_certificate"`
}

type cert struct {
	chain, key string
	notAfter   time.Time
}

// Plan ist das Ergebnis der Analyse; Apply schreibt es in die Datenbank.
type Plan struct {
	Hub      *Hub              `json:"-"`
	HubFound bool              `json:"hub_found"`
	Sites    []Site            `json:"sites"`
	Hosts    []Host            `json:"hosts"`
	Certs    []string          `json:"certificates"`
	Skipped  map[string]string `json:"skipped"`
	Warnings []string          `json:"warnings"`

	certs map[string]cert
}

var (
	commentRe    = regexp.MustCompile(`(?m)#.*$`)
	serverNameRe = regexp.MustCompile(`(?m)^\s*server_name\s+([^;]+);`)
	listenSSLRe  = regexp.MustCompile(`(?m)^\s*listen\s+(?:\[::\]:)?([0-9]+)\s+[^;]*\bssl\b[^;]*;`)
	proxyPassRe  = regexp.MustCompile(`(?m)^\s*proxy_pass\s+(https?)://(\[[0-9a-fA-F:]+\]|[^:/;\s]+):([0-9]+)/?\s*;`)
	corazaOnRe   = regexp.MustCompile(`(?m)^\s*coraza\s+on\s*;`)
	upgradeRe    = regexp.MustCompile(`(?m)^\s*proxy_set_header\s+Upgrade\s+`)
	bodySizeRe   = regexp.MustCompile(`(?m)^\s*client_max_body_size\s+([^;\s]+)\s*;`)
	hstsRe       = regexp.MustCompile(`(?m)^\s*add_header\s+Strict-Transport-Security\s+"([^"]*)"`)
	maxAgeRe     = regexp.MustCompile(`max-age=([0-9]+)`)
	wgKeyRe      = regexp.MustCompile(`(?m)^\s*(PrivateKey|ListenPort|Address)\s*=\s*(\S+)`)
)

// ParseHostConfig liest eine von v2 erzeugte Host-Konfiguration. Ist sie nicht
// eindeutig (mehrere Namen oder Upstreams), wird ein Fehler geliefert.
func ParseHostConfig(content string) (Host, error) {
	var h Host
	content = commentRe.ReplaceAllString(content, "")
	names := map[string]bool{}
	for _, m := range serverNameRe.FindAllStringSubmatch(content, -1) {
		for _, n := range strings.Fields(m[1]) {
			if n != "_" {
				names[domain.NormalizeFQDN(n)] = true
			}
		}
	}
	if len(names) != 1 {
		return h, fmt.Errorf("%d verschiedene server_name gefunden, erwartet genau einer", len(names))
	}
	for n := range names {
		h.FQDN = n
	}
	if err := domain.ValidateFQDN(h.FQDN); err != nil {
		return h, err
	}
	upstreams := map[string][]string{}
	for _, m := range proxyPassRe.FindAllStringSubmatch(content, -1) {
		upstreams[m[0]] = m
	}
	if len(upstreams) != 1 {
		return h, fmt.Errorf("%d verschiedene proxy_pass gefunden, erwartet genau einer", len(upstreams))
	}
	for _, m := range upstreams {
		h.Scheme, h.Address = m[1], strings.Trim(m[2], "[]")
		h.Port, _ = strconv.Atoi(m[3])
	}
	if err := domain.ValidateUpstreamAddress(h.Address); err != nil {
		return h, err
	}
	ports := map[string]bool{}
	for _, m := range listenSSLRe.FindAllStringSubmatch(content, -1) {
		ports[m[1]] = true
	}
	if len(ports) != 1 {
		return h, fmt.Errorf("%d verschiedene TLS-Ports gefunden, erwartet genau einer", len(ports))
	}
	for p := range ports {
		h.ExternalPort, _ = strconv.Atoi(p)
	}
	if err := domain.ValidateExternalPort(h.ExternalPort); err != nil {
		return h, err
	}
	h.WAF = corazaOnRe.MatchString(content)
	h.Websockets = upgradeRe.MatchString(content)
	if m := bodySizeRe.FindStringSubmatch(content); m != nil && domain.ValidateBodySize(m[1]) == nil {
		h.ClientMaxBodySize = m[1]
	}
	if m := hstsRe.FindStringSubmatch(content); m != nil {
		hs := domain.HSTS{IncludeSubdomains: strings.Contains(m[1], "includeSubDomains"), Preload: strings.Contains(m[1], "preload")}
		if ma := maxAgeRe.FindStringSubmatch(m[1]); ma != nil {
			hs.MaxAge, _ = strconv.ParseInt(ma[1], 10, 64)
		}
		h.HSTS = &hs
	}
	return h, nil
}

// ParseWGConf liest den [Interface]-Abschnitt von wg0.conf.
func ParseWGConf(content string) (Hub, error) {
	var hub Hub
	iface, _, _ := strings.Cut(content, "[Peer]")
	for _, m := range wgKeyRe.FindAllStringSubmatch(commentRe.ReplaceAllString(iface, ""), -1) {
		switch m[1] {
		case "PrivateKey":
			hub.PrivateKey = m[2]
		case "ListenPort":
			hub.ListenPort, _ = strconv.Atoi(m[2])
		case "Address":
			hub.Address = strings.TrimSuffix(m[2], ",")
		}
	}
	if err := wireguard.ValidateKey(hub.PrivateKey); err != nil {
		return hub, fmt.Errorf("wg0.conf: %w", err)
	}
	if hub.ListenPort == 0 || hub.Address == "" {
		return hub, errors.New("wg0.conf: ListenPort oder Address fehlt")
	}
	return hub, nil
}

// Analyze liest alle Quellen, ohne etwas zu schreiben.
func Analyze(opt Options) (*Plan, error) {
	p := &Plan{Skipped: map[string]string{}, certs: map[string]cert{}}
	if opt.SitesFile != "" {
		raw, err := os.ReadFile(opt.SitesFile)
		if err != nil {
			return nil, err
		}
		var db struct {
			Sites []Site `json:"sites"`
		}
		if err := json.Unmarshal(raw, &db); err != nil {
			return nil, fmt.Errorf("%s: %w", opt.SitesFile, err)
		}
		for _, s := range db.Sites {
			if err := domain.ValidateSiteName(s.Name); err != nil {
				p.Skipped["site:"+s.Name] = err.Error()
				continue
			}
			if _, err := netip.ParsePrefix(s.Subnet); err != nil {
				p.Skipped["site:"+s.Name] = "ungueltiges Subnetz " + s.Subnet
				continue
			}
			p.Sites = append(p.Sites, s)
		}
	}
	if opt.WGConf != "" {
		raw, err := os.ReadFile(opt.WGConf)
		if err != nil {
			return nil, err
		}
		hub, err := ParseWGConf(string(raw))
		if err != nil {
			return nil, err
		}
		p.Hub, p.HubFound = &hub, true
	} else if len(p.Sites) > 0 {
		p.Warnings = append(p.Warnings, "Sites ohne --wg-conf: der Hub erhaelt einen neuen Schluessel, alle Sites muessen neu eingerichtet werden")
	}
	if opt.ConfDir != "" {
		files, err := filepath.Glob(filepath.Join(opt.ConfDir, "*.conf"))
		if err != nil {
			return nil, err
		}
		sort.Strings(files)
		seen := map[string]string{}
		for _, f := range files {
			base := filepath.Base(f)
			if base == "catch-all.conf" {
				continue
			}
			raw, err := os.ReadFile(f)
			if err != nil {
				p.Skipped[base] = err.Error()
				continue
			}
			h, err := ParseHostConfig(string(raw))
			if err != nil {
				p.Skipped[base] = err.Error()
				continue
			}
			if other, dup := seen[h.FQDN]; dup {
				p.Skipped[base] = "FQDN " + h.FQDN + " bereits in " + other
				continue
			}
			seen[h.FQDN], h.File = base, base
			for _, s := range p.Sites {
				nets := []string{s.Subnet}
				if s.LANCIDR != nil {
					nets = append(nets, *s.LANCIDR)
				}
				if domain.AddressInSubnets(h.Address, nets...) {
					h.Site = s.Name
					break
				}
			}
			if opt.Letsencrypt != "" {
				live := filepath.Join(opt.Letsencrypt, "live", h.FQDN)
				chain, cerr := os.ReadFile(filepath.Join(live, "fullchain.pem"))
				key, kerr := os.ReadFile(filepath.Join(live, "privkey.pem"))
				switch leaf, perr := acme.ParseLeaf(string(chain)); {
				case cerr != nil || kerr != nil:
					p.Warnings = append(p.Warnings, h.FQDN+": kein certbot-Zertifikat gefunden, wird neu ausgestellt")
				case perr != nil:
					p.Warnings = append(p.Warnings, h.FQDN+": Zertifikat nicht lesbar: "+perr.Error())
				case leaf.NotAfter.Before(time.Now()):
					p.Warnings = append(p.Warnings, h.FQDN+": Zertifikat ist abgelaufen, wird neu ausgestellt")
				case leaf.VerifyHostname(h.FQDN) != nil:
					p.Warnings = append(p.Warnings, h.FQDN+": Zertifikat gilt nicht fuer diesen Namen, wird neu ausgestellt")
				default:
					p.certs[h.FQDN] = cert{string(chain), string(key), leaf.NotAfter}
					p.Certs = append(p.Certs, h.FQDN)
					h.HasCertificate = true
				}
			}
			p.Hosts = append(p.Hosts, h)
		}
	}
	return p, nil
}

// Result zaehlt, was Apply geschrieben hat.
type Result struct {
	Hub, Sites, Hosts, Certs, Jobs int
	Existing                       []string
}

// Apply schreibt den Plan in einer Transaktion. Vorhandene Eintraege bleiben unveraendert.
func (p *Plan) Apply(ctx context.Context, st *store.Store, box *secrets.Box, opt Options, actor audit.Entry) (Result, error) {
	var res Result
	var rows []dbq.AuditLog
	err := st.Write(ctx, func(q *dbq.Queries) error {
		res, rows = Result{}, nil
		log := func(action, typ, id string, after any) error {
			e := actor
			e.Action, e.ResourceType, e.ResourceID, e.After, e.Result = action, typ, id, after, audit.Success
			row, err := audit.Append(ctx, q, e)
			rows = append(rows, row)
			return err
		}
		now := store.Now()
		if p.Hub != nil {
			if _, err := q.GetWgHub(ctx); err == nil {
				res.Existing = append(res.Existing, "wireguard-hub")
			} else {
				pub, err := wireguard.PublicFromPrivate(p.Hub.PrivateKey)
				if err != nil {
					return err
				}
				enc, err := box.Seal([]byte(p.Hub.PrivateKey))
				if err != nil {
					return err
				}
				overlay := opt.OverlayCIDR
				if pfx, err := netip.ParsePrefix(p.Hub.Address); err == nil {
					overlay = pfx.Masked().String()
				}
				if err := q.UpsertWgHub(ctx, dbq.UpsertWgHubParams{PrivateKeyEnc: enc, PublicKey: pub,
					ListenPort: int64(p.Hub.ListenPort), Address: p.Hub.Address, OverlayCidr: overlay}); err != nil {
					return err
				}
				res.Hub = 1
				if err := log("import.wireguard_hub", "wireguard", wireguard.Interface, map[string]any{"public_key": pub,
					"listen_port": p.Hub.ListenPort, "address": p.Hub.Address}); err != nil {
					return err
				}
			}
		}
		for _, s := range p.Sites {
			if _, err := q.GetSite(ctx, s.Name); err == nil {
				res.Existing = append(res.Existing, "site:"+s.Name)
				continue
			}
			var psk []byte
			if s.PSK != "" {
				var err error
				if psk, err = box.Seal([]byte(s.PSK)); err != nil {
					return err
				}
			}
			created := s.CreatedAt
			if store.ParseTime(created).IsZero() {
				created = now
			} else {
				created = store.FormatTime(store.ParseTime(created))
			}
			status := "pending"
			if s.PublicKey != nil && *s.PublicKey != "" {
				status = "offline"
			}
			if err := q.InsertSite(ctx, dbq.InsertSiteParams{Name: s.Name, Subnet: s.Subnet, ConnectorIp: s.ConnectorIP,
				LanCidr: s.LANCIDR, PublicKey: s.PublicKey, PskEnc: psk, OsHint: s.OSHint, Email: s.Email, Enabled: 1,
				Status: status, Notes: s.Notes, CreatedAt: created, UpdatedAt: now}); err != nil {
				return fmt.Errorf("Site %s: %w", s.Name, err)
			}
			res.Sites++
			if err := log("import.site", "site", s.Name, map[string]any{"subnet": s.Subnet, "connector_ip": s.ConnectorIP}); err != nil {
				return err
			}
		}
		for _, h := range p.Hosts {
			if _, err := q.GetHost(ctx, h.FQDN); err == nil {
				res.Existing = append(res.Existing, "host:"+h.FQDN)
				continue
			}
			status := domain.HostPending
			if c, ok := p.certs[h.FQDN]; ok {
				if _, err := acme.StoreCertificate(ctx, q, box, h.FQDN, c.chain, c.key, "imported", nil); err != nil {
					return fmt.Errorf("Zertifikat %s: %w", h.FQDN, err)
				}
				res.Certs++
				status = domain.HostActive
			}
			row := dbq.InsertHostParams{Fqdn: h.FQDN, UpstreamScheme: h.Scheme, UpstreamAddress: h.Address,
				UpstreamPort: int64(h.Port), ExternalPort: int64(h.ExternalPort), Status: status, CreatedAt: now, UpdatedAt: now}
			if h.Websockets {
				row.Websockets = 1
			}
			if h.WAF {
				row.Waf = 1
			}
			if h.Site != "" {
				row.SiteName = &h.Site
			}
			if h.ClientMaxBodySize != "" {
				row.ClientMaxBodySize = &h.ClientMaxBodySize
			}
			if h.HSTS != nil {
				b, _ := json.Marshal(h.HSTS)
				js := string(b)
				row.HstsJson = &js
			}
			if err := q.InsertHost(ctx, row); err != nil {
				return fmt.Errorf("Host %s: %w", h.FQDN, err)
			}
			res.Hosts++
			if status == domain.HostPending {
				if _, err := jobs.Enqueue(ctx, q, jobs.CertIssue, h.FQDN, actor.ActorType+":"+actor.ActorID); err != nil {
					return err
				}
				res.Jobs++
			}
			if err := log("import.host", "host", h.FQDN, h); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil {
		audit.Emit(rows...)
	}
	return res, err
}

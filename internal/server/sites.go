package server

import (
	"net/http"
	"net/netip"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/apigen"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/domain"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store/dbq"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/wireguard"
)

func siteAPI(s dbq.Site) apigen.Site {
	return apigen.Site{Name: s.Name, Subnet: s.Subnet, ConnectorIp: s.ConnectorIp, LanCidr: s.LanCidr,
		PublicKey: s.PublicKey, HasPsk: len(s.PskEnc) > 0, OsHint: s.OsHint, Email: s.Email, Enabled: s.Enabled != 0,
		Status: apigen.SiteStatus(s.Status), LastSeenAt: timePtr(s.LastSeenAt), Notes: s.Notes, Version: s.Version,
		CreatedAt: store.ParseTime(s.CreatedAt), UpdatedAt: store.ParseTime(s.UpdatedAt)}
}

// wgEnabled: ohne WireGuard liefern alle Site-Endpunkte 409.
func (s *Server) wgEnabled(w http.ResponseWriter, r *http.Request) bool {
	if s.d.Cfg.WireGuardEnabled {
		return true
	}
	s.writeError(w, r, errf(http.StatusConflict, "WireGuard ist deaktiviert (NRP_WIREGUARD_ENABLED=false)"))
	return false
}

func (s *Server) getSiteTx(t *tx, name string) (dbq.Site, error) {
	site, err := t.q.GetSite(t.ctx, name)
	if isNoRows(err) {
		return site, notFound("Site", name)
	}
	return site, err
}

func (s *Server) saveSite(t *tx, old, site dbq.Site, action string, after any) (apigen.Site, error) {
	site.UpdatedAt = store.Now()
	n, err := t.q.UpdateSite(t.ctx, dbq.UpdateSiteParams{LanCidr: site.LanCidr, PublicKey: site.PublicKey, PskEnc: site.PskEnc,
		OsHint: site.OsHint, Email: site.Email, Enabled: site.Enabled, Status: site.Status, Notes: site.Notes,
		UpdatedAt: site.UpdatedAt, Name: site.Name, Version: old.Version})
	if err != nil {
		return apigen.Site{}, err
	}
	if n == 0 {
		return apigen.Site{}, errf(http.StatusPreconditionFailed, "Site wurde zwischenzeitlich geaendert")
	}
	site.Version = old.Version + 1
	out := siteAPI(site)
	if after == nil {
		after = out
	}
	return out, t.audit(action, "site", site.Name, siteAPI(old), after)
}

func validLAN(cidr *string) (*string, error) {
	cidr = nilIfEmpty(cidr)
	if cidr == nil {
		return nil, nil
	}
	p, err := domain.ValidateCIDR(*cidr)
	if err != nil {
		return nil, badRequest(err)
	}
	s := p.String()
	return &s, nil
}

func (s *Server) ListSites(w http.ResponseWriter, r *http.Request) {
	if !s.wgEnabled(w, r) {
		return
	}
	sites, err := s.d.Store.Read().ListSites(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := apigen.SiteList{Items: []apigen.Site{}}
	for _, site := range sites {
		out.Items = append(out.Items, siteAPI(site))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) CreateSite(w http.ResponseWriter, r *http.Request, _ apigen.CreateSiteParams) {
	if !s.wgEnabled(w, r) {
		return
	}
	var in apigen.SiteInput
	if err := decode(r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	var out apigen.Site
	ok := s.mutate(w, r, "site.create", "site", in.Name, func(t *tx) error {
		if err := domain.ValidateSiteName(in.Name); err != nil {
			return badRequest(err)
		}
		if _, err := t.q.GetSite(t.ctx, in.Name); err == nil {
			return errf(http.StatusConflict, "Site %s existiert bereits", in.Name)
		} else if !isNoRows(err) {
			return err
		}
		hub, err := t.q.GetWgHub(t.ctx)
		if isNoRows(err) {
			return errf(http.StatusConflict, "WireGuard-Hub ist noch nicht initialisiert (Dienst einmal starten)")
		} else if err != nil {
			return err
		}
		overlay, err := netip.ParsePrefix(hub.OverlayCidr)
		if err != nil {
			return err
		}
		prefix := 0
		switch {
		case in.SubnetPrefix != nil:
			prefix = *in.SubnetPrefix
		case in.Targets != nil:
			prefix = wireguard.PrefixForTargets(*in.Targets)
		default:
			prefix = wireguard.PrefixForTargets(6)
		}
		existing, err := t.q.ListSites(t.ctx)
		if err != nil {
			return err
		}
		var allocated []netip.Prefix
		for _, e := range existing {
			if p, err := netip.ParsePrefix(e.Subnet); err == nil {
				allocated = append(allocated, p)
			}
		}
		subnet, err := wireguard.AllocateSubnet(overlay, prefix, allocated)
		if err != nil {
			return errf(http.StatusConflict, "%v", err)
		}
		lan, err := validLAN(in.LanCidr)
		if err != nil {
			return err
		}
		email := nilIfEmpty(in.Email)
		if email != nil {
			if err := domain.ValidateEmail(*email); err != nil {
				return badRequest(err)
			}
		}
		psk, err := wireguard.GeneratePSK()
		if err != nil {
			return err
		}
		pskEnc, err := s.d.Box.Seal([]byte(psk))
		if err != nil {
			return err
		}
		now := store.Now()
		site := dbq.Site{Name: in.Name, Subnet: subnet.String(), ConnectorIp: wireguard.ConnectorIP(subnet).String(),
			LanCidr: lan, PskEnc: pskEnc, Email: email, Enabled: 1, Status: "pending", Notes: nilIfEmpty(in.Notes),
			Version: 1, CreatedAt: now, UpdatedAt: now}
		if in.OsHint != nil {
			v := string(*in.OsHint)
			site.OsHint = &v
		}
		if err := t.q.InsertSite(t.ctx, dbq.InsertSiteParams{Name: site.Name, Subnet: site.Subnet, ConnectorIp: site.ConnectorIp,
			LanCidr: site.LanCidr, PskEnc: site.PskEnc, OsHint: site.OsHint, Email: site.Email, Enabled: 1,
			Status: site.Status, Notes: site.Notes, CreatedAt: now, UpdatedAt: now}); err != nil {
			return err
		}
		out = siteAPI(site)
		return t.audit("site.create", "site", site.Name, nil, out)
	})
	if ok {
		w.Header().Set("ETag", etag(out.Version))
		w.Header().Set("Location", BasePath+"/sites/"+out.Name)
		writeJSON(w, http.StatusCreated, out)
	}
}

func (s *Server) GetSite(w http.ResponseWriter, r *http.Request, name apigen.Name, params apigen.GetSiteParams) {
	if !s.wgEnabled(w, r) {
		return
	}
	site, err := s.d.Store.Read().GetSite(r.Context(), name)
	if isNoRows(err) {
		s.writeError(w, r, notFound("Site", name))
		return
	} else if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := siteAPI(site)
	if flag(params.Live) && s.d.WG != nil && site.PublicKey != nil {
		stats, err := s.d.WG.Stats()
		if err != nil {
			s.writeError(w, r, errf(http.StatusServiceUnavailable, "WireGuard-Status nicht lesbar: %v", err))
			return
		}
		ps := stats[*site.PublicKey]
		live := apigen.SiteLive{Online: ps.Online(), RxBytes: ps.Rx, TxBytes: ps.Tx}
		if !ps.LastHandshake.IsZero() {
			live.LastHandshake = &ps.LastHandshake
		}
		if ps.Endpoint != "" {
			live.Endpoint = &ps.Endpoint
		}
		out.Live = &live
	}
	w.Header().Set("ETag", etag(site.Version))
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) PatchSite(w http.ResponseWriter, r *http.Request, name apigen.Name, params apigen.PatchSiteParams) {
	if !s.wgEnabled(w, r) {
		return
	}
	// Merge Patch: nur vorhandene Schluessel aendern, null loescht.
	var raw map[string]any
	if err := decode(r, &raw); err != nil {
		s.writeError(w, r, err)
		return
	}
	var out apigen.Site
	ok := s.mutate(w, r, "site.update", "site", name, func(t *tx) error {
		old, err := s.getSiteTx(t, name)
		if err != nil {
			return err
		}
		if err := checkIfMatch(params.IfMatch, old.Version); err != nil {
			return err
		}
		site := old
		for k, v := range raw {
			var str *string
			if sv, ok := v.(string); ok {
				str = nilIfEmpty(&sv)
			} else if v != nil && k != "enabled" {
				return errf(http.StatusBadRequest, "%s muss ein String oder null sein", k)
			}
			switch k {
			case "email":
				if str != nil {
					if err := domain.ValidateEmail(*str); err != nil {
						return badRequest(err)
					}
				}
				site.Email = str
			case "os_hint":
				if str != nil && *str != "debian" && *str != "ubuntu" && *str != "alpine" {
					return errf(http.StatusBadRequest, "os_hint: debian, ubuntu oder alpine")
				}
				site.OsHint = str
			case "notes":
				site.Notes = str
			case "lan_cidr":
				if site.LanCidr, err = validLAN(str); err != nil {
					return err
				}
			case "enabled":
				b, ok := v.(bool)
				if !ok {
					return errf(http.StatusBadRequest, "enabled muss true oder false sein")
				}
				site.Enabled = b2i(b)
				if !b {
					site.Status = "offline"
				} else if old.Enabled == 0 {
					site.Status = "pending"
				}
			default:
				return errf(http.StatusBadRequest, "Feld %q kann nicht geaendert werden", k)
			}
		}
		out, err = s.saveSite(t, old, site, "site.update", nil)
		return err
	})
	if ok {
		w.Header().Set("ETag", etag(out.Version))
		writeJSON(w, http.StatusOK, out)
	}
}

func (s *Server) DeleteSite(w http.ResponseWriter, r *http.Request, name apigen.Name, params apigen.DeleteSiteParams) {
	if !s.wgEnabled(w, r) {
		return
	}
	ok := s.mutate(w, r, "site.delete", "site", name, func(t *tx) error {
		old, err := s.getSiteTx(t, name)
		if err != nil {
			return err
		}
		if err := checkIfMatch(params.IfMatch, old.Version); err != nil {
			return err
		}
		if n, err := t.q.CountHostsBySite(t.ctx, &name); err != nil {
			return err
		} else if n > 0 {
			return errf(http.StatusConflict, "Site %s wird noch von %d Host(s) genutzt", name, n)
		}
		if flag(params.KeepConfig) {
			// Datensatz bleibt, der WireGuard-Peer wird entfernt.
			site := old
			site.Enabled, site.Status = 0, "offline"
			_, err := s.saveSite(t, old, site, "site.disable", nil)
			return err
		}
		if n, err := t.q.DeleteSite(t.ctx, dbq.DeleteSiteParams{Name: name, Version: old.Version}); err != nil {
			return err
		} else if n == 0 {
			return errf(http.StatusPreconditionFailed, "Site wurde zwischenzeitlich geaendert")
		}
		return t.audit("site.delete", "site", name, siteAPI(old), nil)
	})
	if ok {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) GetSiteInstallScript(w http.ResponseWriter, r *http.Request, name apigen.Name, params apigen.GetSiteInstallScriptParams) {
	if !s.wgEnabled(w, r) {
		return
	}
	var script string
	// Das Script enthaelt den PSK: Abruf wird protokolliert.
	ok := s.mutate(w, r, "site.install_script", "site", name, func(t *tx) error {
		site, err := s.getSiteTx(t, name)
		if err != nil {
			return err
		}
		hub, err := t.q.GetWgHub(t.ctx)
		if err != nil {
			return errf(http.StatusConflict, "WireGuard-Hub ist nicht initialisiert")
		}
		p := wireguard.ScriptParams{Name: site.Name, Subnet: site.Subnet, ConnectorIP: site.ConnectorIp,
			OverlayCIDR: hub.OverlayCidr, HubPublic: hub.PublicKey, PublicEndpoint: s.d.Cfg.PublicEndpoint,
			ListenPort: int(hub.ListenPort)}
		if site.LanCidr != nil {
			p.LANCIDR = *site.LanCidr
		}
		if site.OsHint != nil {
			p.OS = *site.OsHint
		}
		if params.Os != nil {
			p.OS = string(*params.Os)
		}
		if len(site.PskEnc) > 0 {
			psk, err := s.d.Box.Open(site.PskEnc)
			if err != nil {
				return err
			}
			p.PSK = string(psk)
		}
		if script, err = wireguard.InstallScript(p); err != nil {
			return errf(http.StatusConflict, "%v", err)
		}
		return t.audit("site.install_script", "site", name, nil, map[string]any{"os": p.OS})
	})
	if ok {
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(script))
	}
}

func (s *Server) SetSitePublicKey(w http.ResponseWriter, r *http.Request, name apigen.Name) {
	if !s.wgEnabled(w, r) {
		return
	}
	var in apigen.PublicKeyInput
	if err := decode(r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	var out apigen.Site
	ok := s.mutate(w, r, "site.set_public_key", "site", name, func(t *tx) error {
		if err := wireguard.ValidateKey(in.PublicKey); err != nil {
			return badRequest(err)
		}
		old, err := s.getSiteTx(t, name)
		if err != nil {
			return err
		}
		all, err := t.q.ListSites(t.ctx)
		if err != nil {
			return err
		}
		for _, o := range all {
			if o.Name != name && o.PublicKey != nil && *o.PublicKey == in.PublicKey {
				return errf(http.StatusConflict, "Public Key wird bereits von Site %s verwendet", o.Name)
			}
		}
		site := old
		site.PublicKey = &in.PublicKey
		out, err = s.saveSite(t, old, site, "site.set_public_key", nil)
		return err
	})
	if ok {
		w.Header().Set("ETag", etag(out.Version))
		writeJSON(w, http.StatusOK, out)
	}
}

func (s *Server) RotateSitePsk(w http.ResponseWriter, r *http.Request, name apigen.Name) {
	if !s.wgEnabled(w, r) {
		return
	}
	var out apigen.Site
	ok := s.mutate(w, r, "site.rotate_psk", "site", name, func(t *tx) error {
		old, err := s.getSiteTx(t, name)
		if err != nil {
			return err
		}
		psk, err := wireguard.GeneratePSK()
		if err != nil {
			return err
		}
		site := old
		if site.PskEnc, err = s.d.Box.Seal([]byte(psk)); err != nil {
			return err
		}
		// Im Audit steht nur ein Kurz-Hash des neuen PSK.
		out, err = s.saveSite(t, old, site, "site.rotate_psk", map[string]any{"psk": psk})
		return err
	})
	if ok {
		w.Header().Set("ETag", etag(out.Version))
		writeJSON(w, http.StatusOK, out)
	}
}

package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/apigen"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/audit"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/domain"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/reconcile"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store/dbq"
)

// ── WAF ─────────────────────────────────────────────────────────────────────

var crsVersionRe = regexp.MustCompile(`OWASP (?:ModSecurity )?(?:Core Rule Set|CRS) ver\.?\s*([0-9][0-9A-Za-z.+-]*)`)

// CRSVersion liest die Version des im Image enthaltenen Core Rule Set.
func CRSVersion(crsDir, versionsFile string) string {
	// Das Image legt die Build-Versionen als KEY=VALUE ab.
	if b, err := os.ReadFile(versionsFile); err == nil {
		if m := regexp.MustCompile(`(?m)^CRS_REF=(\S+)`).FindSubmatch(b); m != nil {
			return string(m[1])
		}
	}
	if b, err := os.ReadFile(filepath.Join(crsDir, "crs-setup.conf.example")); err == nil {
		if m := crsVersionRe.FindSubmatch(b); m != nil {
			return string(m[1])
		}
	}
	return "unknown"
}

func (s *Server) wafAPI(ctx context.Context, q *dbq.Queries) (apigen.Waf, error) {
	st, err := store.LoadSettings(ctx, q)
	if err != nil {
		return apigen.Waf{}, err
	}
	hosts, err := q.ListHosts(ctx)
	if err != nil {
		return apigen.Waf{}, err
	}
	s.crsVersion.Do(func() { s.crsVer = CRSVersion(s.d.Cfg.CRSDir, s.d.Cfg.VersionsFile) })
	out := apigen.Waf{Mode: apigen.WafMode(st.WAFMode), CrsVersion: s.crsVer, Hosts: []string{}, Overrides: st.WAFOverrides}
	for _, h := range hosts {
		if h.Waf != 0 {
			out.Hosts = append(out.Hosts, h.Fqdn)
		}
	}
	return out, nil
}

func (s *Server) GetWaf(w http.ResponseWriter, r *http.Request) {
	out, err := s.wafAPI(r.Context(), s.d.Store.Read())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) PutWaf(w http.ResponseWriter, r *http.Request) {
	var in apigen.WafInput
	if err := decode(r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	var out apigen.Waf
	ok := s.mutate(w, r, "waf.set", "waf", "global", func(t *tx) error {
		before, err := s.wafAPI(t.ctx, t.q)
		if err != nil {
			return err
		}
		if in.Mode == nil && in.Overrides == nil {
			return errf(http.StatusBadRequest, "mode oder overrides angeben")
		}
		if in.Mode != nil {
			mode, err := domain.NormalizeWAFMode(string(*in.Mode))
			if err != nil {
				return badRequest(err)
			}
			if err := store.SaveSetting(t.ctx, t.q, domain.KeyWAFMode, mode); err != nil {
				return err
			}
		}
		if in.Overrides != nil {
			if len(*in.Overrides) > 256<<10 {
				return errf(http.StatusBadRequest, "overrides sind zu gross (max. 256 KiB)")
			}
			if err := store.SaveSetting(t.ctx, t.q, domain.KeyWAFOverrides, *in.Overrides); err != nil {
				return err
			}
		}
		if out, err = s.wafAPI(t.ctx, t.q); err != nil {
			return err
		}
		return t.audit("waf.set", "waf", "global", before, out)
	})
	if ok {
		writeJSON(w, http.StatusOK, out)
	}
}

// ── Settings ────────────────────────────────────────────────────────────────

func settingsAPI(st domain.Settings) apigen.Settings {
	out := apigen.Settings{ClientMaxBodySize: st.ClientMaxBodySize,
		Hsts: apigen.Hsts{MaxAge: st.HSTS.MaxAge, IncludeSubdomains: st.HSTS.IncludeSubdomains, Preload: st.HSTS.Preload}}
	if st.ACMEEmail != "" {
		out.AcmeEmail = &st.ACMEEmail
	}
	return out
}

func (s *Server) GetSettings(w http.ResponseWriter, r *http.Request) {
	st, err := store.LoadSettings(r.Context(), s.d.Store.Read())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, settingsAPI(st))
}

func (s *Server) PatchSettings(w http.ResponseWriter, r *http.Request) {
	var raw map[string]json.RawMessage
	if err := decode(r, &raw); err != nil {
		s.writeError(w, r, err)
		return
	}
	var out apigen.Settings
	ok := s.mutate(w, r, "settings.update", "settings", "global", func(t *tx) error {
		old, err := store.LoadSettings(t.ctx, t.q)
		if err != nil {
			return err
		}
		st := old
		for k, v := range raw {
			switch k {
			case "client_max_body_size":
				if err := json.Unmarshal(v, &st.ClientMaxBodySize); err != nil {
					return badRequest(err)
				}
				if err := domain.ValidateBodySize(st.ClientMaxBodySize); err != nil {
					return badRequest(err)
				}
				err = store.SaveSetting(t.ctx, t.q, domain.KeyClientMaxBodySize, st.ClientMaxBodySize)
			case "hsts":
				// Merge Patch: Teilobjekte ergaenzen die bestehenden Werte.
				cur, _ := json.Marshal(st.HSTS)
				merged, merr := mergePatch(cur, v)
				if merr != nil {
					return badRequest(merr)
				}
				if err := strictUnmarshal(merged, &st.HSTS); err != nil {
					return badRequest(err)
				}
				if err := domain.ValidateHSTS(st.HSTS); err != nil {
					return badRequest(err)
				}
				err = store.SaveSetting(t.ctx, t.q, domain.KeyHSTS, st.HSTS)
			case "acme_email":
				var email *string
				if err := json.Unmarshal(v, &email); err != nil {
					return badRequest(err)
				}
				st.ACMEEmail = ""
				if email = nilIfEmpty(email); email != nil {
					if err := domain.ValidateEmail(*email); err != nil {
						return badRequest(err)
					}
					st.ACMEEmail = *email
				}
				err = store.SaveSetting(t.ctx, t.q, domain.KeyACMEEmail, st.ACMEEmail)
			default:
				return errf(http.StatusBadRequest, "unbekannte Einstellung %q", k)
			}
			if err != nil {
				return err
			}
		}
		out = settingsAPI(st)
		return t.audit("settings.update", "settings", "global", settingsAPI(old), out)
	})
	if ok {
		writeJSON(w, http.StatusOK, out)
	}
}

// ── Status ──────────────────────────────────────────────────────────────────

// BuildStatus sammelt den Gesamtzustand (auch fuer nrp health und Metriken).
func (s *Server) BuildStatus(ctx context.Context) (apigen.Status, error) {
	q := s.d.Store.Read()
	var st apigen.Status
	st.Version, st.Mode = s.d.Version, apigen.StatusMode(s.d.Mode)
	st.Nginx.Running = s.d.Nginx.Running()
	if v := s.d.Nginx.Version(ctx); v != "" {
		st.Nginx.Version = &v
	}
	gen, pinned, lastErr := s.d.Reconciler.State()
	st.Render.Generation, st.Render.Pinned = gen, pinned
	if lastErr != "" {
		st.Render.LastError = &lastErr
	}

	hosts, err := q.ListHosts(ctx)
	if err != nil {
		return st, err
	}
	st.Hosts.Total = len(hosts)
	for _, h := range hosts {
		switch h.Status {
		case domain.HostActive:
			st.Hosts.Active++
		case domain.HostError:
			st.Hosts.Error++
		default:
			st.Hosts.PendingCertificate++
		}
		if h.Waf != 0 {
			st.Waf.Hosts++
		}
	}
	settings, err := store.LoadSettings(ctx, q)
	if err != nil {
		return st, err
	}
	st.Waf.Mode = apigen.WafMode(settings.WAFMode)

	certs, err := q.ListCertificates(ctx)
	if err != nil {
		return st, err
	}
	st.Certificates.Total = len(certs)
	for _, c := range certs {
		na := store.ParseTime(c.NotAfter)
		if time.Until(na) < 30*24*time.Hour {
			st.Certificates.Expiring30d++
		}
		if st.Certificates.NextExpiry == nil || na.Before(*st.Certificates.NextExpiry) {
			st.Certificates.NextExpiry = &na
		}
	}

	st.Wireguard.Enabled = s.d.Cfg.WireGuardEnabled
	if st.Wireguard.Enabled {
		if hub, err := q.GetWgHub(ctx); err == nil {
			port := int(hub.ListenPort)
			st.Wireguard.PublicKey, st.Wireguard.ListenPort, st.Wireguard.Address = &hub.PublicKey, &port, &hub.Address
		}
		sites, err := q.ListSites(ctx)
		if err != nil {
			return st, err
		}
		st.Wireguard.SitesTotal = len(sites)
		for _, site := range sites {
			if site.Status == "online" {
				st.Wireguard.SitesOnline++
			}
		}
	}

	counts, err := q.CountJobsByStatus(ctx)
	if err != nil {
		return st, err
	}
	for _, c := range counts {
		switch c.Status {
		case "queued":
			st.Jobs.Queued = int(c.N)
		case "running":
			st.Jobs.Running = int(c.N)
		case "failed":
			st.Jobs.Failed = int(c.N)
		}
	}

	if url := s.d.Cfg.CrowdsecURL; url != "" {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		ok := false
		if req, err := http.NewRequestWithContext(cctx, http.MethodGet, url+"/health", nil); err == nil {
			if resp, err := http.DefaultClient.Do(req); err == nil {
				resp.Body.Close()
				ok = resp.StatusCode < 500
			}
		}
		st.Crowdsec = &struct {
			Reachable bool `json:"reachable"`
		}{Reachable: ok}
	}
	return st, nil
}

func (s *Server) GetStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.BuildStatus(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// ── Render ──────────────────────────────────────────────────────────────────

func reconcileAPI(res reconcile.Result) apigen.ReconcileResult {
	out := apigen.ReconcileResult{Generation: res.Generation, Changed: res.Changed, Reloaded: res.Reloaded}
	if res.Error != "" {
		out.Error = &res.Error
	}
	return out
}

func (s *Server) GetRenderCurrent(w http.ResponseWriter, r *http.Request) {
	gen, files, err := s.d.Reconciler.CurrentFiles()
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, apigen.RenderCurrent{Generation: gen, Files: files})
}

func (s *Server) ListGenerations(w http.ResponseWriter, r *http.Request) {
	rows, err := s.d.Store.Read().ListGenerations(r.Context(), 50)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	cur, _, _ := s.d.Reconciler.State()
	out := apigen.GenerationList{Items: []apigen.Generation{}}
	for _, g := range rows {
		avail := s.d.Reconciler.Available(g.ID)
		out.Items = append(out.Items, apigen.Generation{Id: g.ID, ContentSha256: g.ContentSha256,
			Status: apigen.GenerationStatus(g.Status), NginxTestOutput: g.NginxTestOutput,
			CreatedAt: store.ParseTime(g.CreatedAt), Current: g.ID == cur, Available: &avail})
	}
	writeJSON(w, http.StatusOK, out)
}

// renderAction protokolliert Rollback und erzwungenes Reconcile.
func (s *Server) renderAction(w http.ResponseWriter, r *http.Request, action string, detail map[string]any, run func() (reconcile.Result, error)) {
	res, err := run()
	e := s.entry(r)
	e.Action, e.ResourceType, e.ResourceID = action, "generation", strconv.FormatInt(res.Generation, 10)
	detail["changed"], detail["reloaded"] = res.Changed, res.Reloaded
	e.After = detail
	if err != nil || res.Error != "" {
		e.Result = audit.Failed
		if e.Error = res.Error; err != nil {
			e.Error = err.Error()
		}
	}
	s.auditOwnTx(r.Context(), e)
	if err != nil {
		s.writeError(w, r, errf(http.StatusConflict, "%v", err))
		return
	}
	writeJSON(w, http.StatusOK, reconcileAPI(res))
}

func (s *Server) RollbackRender(w http.ResponseWriter, r *http.Request) {
	var in apigen.RollbackInput
	if err := decode(r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	s.renderAction(w, r, "render.rollback", map[string]any{"target": in.Generation}, func() (reconcile.Result, error) {
		return s.d.Reconciler.Rollback(r.Context(), in.Generation)
	})
}

func (s *Server) ReconcileRender(w http.ResponseWriter, r *http.Request) {
	s.renderAction(w, r, "render.reconcile", map[string]any{}, func() (reconcile.Result, error) {
		return s.d.Reconciler.Reconcile(r.Context(), true)
	})
}

// ── Audit ───────────────────────────────────────────────────────────────────

func jsonMap(s *string) *map[string]any {
	if s == nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal([]byte(*s), &m) != nil {
		m = map[string]any{"value": json.RawMessage(*s)}
	}
	return &m
}

func (s *Server) ListAudit(w http.ResponseWriter, r *http.Request, params apigen.ListAuditParams) {
	limit := 100
	if params.Limit != nil {
		limit = *params.Limit
	}
	arg := dbq.ListAuditParams{Lim: int64(limit) + 1}
	if params.Since != nil {
		arg.Since = store.FormatTime(*params.Since)
	}
	if params.Actor != nil {
		arg.Actor = *params.Actor
	}
	if params.Resource != nil {
		arg.Resource = *params.Resource
	}
	if params.Cursor != nil {
		seq, err := strconv.ParseInt(*params.Cursor, 10, 64)
		if err != nil {
			s.writeError(w, r, errf(http.StatusBadRequest, "ungueltiger Cursor"))
			return
		}
		arg.Cursor = seq
	}
	rows, err := s.d.Store.Read().ListAudit(r.Context(), arg)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := apigen.AuditList{Items: []apigen.AuditEntry{}}
	for i, a := range rows {
		if i == limit {
			c := strconv.FormatInt(rows[i-1].Seq, 10)
			out.NextCursor = &c
			break
		}
		out.Items = append(out.Items, apigen.AuditEntry{Seq: a.Seq, Ts: store.ParseTime(a.Ts), RequestId: a.RequestID,
			ActorType: apigen.AuditEntryActorType(a.ActorType), ActorId: a.ActorID, ActorFingerprint: a.ActorFingerprint,
			SourceIp: a.SourceIp, Action: a.Action, ResourceType: a.ResourceType, ResourceId: a.ResourceID,
			Before: jsonMap(a.BeforeJson), After: jsonMap(a.AfterJson), Result: apigen.AuditEntryResult(a.Result),
			Error: a.Error, Hash: hex.EncodeToString(a.Hash)})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) VerifyAudit(w http.ResponseWriter, r *http.Request) {
	res, err := audit.Verify(r.Context(), s.d.Store.Read())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := apigen.AuditVerify{Ok: res.OK, Entries: res.Entries, BrokenAtSeq: res.BrokenAt}
	if res.Entries > 0 {
		out.FirstSeq, out.LastSeq = &res.FirstSeq, &res.LastSeq
	}
	if res.Error != "" {
		out.Error = &res.Error
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) PruneAudit(w http.ResponseWriter, r *http.Request) {
	if !s.requireLocal(w, r, "audit.prune") {
		return
	}
	var in apigen.AuditPruneInput
	if err := decode(r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	if in.Before.IsZero() || in.Before.After(time.Now()) {
		s.writeError(w, r, errf(http.StatusBadRequest, "before muss in der Vergangenheit liegen"))
		return
	}
	var out apigen.AuditPruneResult
	var rows []dbq.AuditLog
	err := s.d.Store.Write(r.Context(), func(q *dbq.Queries) error {
		deleted, anchor, row, err := audit.Prune(r.Context(), q, in.Before, s.entry(r))
		if err != nil {
			return err
		}
		out.Deleted = deleted
		if anchor != "" {
			out.AnchorHash, rows = &anchor, []dbq.AuditLog{row}
		}
		return nil
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	audit.Emit(rows...)
	writeJSON(w, http.StatusOK, out)
}

// ── Backup ──────────────────────────────────────────────────────────────────

var backupNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,100}$`)

func (s *Server) CreateBackup(w http.ResponseWriter, r *http.Request) {
	if !s.requireLocal(w, r, "backup.create") {
		return
	}
	var in apigen.BackupInput
	if err := decode(r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	name := "nrp-" + time.Now().UTC().Format("20060102-150405") + ".db"
	if in.Name != nil && *in.Name != "" {
		name = *in.Name
	}
	if !backupNameRe.MatchString(name) {
		s.writeError(w, r, errf(http.StatusBadRequest, "ungueltiger Dateiname %q", name))
		return
	}
	dest := filepath.Join(s.d.Cfg.BackupDir, name)
	e := s.entry(r)
	e.Action, e.ResourceType, e.ResourceID = "backup.create", "backup", name
	if err := s.d.Store.Backup(r.Context(), dest); err != nil {
		e.Result, e.Error = audit.Failed, err.Error()
		s.auditOwnTx(r.Context(), e)
		s.writeError(w, r, errf(http.StatusConflict, "%v", err))
		return
	}
	_ = os.Chmod(dest, 0o600)
	s.auditOwnTx(r.Context(), e)
	writeJSON(w, http.StatusCreated, apigen.BackupResult{Path: dest})
}

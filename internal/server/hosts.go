package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/apigen"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/domain"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/jobs"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store/dbq"
)

func hostAPI(h dbq.Host, cert *dbq.Certificate) apigen.Host {
	out := apigen.Host{
		Fqdn: h.Fqdn,
		Upstream: apigen.Upstream{Scheme: apigen.UpstreamScheme(h.UpstreamScheme), Address: h.UpstreamAddress,
			Port: int(h.UpstreamPort), Site: h.SiteName},
		ExternalPort: int(h.ExternalPort), Websockets: h.Websockets != 0, Waf: h.Waf != 0,
		ClientMaxBodySize: h.ClientMaxBodySize, AcmeEmail: h.AcmeEmail,
		Status: apigen.HostStatus(h.Status), StatusDetail: h.StatusDetail, Version: h.Version,
		CreatedAt: store.ParseTime(h.CreatedAt), UpdatedAt: store.ParseTime(h.UpdatedAt),
	}
	if h.HstsJson != nil {
		var hs apigen.Hsts
		if json.Unmarshal([]byte(*h.HstsJson), &hs) == nil {
			out.Hsts = &hs
		}
	}
	if cert != nil {
		out.Certificate = &apigen.CertificateSummary{NotAfter: store.ParseTime(cert.NotAfter), Issuer: cert.Issuer}
	}
	return out
}

// hostInputOf ist die Umkehrung fuer PATCH (JSON Merge Patch auf der Eingabeform).
func hostInputOf(h apigen.Host) apigen.HostInput {
	return apigen.HostInput{Fqdn: &h.Fqdn, Upstream: h.Upstream, ExternalPort: &h.ExternalPort, Websockets: &h.Websockets,
		Waf: &h.Waf, ClientMaxBodySize: h.ClientMaxBodySize, Hsts: h.Hsts, AcmeEmail: h.AcmeEmail}
}

func (s *Server) hostWithCert(t *tx, h dbq.Host) apigen.Host {
	if c, err := t.q.GetCertificate(t.ctx, h.Fqdn); err == nil {
		return hostAPI(h, &c)
	}
	return hostAPI(h, nil)
}

// buildHost validiert die Eingabe und liefert die Zeile (ohne Status/Version).
func (s *Server) buildHost(t *tx, fqdn string, in apigen.HostInput) (dbq.Host, error) {
	h := dbq.Host{Fqdn: fqdn, UpstreamScheme: string(in.Upstream.Scheme), UpstreamAddress: in.Upstream.Address,
		UpstreamPort: int64(in.Upstream.Port), ExternalPort: 443, Websockets: b2i(flag(in.Websockets)), Waf: b2i(flag(in.Waf))}
	if in.ExternalPort != nil {
		h.ExternalPort = int64(*in.ExternalPort)
	}
	checks := []error{
		domain.ValidateFQDN(fqdn),
		domain.ValidateScheme(h.UpstreamScheme),
		domain.ValidateUpstreamAddress(h.UpstreamAddress),
		domain.ValidatePort(int(h.UpstreamPort)),
		domain.ValidateExternalPort(int(h.ExternalPort)),
	}
	if h.ClientMaxBodySize = nilIfEmpty(in.ClientMaxBodySize); h.ClientMaxBodySize != nil {
		checks = append(checks, domain.ValidateBodySize(*h.ClientMaxBodySize))
	}
	if h.AcmeEmail = nilIfEmpty(in.AcmeEmail); h.AcmeEmail != nil {
		checks = append(checks, domain.ValidateEmail(*h.AcmeEmail))
	}
	if in.Hsts != nil {
		checks = append(checks, domain.ValidateHSTS(domain.HSTS{MaxAge: in.Hsts.MaxAge,
			IncludeSubdomains: in.Hsts.IncludeSubdomains, Preload: in.Hsts.Preload}))
		b, _ := json.Marshal(in.Hsts)
		js := string(b)
		h.HstsJson = &js
	}
	for _, err := range checks {
		if err != nil {
			return h, badRequest(err)
		}
	}
	if h.SiteName = nilIfEmpty(in.Upstream.Site); h.SiteName != nil {
		if !s.d.Cfg.WireGuardEnabled {
			return h, errf(http.StatusConflict, "WireGuard ist deaktiviert (NRP_WIREGUARD_ENABLED=false); Upstreams ueber Sites sind nicht moeglich")
		}
		site, err := t.q.GetSite(t.ctx, *h.SiteName)
		if isNoRows(err) {
			return h, errf(http.StatusBadRequest, "Site %q existiert nicht", *h.SiteName)
		} else if err != nil {
			return h, err
		}
		nets := []string{site.Subnet}
		if site.LanCidr != nil {
			nets = append(nets, *site.LanCidr)
		}
		if !domain.AddressInSubnets(h.UpstreamAddress, nets...) {
			return h, errf(http.StatusBadRequest, "Upstream %s liegt nicht im Netz der Site %s (%v)", h.UpstreamAddress, site.Name, nets)
		}
	}
	return h, nil
}

func (s *Server) hasValidCert(t *tx, fqdn string) bool {
	c, err := t.q.GetCertificate(t.ctx, fqdn)
	return err == nil && store.ParseTime(c.NotAfter).After(time.Now())
}

// insertHost legt den Host an und startet bei Bedarf den Zertifikatsjob.
func (s *Server) insertHost(t *tx, h dbq.Host, action string) (apigen.Host, *dbq.Job, error) {
	now := store.Now()
	h.Status, h.CreatedAt, h.UpdatedAt, h.Version = domain.HostPending, now, now, 1
	var job *dbq.Job
	if s.hasValidCert(t, h.Fqdn) {
		h.Status = domain.HostActive
	}
	if err := t.q.InsertHost(t.ctx, dbq.InsertHostParams{Fqdn: h.Fqdn, UpstreamScheme: h.UpstreamScheme,
		UpstreamAddress: h.UpstreamAddress, UpstreamPort: h.UpstreamPort, SiteName: h.SiteName, ExternalPort: h.ExternalPort,
		Websockets: h.Websockets, Waf: h.Waf, ClientMaxBodySize: h.ClientMaxBodySize, HstsJson: h.HstsJson,
		AcmeEmail: h.AcmeEmail, Status: h.Status, CreatedAt: now, UpdatedAt: now}); err != nil {
		return apigen.Host{}, nil, err
	}
	if h.Status == domain.HostPending {
		j, err := jobs.Enqueue(t.ctx, t.q, jobs.CertIssue, h.Fqdn, t.base.ActorType+":"+t.base.ActorID)
		if err != nil {
			return apigen.Host{}, nil, err
		}
		job = &j
	}
	out := s.hostWithCert(t, h)
	return out, job, t.audit(action, "host", h.Fqdn, nil, out)
}

func (s *Server) updateHost(t *tx, old dbq.Host, h dbq.Host, action string) (apigen.Host, error) {
	h.Status, h.StatusDetail, h.CreatedAt = old.Status, old.StatusDetail, old.CreatedAt
	if old.Status == domain.HostError {
		// Eine Aenderung gibt dem Host eine neue Chance (hebt die Quarantaene auf).
		h.Status, h.StatusDetail = domain.HostPending, nil
		if s.hasValidCert(t, h.Fqdn) {
			h.Status = domain.HostActive
		}
	}
	h.UpdatedAt, h.Version = store.Now(), old.Version+1
	n, err := t.q.UpdateHost(t.ctx, dbq.UpdateHostParams{UpstreamScheme: h.UpstreamScheme, UpstreamAddress: h.UpstreamAddress,
		UpstreamPort: h.UpstreamPort, SiteName: h.SiteName, ExternalPort: h.ExternalPort, Websockets: h.Websockets,
		Waf: h.Waf, ClientMaxBodySize: h.ClientMaxBodySize, HstsJson: h.HstsJson, AcmeEmail: h.AcmeEmail,
		Status: h.Status, StatusDetail: h.StatusDetail, UpdatedAt: h.UpdatedAt, Fqdn: h.Fqdn, Version: old.Version})
	if err != nil {
		return apigen.Host{}, err
	}
	if n == 0 {
		return apigen.Host{}, errf(http.StatusPreconditionFailed, "Host wurde zwischenzeitlich geaendert")
	}
	out := s.hostWithCert(t, h)
	return out, t.audit(action, "host", h.Fqdn, s.hostWithCert(t, old), out)
}

func (s *Server) ListHosts(w http.ResponseWriter, r *http.Request, params apigen.ListHostsParams) {
	ctx := r.Context()
	q := s.d.Store.Read()
	hosts, err := q.ListHosts(ctx)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	certs, err := q.ListCertificates(ctx)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	byName := make(map[string]*dbq.Certificate, len(certs))
	for i := range certs {
		byName[certs[i].Fqdn] = &certs[i]
	}
	limit := 100
	if params.Limit != nil {
		limit = *params.Limit
	}
	out := apigen.HostList{Items: []apigen.Host{}}
	for _, h := range hosts {
		if params.Cursor != nil && h.Fqdn <= *params.Cursor {
			continue
		}
		if len(out.Items) == limit {
			last := out.Items[len(out.Items)-1].Fqdn
			out.NextCursor = &last
			break
		}
		out.Items = append(out.Items, hostAPI(h, byName[h.Fqdn]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) CreateHost(w http.ResponseWriter, r *http.Request, _ apigen.CreateHostParams) {
	var in apigen.HostInput
	if err := decode(r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	fqdn := ""
	if in.Fqdn != nil {
		fqdn = domain.NormalizeFQDN(*in.Fqdn)
	}
	var out apigen.HostCreated
	var job *dbq.Job
	ok := s.mutate(w, r, "host.create", "host", fqdn, func(t *tx) error {
		h, err := s.buildHost(t, fqdn, in)
		if err != nil {
			return err
		}
		if _, err := t.q.GetHost(t.ctx, fqdn); err == nil {
			return errf(http.StatusConflict, "Host %s existiert bereits (PUT bzw. --overwrite zum Ersetzen)", fqdn)
		} else if !isNoRows(err) {
			return err
		}
		out.Host, job, err = s.insertHost(t, h, "host.create")
		return err
	})
	if !ok {
		return
	}
	w.Header().Set("ETag", etag(out.Host.Version))
	w.Header().Set("Location", BasePath+"/hosts/"+fqdn)
	if job != nil {
		j := jobAPI(*job)
		out.Job = &j
		w.Header().Set("Location", BasePath+"/jobs/"+job.ID)
		s.d.JobNotify()
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) GetHost(w http.ResponseWriter, r *http.Request, fqdn apigen.Fqdn) {
	fqdn = domain.NormalizeFQDN(fqdn)
	q := s.d.Store.Read()
	h, err := q.GetHost(r.Context(), fqdn)
	if isNoRows(err) {
		s.writeError(w, r, notFound("Host", fqdn))
		return
	} else if err != nil {
		s.writeError(w, r, err)
		return
	}
	var cert *dbq.Certificate
	if c, err := q.GetCertificate(r.Context(), fqdn); err == nil {
		cert = &c
	}
	w.Header().Set("ETag", etag(h.Version))
	writeJSON(w, http.StatusOK, hostAPI(h, cert))
}

func (s *Server) PatchHost(w http.ResponseWriter, r *http.Request, fqdn apigen.Fqdn, params apigen.PatchHostParams) {
	fqdn = domain.NormalizeFQDN(fqdn)
	var patch json.RawMessage
	if err := decode(r, &patch); err != nil {
		s.writeError(w, r, err)
		return
	}
	var out apigen.Host
	ok := s.mutate(w, r, "host.update", "host", fqdn, func(t *tx) error {
		old, err := t.q.GetHost(t.ctx, fqdn)
		if isNoRows(err) {
			return notFound("Host", fqdn)
		} else if err != nil {
			return err
		}
		if err := checkIfMatch(params.IfMatch, old.Version); err != nil {
			return err
		}
		base, _ := json.Marshal(hostInputOf(hostAPI(old, nil)))
		merged, err := mergePatch(base, patch)
		if err != nil {
			return badRequest(err)
		}
		var in apigen.HostInput
		if err := strictUnmarshal(merged, &in); err != nil {
			return badRequest(err)
		}
		if in.Fqdn != nil && domain.NormalizeFQDN(*in.Fqdn) != fqdn {
			return errf(http.StatusBadRequest, "fqdn kann nicht geaendert werden")
		}
		h, err := s.buildHost(t, fqdn, in)
		if err != nil {
			return err
		}
		out, err = s.updateHost(t, old, h, "host.update")
		return err
	})
	if ok {
		w.Header().Set("ETag", etag(out.Version))
		writeJSON(w, http.StatusOK, out)
	}
}

func (s *Server) PutHost(w http.ResponseWriter, r *http.Request, fqdn apigen.Fqdn, params apigen.PutHostParams) {
	fqdn = domain.NormalizeFQDN(fqdn)
	var in apigen.HostInput
	if err := decode(r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	var out apigen.Host
	var job *dbq.Job
	status := http.StatusOK
	ok := s.mutate(w, r, "host.replace", "host", fqdn, func(t *tx) error {
		if in.Fqdn != nil && domain.NormalizeFQDN(*in.Fqdn) != fqdn {
			return errf(http.StatusBadRequest, "fqdn im Body weicht vom Pfad ab")
		}
		h, err := s.buildHost(t, fqdn, in)
		if err != nil {
			return err
		}
		old, err := t.q.GetHost(t.ctx, fqdn)
		if isNoRows(err) {
			status = http.StatusCreated
			out, job, err = s.insertHost(t, h, "host.create")
			return err
		} else if err != nil {
			return err
		}
		if err := checkIfMatch(params.IfMatch, old.Version); err != nil {
			return err
		}
		out, err = s.updateHost(t, old, h, "host.replace")
		return err
	})
	if !ok {
		return
	}
	if job != nil {
		w.Header().Set("Location", BasePath+"/jobs/"+job.ID)
		s.d.JobNotify()
	}
	w.Header().Set("ETag", etag(out.Version))
	writeJSON(w, status, out)
}

func (s *Server) DeleteHost(w http.ResponseWriter, r *http.Request, fqdn apigen.Fqdn, params apigen.DeleteHostParams) {
	fqdn = domain.NormalizeFQDN(fqdn)
	revoke := false
	ok := s.mutate(w, r, "host.delete", "host", fqdn, func(t *tx) error {
		old, err := t.q.GetHost(t.ctx, fqdn)
		if isNoRows(err) {
			return notFound("Host", fqdn)
		} else if err != nil {
			return err
		}
		if err := checkIfMatch(params.IfMatch, old.Version); err != nil {
			return err
		}
		before := s.hostWithCert(t, old)
		if n, err := t.q.DeleteHost(t.ctx, dbq.DeleteHostParams{Fqdn: fqdn, Version: old.Version}); err != nil {
			return err
		} else if n == 0 {
			return errf(http.StatusPreconditionFailed, "Host wurde zwischenzeitlich geaendert")
		}
		after := map[string]any{"keep_cert": flag(params.KeepCert), "revoke": flag(params.Revoke)}
		switch {
		case flag(params.KeepCert):
		case flag(params.Revoke) && before.Certificate != nil:
			// Der Job widerruft bei der CA und entfernt das Zertifikat danach.
			if _, err := jobs.Enqueue(t.ctx, t.q, jobs.CertRevoke, fqdn, t.base.ActorType+":"+t.base.ActorID); err != nil {
				return err
			}
			revoke = true
		default:
			if _, err := t.q.DeleteCertificate(t.ctx, fqdn); err != nil {
				return err
			}
		}
		return t.audit("host.delete", "host", fqdn, before, after)
	})
	if !ok {
		return
	}
	if revoke {
		s.d.JobNotify()
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Zertifikate ─────────────────────────────────────────────────────────────

func certAPI(c dbq.Certificate, withChain bool) apigen.Certificate {
	na := store.ParseTime(c.NotAfter)
	out := apigen.Certificate{Fqdn: c.Fqdn, NotBefore: store.ParseTime(c.NotBefore), NotAfter: na,
		AriRenewAt: timePtr(c.AriRenewAt), Issuer: c.Issuer, Source: apigen.CertificateSource(c.Source),
		UpdatedAt: store.ParseTime(c.UpdatedAt), DaysLeft: int(time.Until(na).Hours() / 24)}
	if withChain {
		out.ChainPem = &c.ChainPem
	}
	return out
}

func (s *Server) ListCertificates(w http.ResponseWriter, r *http.Request) {
	certs, err := s.d.Store.Read().ListCertificates(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := apigen.CertificateList{Items: []apigen.Certificate{}}
	for _, c := range certs {
		out.Items = append(out.Items, certAPI(c, false))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) GetCertificate(w http.ResponseWriter, r *http.Request, fqdn apigen.Fqdn) {
	fqdn = domain.NormalizeFQDN(fqdn)
	c, err := s.d.Store.Read().GetCertificate(r.Context(), fqdn)
	if isNoRows(err) {
		s.writeError(w, r, notFound("Zertifikat", fqdn))
		return
	} else if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, certAPI(c, true))
}

func (s *Server) RenewCertificate(w http.ResponseWriter, r *http.Request, fqdn apigen.Fqdn, _ apigen.RenewCertificateParams) {
	fqdn = domain.NormalizeFQDN(fqdn)
	var job dbq.Job
	ok := s.mutate(w, r, "certificate.renew_request", "certificate", fqdn, func(t *tx) error {
		if _, err := t.q.GetHost(t.ctx, fqdn); isNoRows(err) {
			return notFound("Host", fqdn)
		} else if err != nil {
			return err
		}
		for _, k := range []string{jobs.CertIssue, jobs.CertRenew} {
			if open, err := jobs.HasOpen(t.ctx, t.q, k, fqdn); err != nil {
				return err
			} else if open {
				return errf(http.StatusConflict, "fuer %s laeuft bereits ein Zertifikatsjob", fqdn)
			}
		}
		var err error
		if job, err = jobs.Enqueue(t.ctx, t.q, jobs.CertRenew, fqdn, t.base.ActorType+":"+t.base.ActorID); err != nil {
			return err
		}
		return t.audit("certificate.renew_request", "certificate", fqdn, nil, map[string]any{"job": job.ID})
	})
	if !ok {
		return
	}
	s.d.JobNotify()
	w.Header().Set("Location", BasePath+"/jobs/"+job.ID)
	writeJSON(w, http.StatusAccepted, jobAPI(job))
}

func (s *Server) DeleteCertificate(w http.ResponseWriter, r *http.Request, fqdn apigen.Fqdn, params apigen.DeleteCertificateParams) {
	fqdn = domain.NormalizeFQDN(fqdn)
	var job *dbq.Job
	ok := s.mutate(w, r, "certificate.delete", "certificate", fqdn, func(t *tx) error {
		c, err := t.q.GetCertificate(t.ctx, fqdn)
		if isNoRows(err) {
			return notFound("Zertifikat", fqdn)
		} else if err != nil {
			return err
		}
		before := certAPI(c, false)
		if flag(params.Revoke) {
			j, err := jobs.Enqueue(t.ctx, t.q, jobs.CertRevoke, fqdn, t.base.ActorType+":"+t.base.ActorID)
			if err != nil {
				return err
			}
			job = &j
			return t.audit("certificate.revoke_request", "certificate", fqdn, before, map[string]any{"job": j.ID})
		}
		if _, err := t.q.DeleteCertificate(t.ctx, fqdn); err != nil {
			return err
		}
		// Ein noch vorhandener Host braucht wieder ein Zertifikat.
		if h, err := t.q.GetHost(t.ctx, fqdn); err == nil {
			detail := "Zertifikat wurde entfernt"
			if err := t.q.SetHostStatus(t.ctx, dbq.SetHostStatusParams{Status: domain.HostPending, StatusDetail: &detail, Fqdn: h.Fqdn}); err != nil {
				return err
			}
		}
		return t.audit("certificate.delete", "certificate", fqdn, before, nil)
	})
	if !ok {
		return
	}
	if job != nil {
		s.d.JobNotify()
		w.Header().Set("Location", BasePath+"/jobs/"+job.ID)
		writeJSON(w, http.StatusAccepted, jobAPI(*job))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Jobs ────────────────────────────────────────────────────────────────────

func jobAPI(j dbq.Job) apigen.Job {
	return apigen.Job{Id: j.ID, Kind: apigen.JobKind(j.Kind), Resource: j.Resource, Status: apigen.JobStatus(j.Status),
		Attempts: int(j.Attempts), Error: j.Error, CreatedBy: j.CreatedBy, CreatedAt: store.ParseTime(j.CreatedAt),
		StartedAt: timePtr(j.StartedAt), FinishedAt: timePtr(j.FinishedAt)}
}

func (s *Server) ListJobs(w http.ResponseWriter, r *http.Request, params apigen.ListJobsParams) {
	limit := 100
	if params.Limit != nil {
		limit = *params.Limit
	}
	arg := dbq.ListJobsParams{Lim: int64(limit) + 1}
	if params.Status != nil {
		arg.Status = string(*params.Status)
	}
	if params.Cursor != nil {
		arg.Cursor = *params.Cursor
	}
	rows, err := s.d.Store.Read().ListJobs(r.Context(), arg)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := apigen.JobList{Items: []apigen.Job{}}
	for i, j := range rows {
		if i == limit {
			out.NextCursor = &rows[i-1].ID
			break
		}
		out.Items = append(out.Items, jobAPI(j))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) GetJob(w http.ResponseWriter, r *http.Request, id string) {
	j, err := s.d.Store.Read().GetJob(r.Context(), id)
	if isNoRows(err) {
		s.writeError(w, r, notFound("Job", id))
		return
	} else if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, jobAPI(j))
}

package server

import (
	"context"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/apigen"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/auth"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/domain"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/pki"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store/dbq"
)

func clientAPI(c dbq.ApiClient) apigen.ApiClient {
	return apigen.ApiClient{Id: c.ID, Name: c.Name, Role: apigen.Role(c.Role), CertSha256: c.CertSha256, Serial: c.Serial,
		NotAfter: store.ParseTime(c.NotAfter), Disabled: c.Disabled != 0, CreatedBy: c.CreatedBy,
		CreatedAt: store.ParseTime(c.CreatedAt), LastUsedAt: timePtr(c.LastUsedAt)}
}

func (s *Server) loadCA(ctx context.Context, q *dbq.Queries) (*pki.CA, error) {
	row, err := q.GetPki(ctx)
	if isNoRows(err) {
		return nil, errf(http.StatusConflict, "API-CA ist noch nicht initialisiert (Dienst einmal starten)")
	} else if err != nil {
		return nil, err
	}
	key, err := s.d.Box.Open(row.CaKeyEnc)
	if err != nil {
		return nil, err
	}
	return pki.LoadCA([]byte(row.CaCertPem), key)
}

// issue stellt ein Client-Zertifikat aus: per CSR (Schluessel bleibt beim
// Client) oder mit serverseitig erzeugtem Schluesselpaar.
func (s *Server) issue(t *tx, name string, csrPEM *string, days *int) (certPEM string, keyPEM *string, cert *x509.Certificate, ca *pki.CA, err error) {
	if ca, err = s.loadCA(t.ctx, t.q); err != nil {
		return
	}
	d := 90
	if days != nil {
		d = *days
	}
	if d < 1 || d > 397 {
		err = errf(http.StatusBadRequest, "days muss zwischen 1 und 397 liegen")
		return
	}
	var cp, kp []byte
	if csrPEM != nil && *csrPEM != "" {
		if cp, cert, err = ca.SignClientCSR(name, []byte(*csrPEM), d); err != nil {
			err = badRequest(err)
			return
		}
	} else {
		if cp, kp, cert, err = ca.IssueClient(name, d); err != nil {
			return
		}
		k := string(kp)
		keyPEM = &k
	}
	return string(cp), keyPEM, cert, ca, nil
}

func (s *Server) ListClients(w http.ResponseWriter, r *http.Request) {
	rows, err := s.d.Store.Read().ListClients(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := apigen.ApiClientList{Items: []apigen.ApiClient{}}
	for _, c := range rows {
		out.Items = append(out.Items, clientAPI(c))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) CreateClient(w http.ResponseWriter, r *http.Request) {
	var in apigen.ApiClientInput
	if err := decode(r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	var out apigen.ApiClientIssued
	ok := s.mutate(w, r, "client.issue", "client", in.Name, func(t *tx) error {
		if err := domain.ValidateName(in.Name); err != nil {
			return badRequest(err)
		}
		if !auth.ValidRole(string(in.Role)) {
			return errf(http.StatusBadRequest, "ungueltige Rolle %q (viewer, operator, admin)", in.Role)
		}
		if _, err := t.q.GetClientByName(t.ctx, in.Name); err == nil {
			return errf(http.StatusConflict, "Client %s existiert bereits (renew zum Erneuern, revoke --purge zum Entfernen)", in.Name)
		} else if !isNoRows(err) {
			return err
		}
		certPEM, keyPEM, cert, ca, err := s.issue(t, in.Name, in.CsrPem, in.Days)
		if err != nil {
			return err
		}
		c := dbq.ApiClient{ID: ulid.Make().String(), Name: in.Name, Role: string(in.Role), CertSha256: pki.Fingerprint(cert),
			Serial: cert.SerialNumber.Text(16), NotAfter: store.FormatTime(cert.NotAfter),
			CreatedBy: t.base.ActorType + ":" + t.base.ActorID, CreatedAt: store.Now()}
		if err := t.q.InsertClient(t.ctx, dbq.InsertClientParams{ID: c.ID, Name: c.Name, Role: c.Role, CertSha256: c.CertSha256,
			Serial: c.Serial, NotAfter: c.NotAfter, CreatedBy: c.CreatedBy, CreatedAt: c.CreatedAt}); err != nil {
			return err
		}
		out = apigen.ApiClientIssued{Client: clientAPI(c), CertPem: certPEM, KeyPem: keyPEM, CaPem: string(ca.CertPEM)}
		return t.audit("client.issue", "client", c.Name, nil, out.Client)
	})
	if ok {
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusCreated, out)
	}
}

func (s *Server) GetClient(w http.ResponseWriter, r *http.Request, name apigen.Name) {
	c, err := s.d.Store.Read().GetClientByName(r.Context(), name)
	if isNoRows(err) {
		s.writeError(w, r, notFound("Client", name))
		return
	} else if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, clientAPI(c))
}

func (s *Server) RenewClient(w http.ResponseWriter, r *http.Request, name apigen.Name) {
	var in apigen.ApiClientRenewInput
	if err := decode(r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	var out apigen.ApiClientIssued
	ok := s.mutate(w, r, "client.renew", "client", name, func(t *tx) error {
		old, err := t.q.GetClientByName(t.ctx, name)
		if isNoRows(err) {
			return notFound("Client", name)
		} else if err != nil {
			return err
		}
		if old.Disabled != 0 {
			return errf(http.StatusConflict, "Client %s ist widerrufen und kann nicht erneuert werden", name)
		}
		certPEM, keyPEM, cert, ca, err := s.issue(t, name, in.CsrPem, in.Days)
		if err != nil {
			return err
		}
		c := old
		c.CertSha256, c.Serial, c.NotAfter = pki.Fingerprint(cert), cert.SerialNumber.Text(16), store.FormatTime(cert.NotAfter)
		// Das alte Zertifikat verliert sofort seine Gueltigkeit (Fingerprint ersetzt).
		if err := t.q.UpdateClientCert(t.ctx, dbq.UpdateClientCertParams{CertSha256: c.CertSha256, Serial: c.Serial,
			NotAfter: c.NotAfter, Name: name}); err != nil {
			return err
		}
		out = apigen.ApiClientIssued{Client: clientAPI(c), CertPem: certPEM, KeyPem: keyPEM, CaPem: string(ca.CertPEM)}
		return t.audit("client.renew", "client", name, clientAPI(old), out.Client)
	})
	if ok {
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, out)
	}
}

func (s *Server) DeleteClient(w http.ResponseWriter, r *http.Request, name apigen.Name, params apigen.DeleteClientParams) {
	ok := s.mutate(w, r, "client.revoke", "client", name, func(t *tx) error {
		old, err := t.q.GetClientByName(t.ctx, name)
		if isNoRows(err) {
			return notFound("Client", name)
		} else if err != nil {
			return err
		}
		if flag(params.Purge) {
			if _, err := t.q.DeleteClient(t.ctx, name); err != nil {
				return err
			}
			return t.audit("client.purge", "client", name, clientAPI(old), nil)
		}
		if _, err := t.q.DisableClient(t.ctx, name); err != nil {
			return err
		}
		c := old
		c.Disabled = 1
		return t.audit("client.revoke", "client", name, clientAPI(old), clientAPI(c))
	})
	if ok {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) GetCa(w http.ResponseWriter, r *http.Request) {
	row, err := s.d.Store.Read().GetPki(r.Context())
	if isNoRows(err) {
		s.writeError(w, r, errf(http.StatusConflict, "API-CA ist noch nicht initialisiert (Dienst einmal starten)"))
		return
	} else if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, apigen.Ca{CaPem: row.CaCertPem})
}

// ── Tokens (optional, NRP_API_TOKENS_ENABLED) ───────────────────────────────

func tokenAPI(t dbq.ApiToken) apigen.Token {
	return apigen.Token{Id: t.ID, Name: t.Name, Role: apigen.Role(t.Role), ExpiresAt: store.ParseTime(t.ExpiresAt),
		Disabled: t.Disabled != 0, CreatedBy: t.CreatedBy, CreatedAt: store.ParseTime(t.CreatedAt), LastUsedAt: timePtr(t.LastUsedAt)}
}

func (s *Server) tokensEnabled(w http.ResponseWriter, r *http.Request) bool {
	if s.d.Cfg.TokensEnabled {
		return true
	}
	s.writeError(w, r, errf(http.StatusConflict, "API-Tokens sind deaktiviert (NRP_API_TOKENS_ENABLED=true setzen)"))
	return false
}

func (s *Server) ListTokens(w http.ResponseWriter, r *http.Request) {
	if !s.tokensEnabled(w, r) {
		return
	}
	rows, err := s.d.Store.Read().ListTokens(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	out := apigen.TokenList{Items: []apigen.Token{}}
	for _, t := range rows {
		out.Items = append(out.Items, tokenAPI(t))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) CreateToken(w http.ResponseWriter, r *http.Request) {
	if !s.tokensEnabled(w, r) {
		return
	}
	var in apigen.TokenInput
	if err := decode(r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	var out apigen.TokenIssued
	ok := s.mutate(w, r, "token.create", "token", in.Name, func(t *tx) error {
		if err := domain.ValidateName(in.Name); err != nil {
			return badRequest(err)
		}
		if !auth.ValidRole(string(in.Role)) {
			return errf(http.StatusBadRequest, "ungueltige Rolle %q", in.Role)
		}
		days := 90
		if in.ExpiresInDays != nil {
			days = *in.ExpiresInDays
		}
		if days < 1 || days > 365 {
			return errf(http.StatusBadRequest, "expires_in_days muss zwischen 1 und 365 liegen")
		}
		id := ulid.Make().String()
		full, hash, err := auth.NewToken(id)
		if err != nil {
			return err
		}
		row := dbq.ApiToken{ID: id, Name: in.Name, Role: string(in.Role), SecretSha256: hash,
			ExpiresAt: store.FormatTime(time.Now().Add(time.Duration(days) * 24 * time.Hour)),
			CreatedBy: t.base.ActorType + ":" + t.base.ActorID, CreatedAt: store.Now()}
		if err := t.q.InsertToken(t.ctx, dbq.InsertTokenParams{ID: row.ID, Name: row.Name, Role: row.Role,
			SecretSha256: row.SecretSha256, ExpiresAt: row.ExpiresAt, CreatedBy: row.CreatedBy, CreatedAt: row.CreatedAt}); err != nil {
			return err
		}
		out = apigen.TokenIssued{Token: tokenAPI(row), Secret: full}
		return t.audit("token.create", "token", id, nil, out.Token)
	})
	if ok {
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusCreated, out)
	}
}

func (s *Server) DeleteToken(w http.ResponseWriter, r *http.Request, id string) {
	if !s.tokensEnabled(w, r) {
		return
	}
	ok := s.mutate(w, r, "token.revoke", "token", id, func(t *tx) error {
		old, err := t.q.GetToken(t.ctx, id)
		if isNoRows(err) {
			return notFound("Token", id)
		} else if err != nil {
			return err
		}
		if _, err := t.q.DisableToken(t.ctx, id); err != nil {
			return err
		}
		return t.audit("token.revoke", "token", id, tokenAPI(old), map[string]any{"disabled": true})
	})
	if ok {
		w.WriteHeader(http.StatusNoContent)
	}
}

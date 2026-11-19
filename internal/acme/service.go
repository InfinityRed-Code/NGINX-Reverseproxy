// Package acme stellt Zertifikate per ACME (HTTP-01) aus, erneuert sie nach ARI
// und legt sie verschluesselt in der Datenbank ab.
package acme

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/audit"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/domain"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/jobs"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/secrets"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store/dbq"
)

type Issued struct {
	ChainPEM string
	KeyPEM   string
}

// Issuer kapselt die ACME-CA (lego; in Tests ein Fake).
type Issuer interface {
	Obtain(ctx context.Context, fqdn string) (*Issued, error)
	Revoke(ctx context.Context, chainPEM string) error
	RenewAt(ctx context.Context, chainPEM string) (*time.Time, error)
}

type Service struct {
	Store  *store.Store
	Box    *secrets.Box
	Issuer Issuer
	Log    *slog.Logger
	// OnChange wird nach geaenderten Zertifikaten aufgerufen (Reconcile).
	OnChange func()
	// Notify weckt den Job-Runner.
	Notify func()
}

// ParseLeaf liest das Blatt-Zertifikat einer PEM-Kette.
func ParseLeaf(chainPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(chainPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("keine PEM-Zertifikatskette")
	}
	return x509.ParseCertificate(block.Bytes)
}

// StoreCertificate validiert Kette und Schluessel und speichert sie (Schluessel verschluesselt).
func StoreCertificate(ctx context.Context, q *dbq.Queries, box *secrets.Box, fqdn, chainPEM, keyPEM, source string, renewAt *time.Time) (*x509.Certificate, error) {
	leaf, err := ParseLeaf(chainPEM)
	if err != nil {
		return nil, err
	}
	if err := leaf.VerifyHostname(fqdn); err != nil {
		return nil, fmt.Errorf("Zertifikat gilt nicht fuer %s: %w", fqdn, err)
	}
	if block, _ := pem.Decode([]byte(keyPEM)); block == nil {
		return nil, errors.New("kein PEM-Schluessel")
	}
	enc, err := box.Seal([]byte(keyPEM))
	if err != nil {
		return nil, err
	}
	issuer := leaf.Issuer.CommonName
	if len(leaf.Issuer.Organization) > 0 {
		issuer = leaf.Issuer.Organization[0]
	}
	var ari *string
	if renewAt != nil {
		s := store.FormatTime(*renewAt)
		ari = &s
	}
	return leaf, q.UpsertCertificate(ctx, dbq.UpsertCertificateParams{
		Fqdn: fqdn, ChainPem: chainPEM, KeyEnc: enc, NotBefore: store.FormatTime(leaf.NotBefore),
		NotAfter: store.FormatTime(leaf.NotAfter), AriRenewAt: ari, Issuer: issuer, Source: source, UpdatedAt: store.Now(),
	})
}

// RenewalTime: ARI-Zeitpunkt, sonst wenn ein Drittel der Laufzeit uebrig ist.
func RenewalTime(c dbq.Certificate) time.Time {
	if c.AriRenewAt != nil {
		if t := store.ParseTime(*c.AriRenewAt); !t.IsZero() {
			return t
		}
	}
	nb, na := store.ParseTime(c.NotBefore), store.ParseTime(c.NotAfter)
	return na.Add(-na.Sub(nb) / 3)
}

func (s *Service) system(ctx context.Context, q *dbq.Queries, action, fqdn string, after any, runErr error) (dbq.AuditLog, error) {
	e := audit.Entry{RequestID: "system", ActorType: audit.ActorSystem, ActorID: "nrpd", Action: action,
		ResourceType: "certificate", ResourceID: fqdn, After: after}
	if runErr != nil {
		e.Result, e.Error = audit.Failed, runErr.Error()
	}
	return audit.Append(ctx, q, e)
}

// HandleIssue bearbeitet cert_issue und cert_renew.
func (s *Service) HandleIssue(ctx context.Context, job dbq.Job) error {
	fqdn := job.Resource
	if _, err := s.Store.Read().GetHost(ctx, fqdn); errors.Is(err, sql.ErrNoRows) {
		return nil // Host wurde inzwischen geloescht
	} else if err != nil {
		return err
	}
	action := "certificate.issue"
	if job.Kind == jobs.CertRenew {
		action = "certificate.renew"
	}
	issued, err := s.Issuer.Obtain(ctx, fqdn)
	if err != nil {
		s.fail(ctx, action, fqdn, err)
		return err
	}
	renewAt, ariErr := s.Issuer.RenewAt(ctx, issued.ChainPEM)
	if ariErr != nil {
		s.Log.Warn("ARI-Abfrage fehlgeschlagen", "fqdn", fqdn, "error", ariErr)
	}
	var row dbq.AuditLog
	err = s.Store.Write(ctx, func(q *dbq.Queries) error {
		leaf, err := StoreCertificate(ctx, q, s.Box, fqdn, issued.ChainPEM, issued.KeyPEM, "acme", renewAt)
		if err != nil {
			return err
		}
		if err := q.SetHostStatus(ctx, dbq.SetHostStatusParams{Status: domain.HostActive, Fqdn: fqdn}); err != nil {
			return err
		}
		row, err = s.system(ctx, q, action, fqdn, map[string]any{"not_after": store.FormatTime(leaf.NotAfter),
			"issuer": leaf.Issuer.CommonName, "serial": leaf.SerialNumber.Text(16)}, nil)
		return err
	})
	if err != nil {
		s.fail(ctx, action, fqdn, err)
		return err
	}
	audit.Emit(row)
	if s.OnChange != nil {
		s.OnChange()
	}
	return nil
}

// fail protokolliert den Fehlschlag; ein Host ohne Zertifikat erhaelt den Status error.
func (s *Service) fail(ctx context.Context, action, fqdn string, runErr error) {
	if ctx.Err() != nil {
		return
	}
	var row dbq.AuditLog
	err := s.Store.Write(ctx, func(q *dbq.Queries) error {
		if _, err := q.GetCertificate(ctx, fqdn); errors.Is(err, sql.ErrNoRows) {
			detail := "ACME: " + runErr.Error()
			if err := q.SetHostStatus(ctx, dbq.SetHostStatusParams{Status: domain.HostError, StatusDetail: &detail, Fqdn: fqdn}); err != nil {
				return err
			}
		}
		var err error
		row, err = s.system(ctx, q, action, fqdn, nil, runErr)
		return err
	})
	if err == nil {
		audit.Emit(row)
	}
}

// HandleRevoke widerruft ein Zertifikat bei der CA und entfernt es.
func (s *Service) HandleRevoke(ctx context.Context, job dbq.Job) error {
	fqdn := job.Resource
	cert, err := s.Store.Read().GetCertificate(ctx, fqdn)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	} else if err != nil {
		return err
	}
	if cert.Source == "acme" {
		if err := s.Issuer.Revoke(ctx, cert.ChainPem); err != nil {
			s.fail(ctx, "certificate.revoke", fqdn, err)
			return err
		}
	}
	var row dbq.AuditLog
	err = s.Store.Write(ctx, func(q *dbq.Queries) error {
		if _, err := q.DeleteCertificate(ctx, fqdn); err != nil {
			return err
		}
		row, err = s.system(ctx, q, "certificate.revoke", fqdn, map[string]any{"source": cert.Source}, nil)
		return err
	})
	if err != nil {
		return err
	}
	audit.Emit(row)
	if s.OnChange != nil {
		s.OnChange()
	}
	return nil
}

// Schedule reiht faellige Erneuerungen und fehlende Ausstellungen ein.
func (s *Service) Schedule(ctx context.Context) error {
	q := s.Store.Read()
	hosts, err := q.ListHosts(ctx)
	if err != nil {
		return err
	}
	queued := false
	for _, h := range hosts {
		kind := ""
		cert, err := q.GetCertificate(ctx, h.Fqdn)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			kind = jobs.CertIssue
		case err != nil:
			return err
		case !time.Now().Before(RenewalTime(cert)):
			kind = jobs.CertRenew
		default:
			continue
		}
		err = s.Store.Write(ctx, func(q *dbq.Queries) error {
			for _, k := range []string{jobs.CertIssue, jobs.CertRenew} {
				if open, err := jobs.HasOpen(ctx, q, k, h.Fqdn); err != nil || open {
					return err
				}
			}
			_, err := jobs.Enqueue(ctx, q, kind, h.Fqdn, "system:nrpd")
			queued = queued || err == nil
			return err
		})
		if err != nil {
			return err
		}
	}
	if queued && s.Notify != nil {
		s.Notify()
	}
	return nil
}

// RefreshARI aktualisiert den vorgeschlagenen Erneuerungszeitpunkt aller ACME-Zertifikate.
func (s *Service) RefreshARI(ctx context.Context) {
	certs, err := s.Store.Read().ListCertificates(ctx)
	if err != nil {
		return
	}
	for _, c := range certs {
		if c.Source != "acme" || ctx.Err() != nil {
			continue
		}
		t, err := s.Issuer.RenewAt(ctx, c.ChainPem)
		if err != nil || t == nil {
			continue
		}
		ts := store.FormatTime(*t)
		if c.AriRenewAt != nil && *c.AriRenewAt == ts {
			continue
		}
		_ = s.Store.Write(ctx, func(q *dbq.Queries) error {
			return q.SetCertificateRenewAt(ctx, dbq.SetCertificateRenewAtParams{AriRenewAt: &ts, Fqdn: c.Fqdn})
		})
	}
}

// Run plant beim Start und danach taeglich (mit Jitter) Erneuerungen ein.
func (s *Service) Run(ctx context.Context) {
	wait := 20 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		s.RefreshARI(ctx)
		if err := s.Schedule(ctx); err != nil && ctx.Err() == nil {
			s.Log.Error("Erneuerungen planen", "error", err)
		}
		_ = s.Store.Write(ctx, func(q *dbq.Queries) error {
			return q.PruneJobs(ctx, pruneBefore())
		})
		wait = 24*time.Hour + time.Duration(rand.Int64N(int64(time.Hour)))
	}
}

func pruneBefore() *string {
	s := store.FormatTime(time.Now().Add(-30 * 24 * time.Hour))
	return &s
}

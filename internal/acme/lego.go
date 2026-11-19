package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/secrets"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store/dbq"
)

// webroot legt HTTP-01-Tokens unter <dir>/.well-known/acme-challenge/ ab. Der
// globale Port-80-Server von nginx liefert sie fuer alle Namen aus.
type webroot struct{ dir string }

func (w webroot) path(token string) string {
	return filepath.Join(w.dir, ".well-known", "acme-challenge", filepath.Base(token))
}

func (w webroot) Present(_, token, keyAuth string) error {
	p := w.path(token)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(keyAuth), 0o644)
}

func (w webroot) CleanUp(_, token, _ string) error {
	err := os.Remove(w.path(token))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

type account struct {
	email string
	reg   *registration.Resource
	key   crypto.PrivateKey
}

func (a *account) GetEmail() string                        { return a.email }
func (a *account) GetRegistration() *registration.Resource { return a.reg }
func (a *account) GetPrivateKey() crypto.PrivateKey        { return a.key }

// LegoIssuer implementiert Issuer mit go-acme/lego. Client und Account werden
// beim ersten Gebrauch erzeugt; der Account-Schluessel liegt verschluesselt in der DB.
type LegoIssuer struct {
	Directory string
	Email     string
	Webroot   string
	CAFile    string
	Store     *store.Store
	Box       *secrets.Box

	mu     sync.Mutex
	client *lego.Client
}

func (l *LegoIssuer) httpClient() (*http.Client, error) {
	if l.CAFile == "" {
		return nil, nil
	}
	pemBytes, err := os.ReadFile(l.CAFile)
	if err != nil {
		return nil, fmt.Errorf("NRP_ACME_CA_FILE: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("NRP_ACME_CA_FILE enthaelt kein Zertifikat")
	}
	return &http.Client{Timeout: 60 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{RootCAs: pool}}}, nil
}

func (l *LegoIssuer) get(ctx context.Context) (*lego.Client, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.client != nil {
		return l.client, nil
	}
	acct := &account{email: l.Email}
	row, err := l.Store.Read().GetAcmeAccount(ctx, l.Directory)
	known := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if known {
		keyPEM, err := l.Box.Open(row.KeyEnc)
		if err != nil {
			return nil, fmt.Errorf("ACME-Account-Schluessel: %w", err)
		}
		if acct.key, err = certcrypto.ParsePEMPrivateKey(keyPEM); err != nil {
			return nil, err
		}
		acct.reg = &registration.Resource{}
		if err := json.Unmarshal([]byte(row.RegJson), acct.reg); err != nil {
			return nil, err
		}
	} else if acct.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return nil, err
	}

	cfg := lego.NewConfig(acct)
	cfg.CADirURL = l.Directory
	cfg.Certificate.KeyType = certcrypto.EC256
	cfg.UserAgent = "nrp"
	if hc, err := l.httpClient(); err != nil {
		return nil, err
	} else if hc != nil {
		cfg.HTTPClient = hc
	}
	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("ACME-Verzeichnis %s: %w", l.Directory, err)
	}
	if err := client.Challenge.SetHTTP01Provider(webroot{l.Webroot}); err != nil {
		return nil, err
	}
	if !known {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("ACME-Registrierung: %w", err)
		}
		acct.reg = reg
		regJSON, _ := json.Marshal(reg)
		enc, err := l.Box.Seal(certcrypto.PEMEncode(acct.key))
		if err != nil {
			return nil, err
		}
		var email *string
		if l.Email != "" {
			email = &l.Email
		}
		if err := l.Store.Write(ctx, func(q *dbq.Queries) error {
			return q.UpsertAcmeAccount(ctx, dbq.UpsertAcmeAccountParams{Directory: l.Directory, Email: email,
				KeyEnc: enc, RegJson: string(regJSON), CreatedAt: store.Now()})
		}); err != nil {
			return nil, err
		}
	}
	l.client = client
	return client, nil
}

func (l *LegoIssuer) Obtain(ctx context.Context, fqdn string) (*Issued, error) {
	c, err := l.get(ctx)
	if err != nil {
		return nil, err
	}
	res, err := c.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{fqdn}, Bundle: true})
	if err != nil {
		return nil, err
	}
	return &Issued{ChainPEM: string(res.Certificate), KeyPEM: string(res.PrivateKey)}, nil
}

func (l *LegoIssuer) Revoke(ctx context.Context, chainPEM string) error {
	c, err := l.get(ctx)
	if err != nil {
		return err
	}
	return c.Certificate.Revoke([]byte(chainPEM))
}

// RenewAt fragt ACME Renewal Information ab. nil = die CA bietet kein ARI.
func (l *LegoIssuer) RenewAt(ctx context.Context, chainPEM string) (*time.Time, error) {
	c, err := l.get(ctx)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(chainPEM))
	if block == nil {
		return nil, errors.New("Kette nicht lesbar")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	info, err := c.Certificate.GetRenewalInfo(certificate.RenewalInfoRequest{Cert: leaf})
	if err != nil {
		if errors.Is(err, api.ErrNoARI) {
			return nil, nil
		}
		return nil, err
	}
	// Mitte des vorgeschlagenen Fensters: stabil ueber wiederholte Abfragen.
	w := info.SuggestedWindow
	if w.Start.IsZero() || w.End.IsZero() {
		return nil, nil
	}
	t := w.Start.Add(w.End.Sub(w.Start) / 2)
	return &t, nil
}

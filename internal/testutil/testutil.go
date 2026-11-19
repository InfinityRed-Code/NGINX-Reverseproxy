// Package testutil stellt Bausteine fuer Tests bereit (Store, Master-Key, Zertifikate).
package testutil

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/audit"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/secrets"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store"
)

// Store liefert eine migrierte Datenbank in einem temporaeren Verzeichnis.
func Store(t testing.TB) *store.Store {
	t.Helper()
	audit.Output = io.Discard
	st, err := store.Open(filepath.Join(t.TempDir(), "db", "nrp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return st
}

func Box(t testing.TB) *secrets.Box {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	b, err := secrets.New(key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// SelfSigned erzeugt ein selbstsigniertes Zertifikat fuer fqdn (Kette und Schluessel als PEM).
func SelfSigned(t testing.TB, fqdn string, notAfter time.Time) (chainPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sn, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: fqdn, Organization: []string{"NRP Test"}}, DNSNames: []string{fqdn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}))
}

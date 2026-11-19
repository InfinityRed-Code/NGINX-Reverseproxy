// Package pki implementiert die interne CA fuer die mTLS-API (ECDSA P-256).
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"slices"
	"sort"
	"time"
)

const (
	caValidity     = 10 * 365 * 24 * time.Hour
	serverValidity = 397 * 24 * time.Hour
	renewBefore    = 30 * 24 * time.Hour
)

type CA struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM []byte
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func encodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func encodeKey(k *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseCert liest das erste Zertifikat aus einem PEM-Block.
func ParseCert(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("kein PEM-Zertifikat")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseKey(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("kein PEM-Schluessel")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("CA-Schluessel ist kein ECDSA-Schluessel")
	}
	return ec, nil
}

// NewCA erzeugt eine neue CA und liefert Zertifikat und Schluessel als PEM.
func NewCA() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: "NRP API CA", Organization: []string{"NRP"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(caValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = encodeKey(key)
	return encodeCert(der), keyPEM, err
}

func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cert, err := ParseCert(certPEM)
	if err != nil {
		return nil, fmt.Errorf("CA-Zertifikat: %w", err)
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("CA-Schluessel: %w", err)
	}
	return &CA{Cert: cert, Key: key, CertPEM: certPEM}, nil
}

func (ca *CA) sign(tpl *x509.Certificate, pub any) ([]byte, *x509.Certificate, error) {
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	tpl.SerialNumber = sn
	tpl.NotBefore = time.Now().Add(-5 * time.Minute)
	tpl.BasicConstraintsValid = true
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return encodeCert(der), cert, err
}

func splitSANs(sans []string) (dns []string, ips []net.IP) {
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		} else if s != "" {
			dns = append(dns, s)
		}
	}
	return
}

// IssueServer stellt das Server-Zertifikat der API aus.
func (ca *CA) IssueServer(sans []string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	dns, ips := splitSANs(sans)
	tpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "nrp-api"},
		NotAfter:    time.Now().Add(serverValidity),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    dns,
		IPAddresses: ips,
	}
	certPEM, _, err = ca.sign(tpl, &key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = encodeKey(key)
	return certPEM, keyPEM, err
}

// ServerNeedsReissue prueft Restlaufzeit und SANs des Server-Zertifikats.
func ServerNeedsReissue(certPEM []byte, sans []string) bool {
	cert, err := ParseCert(certPEM)
	if err != nil || time.Until(cert.NotAfter) < renewBefore {
		return true
	}
	var have []string
	have = append(have, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		have = append(have, ip.String())
	}
	dns, ips := splitSANs(sans)
	want := append([]string{}, dns...)
	for _, ip := range ips {
		want = append(want, ip.String())
	}
	sort.Strings(have)
	sort.Strings(want)
	return !slices.Equal(have, slices.Compact(want))
}

func clientTemplate(name string, days int) *x509.Certificate {
	return &x509.Certificate{
		Subject:     pkix.Name{CommonName: name},
		NotAfter:    time.Now().Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

// IssueClient erzeugt Schluesselpaar und Client-Zertifikat serverseitig.
func (ca *CA) IssueClient(name string, days int) (certPEM, keyPEM []byte, cert *x509.Certificate, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	certPEM, cert, err = ca.sign(clientTemplate(name, days), &key.PublicKey)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPEM, err = encodeKey(key)
	return certPEM, keyPEM, cert, err
}

// SignClientCSR signiert einen CSR. Subject und Erweiterungen des CSR werden
// ignoriert; die Identitaet haengt allein am Fingerprint in api_clients.
func (ca *CA) SignClientCSR(name string, csrPEM []byte, days int) (certPEM []byte, cert *x509.Certificate, err error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || (block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST") {
		return nil, nil, errors.New("kein PEM-CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("CSR-Signatur: %w", err)
	}
	switch pub := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
	case interface{ Size() int }: // *rsa.PublicKey
		if pub.Size() < 256 {
			return nil, nil, errors.New("RSA-Schluessel im CSR muss mindestens 2048 Bit haben")
		}
	}
	return ca.sign(clientTemplate(name, days), csr.PublicKey)
}

// Fingerprint ist der SHA-256 ueber das DER-kodierte Zertifikat (hex).
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

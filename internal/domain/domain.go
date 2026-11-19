// Package domain enthaelt die Fachtypen und die Eingabevalidierung
// (Port von legacy/v2/nrp/core/validation.py, verschaerft).
package domain

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

type HSTS struct {
	MaxAge            int64 `json:"max_age"`
	IncludeSubdomains bool  `json:"include_subdomains"`
	Preload           bool  `json:"preload"`
}

// Settings sind die globalen Defaults aus der Tabelle settings.
type Settings struct {
	ClientMaxBodySize string
	HSTS              HSTS
	WAFMode           string
	WAFOverrides      string
	ACMEEmail         string
}

func DefaultSettings() Settings {
	return Settings{
		ClientMaxBodySize: "100M",
		HSTS:              HSTS{MaxAge: 31536000, IncludeSubdomains: true, Preload: false},
		WAFMode:           "DetectionOnly",
	}
}

const (
	KeyClientMaxBodySize = "defaults.client_max_body_size"
	KeyHSTS              = "defaults.hsts"
	KeyWAFMode           = "waf.mode"
	KeyWAFOverrides      = "waf.overrides"
	KeyACMEEmail         = "acme.email"
)

const (
	HostPending = "pending_certificate"
	HostActive  = "active"
	HostError   = "error"
)

var (
	fqdnRe     = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	hostnameRe = regexp.MustCompile(`^(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?))*$`)
	numericRe  = regexp.MustCompile(`^[0-9.]+$`)
	bodySizeRe = regexp.MustCompile(`^[0-9]{1,12}[kKmMgG]?$`)
	siteNameRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$`)
	nameRe     = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._@-]{0,62}[A-Za-z0-9])?$`)
	emailRe    = regexp.MustCompile(`^[^\s@<>"']+@[^\s@<>"']+\.[^\s@<>"']+$`)
)

// NormalizeFQDN liefert den Namen in Kleinbuchstaben ohne abschliessenden Punkt.
func NormalizeFQDN(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

func ValidateFQDN(fqdn string) error {
	if len(fqdn) > 253 || !fqdnRe.MatchString(fqdn) {
		return fmt.Errorf("ungueltiger FQDN %q", fqdn)
	}
	return nil
}

// ValidateUpstreamAddress akzeptiert IPv4, IPv6 oder einen Hostnamen. Der Wert
// landet in proxy_pass und darf deshalb keine Sonderzeichen enthalten.
func ValidateUpstreamAddress(addr string) error {
	if _, err := netip.ParseAddr(addr); err == nil && !strings.Contains(addr, "%") {
		return nil
	}
	if numericRe.MatchString(addr) {
		return fmt.Errorf("ungueltige IP-Adresse %q", addr)
	}
	if len(addr) <= 253 && hostnameRe.MatchString(addr) {
		return nil
	}
	return fmt.Errorf("ungueltige Upstream-Adresse %q (IP oder Hostname erwartet)", addr)
}

// UpstreamHost formatiert die Adresse fuer eine URL (IPv6 in eckigen Klammern).
func UpstreamHost(addr string) string {
	if ip, err := netip.ParseAddr(addr); err == nil && ip.Is6() {
		return "[" + addr + "]"
	}
	return addr
}

func ValidatePort(p int) error {
	if p < 1 || p > 65535 {
		return fmt.Errorf("ungueltiger Port %d (1-65535)", p)
	}
	return nil
}

// ReservedExternalPorts sind Ports, die NRP selbst belegt.
func ValidateExternalPort(p int) error {
	if err := ValidatePort(p); err != nil {
		return err
	}
	if p == 80 || p == 8443 {
		return fmt.Errorf("externer Port %d ist reserviert", p)
	}
	return nil
}

func ValidateScheme(s string) error {
	if s != "http" && s != "https" {
		return fmt.Errorf("ungueltiges Schema %q (http oder https)", s)
	}
	return nil
}

func ValidateBodySize(s string) error {
	if !bodySizeRe.MatchString(s) {
		return fmt.Errorf("ungueltige Groesse %q (z. B. 100M)", s)
	}
	return nil
}

func ValidateSiteName(s string) error {
	if !siteNameRe.MatchString(s) {
		return fmt.Errorf("ungueltiger Site-Name %q (a-z, 0-9, '-', max. 32 Zeichen)", s)
	}
	return nil
}

// ValidateName prueft Client- und Token-Namen.
func ValidateName(s string) error {
	if !nameRe.MatchString(s) {
		return fmt.Errorf("ungueltiger Name %q", s)
	}
	return nil
}

func ValidateEmail(s string) error {
	if len(s) > 254 || !emailRe.MatchString(s) {
		return fmt.Errorf("ungueltige E-Mail-Adresse %q", s)
	}
	return nil
}

func ValidateHSTS(h HSTS) error {
	if h.MaxAge < 0 {
		return fmt.Errorf("hsts.max_age darf nicht negativ sein")
	}
	if h.Preload && (h.MaxAge < 31536000 || !h.IncludeSubdomains) {
		return fmt.Errorf("hsts.preload erfordert max_age >= 31536000 und include_subdomains")
	}
	return nil
}

// NormalizeWAFMode akzeptiert die API-Schreibweise und die CLI-Kurzformen.
func NormalizeWAFMode(s string) (string, error) {
	switch strings.ToLower(strings.ReplaceAll(s, "-", "")) {
	case "on":
		return "On", nil
	case "detectiononly":
		return "DetectionOnly", nil
	case "off":
		return "Off", nil
	}
	return "", fmt.Errorf("ungueltiger WAF-Modus %q (On, DetectionOnly, Off)", s)
}

// ValidateCIDR prueft ein IPv4-Netz in kanonischer Form.
func ValidateCIDR(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("ungueltiges IPv4-Netz %q", s)
	}
	return p.Masked(), nil
}

// AddressInSubnets prueft, ob addr eine IP in einem der Netze ist.
func AddressInSubnets(addr string, cidrs ...string) bool {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil && p.Contains(ip) {
			return true
		}
	}
	return false
}

// Package render erzeugt aus dem DB-Zustand die nginx- und Coraza-Konfiguration
// einer Generation. Rendering ist eine reine Funktion (Golden-File-Tests).
package render

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"text/template"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/domain"
)

//go:embed templates/*.tmpl
var templatesFS embed.FS

var tmpl = template.Must(template.ParseFS(templatesFS, "templates/*.tmpl"))

// GenPlaceholder steht in gerenderten Dateien fuer das Generationsverzeichnis.
// Der Inhalts-Hash wird mit Platzhalter berechnet und ist damit unabhaengig
// von der Generationsnummer; beim Schreiben wird der echte Pfad eingesetzt.
const GenPlaceholder = "@NRP_GEN_DIR@"

// AfterRulesMarker trennt in den WAF-Overrides den Teil vor den CRS-Regeln
// (z. B. Paranoia Level) vom Teil danach (z. B. SecRuleRemoveById).
const AfterRulesMarker = "# nrp:after-rules"

type Host struct {
	FQDN              string
	Scheme            string
	Address           string
	Port              int
	ExternalPort      int
	Websockets        bool
	WAF               bool
	ClientMaxBodySize string
	HSTS              domain.HSTS
	// CertFingerprint leer = kein Zertifikat; der Host wird dann nicht gerendert
	// (ACME laeuft ueber den globalen Port-80-Server).
	CertFingerprint string
}

type Paths struct {
	CertsDir       string
	AcmeDir        string
	HTMLDir        string
	CRSDir         string
	CorazaAuditLog string
}

type Input struct {
	Hosts        []Host
	WAFMode      string
	WAFOverrides string
	// CRSSetup ist der Inhalt von crs-setup.conf.example aus dem Image.
	CRSSetup string
	Paths    Paths
}

type common struct {
	Paths
	GenDir   string
	WAFMode  string
	TLSPorts []int
}

type hostData struct {
	Host
	common
	UpstreamHost string
}

func exec(name string, data any) (string, error) {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		return "", fmt.Errorf("Template %s: %w", name, err)
	}
	return buf.String(), nil
}

// Render liefert relative Dateipfade (mit '/') und Inhalte einer Generation.
func Render(in Input) (map[string]string, error) {
	mode, err := domain.NormalizeWAFMode(in.WAFMode)
	if err != nil {
		return nil, err
	}
	hosts := append([]Host(nil), in.Hosts...)
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].FQDN < hosts[j].FQDN })

	ports := map[int]bool{443: true}
	for _, h := range hosts {
		if h.CertFingerprint != "" {
			ports[h.ExternalPort] = true
		}
	}
	c := common{Paths: in.Paths, GenDir: GenPlaceholder, WAFMode: mode}
	for p := range ports {
		c.TLSPorts = append(c.TLSPorts, p)
	}
	sort.Ints(c.TLSPorts)

	files := map[string]string{}
	for name, path := range map[string]string{
		"00-acme-and-catchall.conf": "http.d/00-acme-and-catchall.conf",
		"10-ssl-params.conf":        "http.d/10-ssl-params.conf",
		"coraza.conf":               "coraza/coraza.conf",
		"main.conf":                 "coraza/main.conf",
	} {
		if files[path], err = exec(name, c); err != nil {
			return nil, err
		}
	}
	before, after, _ := strings.Cut(in.WAFOverrides, AfterRulesMarker)
	files["coraza/crs-setup.conf"] = in.CRSSetup
	files["coraza/crs-overrides.conf"] = "# NRP v3 - eigene Anpassungen vor den CRS-Regeln ('nrp waf rules set').\n" + ensureNL(before)
	files["coraza/crs-overrides-after.conf"] = "# NRP v3 - eigene Anpassungen nach den CRS-Regeln.\n" + ensureNL(after)

	for _, h := range hosts {
		if h.CertFingerprint == "" {
			continue
		}
		if err := validateHost(h); err != nil {
			return nil, err
		}
		d := hostData{Host: h, common: c, UpstreamHost: domain.UpstreamHost(h.Address)}
		if files["http.d/host-"+h.FQDN+".conf"], err = exec("host", d); err != nil {
			return nil, err
		}
		if files["snippets/hsts-"+h.FQDN+".conf"], err = exec("hsts", d); err != nil {
			return nil, err
		}
	}
	return files, nil
}

func ensureNL(s string) string {
	s = strings.TrimLeft(s, "\r\n")
	if s != "" && !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	return s
}

// validateHost ist die letzte Verteidigungslinie vor dem Template: nichts, was
// nicht validiert ist, darf in eine nginx-Datei oder einen Dateinamen gelangen.
func validateHost(h Host) error {
	if err := domain.ValidateFQDN(h.FQDN); err != nil {
		return err
	}
	if err := domain.ValidateUpstreamAddress(h.Address); err != nil {
		return fmt.Errorf("%s: %w", h.FQDN, err)
	}
	if err := domain.ValidateScheme(h.Scheme); err != nil {
		return fmt.Errorf("%s: %w", h.FQDN, err)
	}
	if err := domain.ValidateBodySize(h.ClientMaxBodySize); err != nil {
		return fmt.Errorf("%s: %w", h.FQDN, err)
	}
	if err := domain.ValidatePort(h.Port); err != nil {
		return fmt.Errorf("%s: %w", h.FQDN, err)
	}
	return domain.ValidateExternalPort(h.ExternalPort)
}

// Hash ist der Inhalts-Hash einer Generation (Pfade und Inhalte, sortiert).
func Hash(files map[string]string) string {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		fmt.Fprintf(h, "%d:%s\n%d:", len(n), n, len(files[n]))
		h.Write([]byte(files[n]))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Materialize setzt das Generationsverzeichnis in alle Dateien ein.
func Materialize(files map[string]string, genDir string) map[string]string {
	out := make(map[string]string, len(files))
	for n, c := range files {
		out[n] = strings.ReplaceAll(c, GenPlaceholder, genDir)
	}
	return out
}

// Package cli enthaelt die cobra-Befehle. Ein Binary, drei Client-Modi:
// lokal (Unix-Socket), remote (mTLS-API) und offline (direkt auf SQLite).
// Alle Modi nutzen denselben generierten API-Client und dieselben Handler.
package cli

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/apigen"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/config"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/server"
)

type app struct {
	version string
	cfg     config.Config
	out     io.Writer
	errOut  io.Writer
	in      io.Reader

	offline bool
	server  string
	cert    string
	key     string
	ca      string
	token   string
	profile string
	output  string

	client  *apigen.Client
	cleanup []func()
}

type profile struct {
	Server string `yaml:"server"`
	Cert   string `yaml:"cert"`
	Key    string `yaml:"key"`
	CA     string `yaml:"ca"`
	Token  string `yaml:"token"`
}

type profileFile struct {
	Current  string             `yaml:"current"`
	Profiles map[string]profile `yaml:"profiles"`
}

// Execute fuehrt die CLI aus und liefert den Exit-Code.
func Execute(version string) int {
	a := &app{version: version, cfg: config.Load(), out: os.Stdout, errOut: os.Stderr, in: os.Stdin}
	root := a.rootCmd()
	err := root.Execute()
	for i := len(a.cleanup) - 1; i >= 0; i-- {
		a.cleanup[i]()
	}
	if err != nil {
		var ee exitError
		if errors.As(err, &ee) {
			return int(ee)
		}
		fmt.Fprintln(a.errOut, "Fehler:", err)
		return 1
	}
	return 0
}

// exitError beendet ohne weitere Meldung mit dem gegebenen Code.
type exitError int

func (e exitError) Error() string { return fmt.Sprintf("exit %d", int(e)) }

func (a *app) rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "nrp",
		Short:         "NRP - NGINX Reverse Proxy (Container, REST-API, SQLite)",
		Long:          "NRP verwaltet nginx, Zertifikate, Coraza-WAF und WireGuard-Sites.\n\nIm Container: docker exec -it nrp nrp <befehl>\nRemote:       nrp --server https://proxy:8443 --cert c.crt --key c.key --ca nrp-ca.crt <befehl>\nNotfall:      docker exec -it nrp nrp --offline <befehl>",
		Version:       a.version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	pf := root.PersistentFlags()
	pf.BoolVar(&a.offline, "offline", false, "Notfallmodus: direkt auf der Datenbank arbeiten (nur wenn der Dienst nicht laeuft)")
	pf.StringVar(&a.server, "server", os.Getenv("NRP_SERVER"), "URL der API, z. B. https://proxy:8443 (Standard: lokaler Socket)")
	pf.StringVar(&a.cert, "cert", os.Getenv("NRP_CERT"), "Client-Zertifikat (PEM) fuer --server")
	pf.StringVar(&a.key, "key", os.Getenv("NRP_KEY"), "Client-Schluessel (PEM) fuer --server")
	pf.StringVar(&a.ca, "ca", os.Getenv("NRP_CA"), "CA-Zertifikat der NRP-API (nrp ca show)")
	pf.StringVar(&a.token, "token", os.Getenv("NRP_TOKEN"), "API-Token statt Client-Zertifikat (Token-Listener)")
	pf.StringVar(&a.profile, "profile", os.Getenv("NRP_PROFILE"), "Profil aus ~/.config/nrp/config.yaml")
	pf.StringVarP(&a.output, "output", "o", "table", "Ausgabeformat: table, json oder yaml")

	root.AddCommand(a.serveCmd(), a.healthCmd(), a.doctorCmd(), a.hostCmd(), a.listAliasCmd(), a.certCmd(), a.siteCmd(),
		a.wafCmd(), a.settingsCmd(), a.statusCmd(), a.jobCmd(), a.auditCmd(), a.renderCmd(), a.clientCmd(),
		a.tokenCmd(), a.caCmd(), a.backupCmd(), a.exportCmd(), a.applyCmd(), a.importCmd())
	return root
}

// ── Verbindung ──────────────────────────────────────────────────────────────

func (a *app) loadProfile() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(home, ".config", "nrp", "config.yaml"))
	if err != nil {
		if a.profile != "" {
			return fmt.Errorf("Profil %q: %w", a.profile, err)
		}
		return nil
	}
	var pf profileFile
	if err := yaml.Unmarshal(raw, &pf); err != nil {
		return fmt.Errorf("config.yaml: %w", err)
	}
	name := a.profile
	if name == "" {
		name = pf.Current
	}
	if name == "" {
		return nil
	}
	p, ok := pf.Profiles[name]
	if !ok {
		return fmt.Errorf("Profil %q nicht in config.yaml", name)
	}
	for dst, src := range map[*string]string{&a.server: p.Server, &a.cert: p.Cert, &a.key: p.Key, &a.ca: p.CA, &a.token: p.Token} {
		if *dst == "" {
			*dst = src
		}
	}
	return nil
}

func (a *app) remoteClient() (*http.Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS13}
	if a.ca != "" {
		pemBytes, err := os.ReadFile(a.ca)
		if err != nil {
			return nil, fmt.Errorf("--ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("--ca enthaelt kein Zertifikat")
		}
		tc.RootCAs = pool
	}
	if a.cert != "" || a.key != "" {
		pair, err := tls.LoadX509KeyPair(a.cert, a.key)
		if err != nil {
			return nil, fmt.Errorf("--cert/--key: %w", err)
		}
		tc.Certificates = []tls.Certificate{pair}
	} else if a.token == "" {
		return nil, errors.New("--server benoetigt --cert/--key oder --token")
	}
	return &http.Client{Timeout: 5 * time.Minute, Transport: &http.Transport{TLSClientConfig: tc}}, nil
}

// api liefert den Client fuer den gewaehlten Modus.
func (a *app) api() (*apigen.Client, error) {
	if a.client != nil {
		return a.client, nil
	}
	var hc *http.Client
	base := "http://nrp" + server.BasePath
	var opts []apigen.ClientOption
	switch {
	case a.offline:
		rt, err := a.offlineTransport()
		if err != nil {
			return nil, err
		}
		hc = &http.Client{Transport: rt}
	default:
		if a.server == "" {
			if err := a.loadProfile(); err != nil {
				return nil, err
			}
		}
		if a.server != "" {
			var err error
			if hc, err = a.remoteClient(); err != nil {
				return nil, err
			}
			base = strings.TrimRight(a.server, "/") + server.BasePath
			if a.token != "" {
				opts = append(opts, apigen.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
					req.Header.Set("Authorization", "Bearer "+a.token)
					return nil
				}))
			}
			break
		}
		sock := a.cfg.SocketPath()
		if _, err := os.Stat(sock); err != nil {
			return nil, fmt.Errorf("Dienst nicht erreichbar (%s fehlt). Laeuft nrpd? Notfall: nrp --offline ..., remote: --server", sock)
		}
		hc = &http.Client{Timeout: 5 * time.Minute, Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			}}}
	}
	c, err := apigen.NewClient(base, append(opts, apigen.WithHTTPClient(hc))...)
	a.client = c
	return c, err
}

// ── Aufruf und Ausgabe ──────────────────────────────────────────────────────

type apiErr struct {
	Status int
	Detail string
}

func (e *apiErr) Error() string { return fmt.Sprintf("%s (HTTP %d)", e.Detail, e.Status) }

func readResp(resp *http.Response, err error) ([]byte, http.Header, error) {
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode >= 400 {
		var p apigen.Problem
		detail := strings.TrimSpace(string(body))
		if json.Unmarshal(body, &p) == nil && p.Detail != nil {
			detail = *p.Detail
		}
		if detail == "" {
			detail = resp.Status
		}
		return nil, resp.Header, &apiErr{Status: resp.StatusCode, Detail: detail}
	}
	return body, resp.Header, nil
}

// do dekodiert eine JSON-Antwort; bei 204 bleibt das Ergebnis leer.
func do[T any](resp *http.Response, err error) (*T, http.Header, error) {
	body, hdr, err := readResp(resp, err)
	if err != nil {
		return nil, hdr, err
	}
	var v T
	if len(body) > 0 {
		if err := json.Unmarshal(body, &v); err != nil {
			return nil, hdr, fmt.Errorf("Antwort nicht lesbar: %w", err)
		}
	}
	return &v, hdr, nil
}

func isNotFound(err error) bool {
	var ae *apiErr
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// print gibt v als JSON/YAML aus oder ruft table fuer die Tabellenform.
func (a *app) print(v any, table func(w *tabwriter.Writer)) error {
	switch strings.ToLower(a.output) {
	case "json":
		enc := json.NewEncoder(a.out)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	case "yaml", "yml":
		return a.printYAML(v)
	case "table", "":
		w := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
		table(w)
		return w.Flush()
	}
	return fmt.Errorf("unbekanntes Ausgabeformat %q (table, json, yaml)", a.output)
}

func (a *app) printYAML(v any) error {
	raw, err := json.Marshal(v) // ueber JSON, damit die API-Feldnamen gelten
	if err != nil {
		return err
	}
	var generic any
	if err := yaml.Unmarshal(raw, &generic); err != nil {
		return err
	}
	enc := yaml.NewEncoder(a.out)
	enc.SetIndent(2)
	defer enc.Close()
	return enc.Encode(generic)
}

func (a *app) isTTY() bool {
	f, ok := a.in.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// prompt fragt interaktiv; ohne TTY ist ein fehlender Pflichtwert ein Fehler.
func (a *app) prompt(label, def string) (string, error) {
	if !a.isTTY() {
		return "", fmt.Errorf("%s fehlt (kein TTY fuer interaktive Abfrage; -it verwenden oder Flag setzen)", label)
	}
	if def != "" {
		fmt.Fprintf(a.errOut, "%s [%s]: ", label, def)
	} else {
		fmt.Fprintf(a.errOut, "%s: ", label)
	}
	line, err := bufio.NewReader(a.in).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	if line = strings.TrimSpace(line); line == "" {
		return def, nil
	}
	return line, nil
}

func (a *app) confirm(question string, yes bool) error {
	if yes {
		return nil
	}
	ans, err := a.prompt(question+" (j/N)", "n")
	if err != nil {
		return fmt.Errorf("%w; mit --yes bestaetigen", err)
	}
	if s := strings.ToLower(ans); s != "j" && s != "ja" && s != "y" && s != "yes" {
		return errors.New("abgebrochen")
	}
	return nil
}

func deref[T any](p *T) (v T) {
	if p != nil {
		v = *p
	}
	return v
}

func str(p *string, def string) string {
	if p == nil || *p == "" {
		return def
	}
	return *p
}

func ts(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04")
}

func yesNo(b bool) string {
	if b {
		return "ja"
	}
	return "nein"
}

func ptr[T any](v T) *T { return &v }

func ctxOf(cmd *cobra.Command) context.Context { return cmd.Context() }

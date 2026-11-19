package render

import (
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/domain"
)

var update = flag.Bool("update", false, "Golden Files neu schreiben")

var paths = Paths{CertsDir: "/run/nrp/certs", AcmeDir: "/run/nrp/acme", HTMLDir: "/usr/share/nrp/html",
	CRSDir: "/usr/share/nrp/coreruleset", CorazaAuditLog: "/var/log/nrp/coraza/audit.log"}

var defHSTS = domain.HSTS{MaxAge: 31536000, IncludeSubdomains: true}

func host(fqdn string, mod func(*Host)) Host {
	h := Host{FQDN: fqdn, Scheme: "http", Address: "192.168.1.10", Port: 8080, ExternalPort: 443,
		ClientMaxBodySize: "100M", HSTS: defHSTS, CertFingerprint: "aa11"}
	if mod != nil {
		mod(&h)
	}
	return h
}

// Jede Template-Variante: 443/Custom-Port, WS an/aus, WAF an/aus, Site-Upstream.
var scenarios = map[string]Input{
	"empty":    {WAFMode: "DetectionOnly", Paths: paths},
	"standard": {WAFMode: "DetectionOnly", Paths: paths, Hosts: []Host{host("app.example.com", nil)}},
	"variants": {WAFMode: "On", Paths: paths, CRSSetup: "# crs-setup aus dem Image\n",
		WAFOverrides: "SecAction \"id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=2\"\n# nrp:after-rules\nSecRuleRemoveById 920350\n",
		Hosts: []Host{
			host("ws.example.com", func(h *Host) { h.Websockets = true }),
			host("waf.example.com", func(h *Host) { h.WAF = true }),
			host("custom.example.com", func(h *Host) { h.ExternalPort = 8444; h.Websockets = true; h.WAF = true }),
			host("site.example.com", func(h *Host) { h.Scheme = "https"; h.Address = "10.240.0.18"; h.Port = 443 }),
			host("v6.example.com", func(h *Host) { h.Address = "fd00::10" }),
			host("tuned.example.com", func(h *Host) {
				h.ClientMaxBodySize = "2g"
				h.HSTS = domain.HSTS{MaxAge: 63072000, IncludeSubdomains: true, Preload: true}
			}),
			host("nohsts-sub.example.com", func(h *Host) { h.HSTS = domain.HSTS{MaxAge: 300} }),
			host("pending.example.com", func(h *Host) { h.CertFingerprint = "" }),
		}},
}

func flatten(files map[string]string) string {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString("##### " + n + " #####\n" + files[n])
		if !strings.HasSuffix(files[n], "\n") {
			b.WriteString("\n")
		}
	}
	return b.String()
}

func TestGolden(t *testing.T) {
	for name, in := range scenarios {
		t.Run(name, func(t *testing.T) {
			files, err := Render(in)
			if err != nil {
				t.Fatal(err)
			}
			got := flatten(files)
			golden := filepath.Join("testdata", name+".golden")
			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (mit 'go test ./internal/render -update' erzeugen)", err)
			}
			if strings.ReplaceAll(string(want), "\r\n", "\n") != got {
				t.Errorf("%s weicht ab; mit -update neu schreiben und den Diff pruefen.\n--- erhalten ---\n%s", golden, got)
			}
		})
	}
}

func TestRenderProperties(t *testing.T) {
	files, err := Render(scenarios["variants"])
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files["http.d/host-pending.example.com.conf"]; ok {
		t.Error("Host ohne Zertifikat darf nicht gerendert werden")
	}
	ws := files["http.d/host-ws.example.com.conf"]
	if !strings.Contains(ws, "proxy_set_header Connection $connection_upgrade;") || strings.Contains(ws, "$http_connection") {
		t.Error("WebSocket-Header muss $connection_upgrade nutzen")
	}
	std := files["http.d/host-waf.example.com.conf"]
	for _, want := range []string{"http2 on;", "listen [::]:443 ssl;", "proxy_http_version 1.1;", "coraza on;",
		"coraza_rules_file " + GenPlaceholder + "/coraza/main.conf;", "proxy_set_header X-Forwarded-For $remote_addr;"} {
		if !strings.Contains(std, want) {
			t.Errorf("Host-Config enthaelt %q nicht", want)
		}
	}
	if strings.Contains(std, "Upgrade") || strings.Contains(std, "ssl_dhparam") {
		t.Error("ohne WebSockets kein Upgrade-Header; kein ssl_dhparam in v3")
	}
	custom := files["http.d/host-custom.example.com.conf"]
	if !strings.Contains(custom, "error_page 497 =301 https://$host:8444$request_uri;") || !strings.Contains(custom, "return 301 https://$host:8444$request_uri;") {
		t.Error("Custom-Port: 497-Umleitung bzw. Port-80-Redirect fehlt")
	}
	if !strings.Contains(files["http.d/host-v6.example.com.conf"], "proxy_pass http://[fd00::10]:8080/;") {
		t.Error("IPv6-Upstream muss in eckigen Klammern stehen")
	}
	catchall := files["http.d/00-acme-and-catchall.conf"]
	for _, want := range []string{"listen 443 ssl default_server;", "listen 8444 ssl default_server;", "ssl_reject_handshake on;", "/.well-known/acme-challenge/"} {
		if !strings.Contains(catchall, want) {
			t.Errorf("Catch-All enthaelt %q nicht", want)
		}
	}
	if h := files["snippets/hsts-tuned.example.com.conf"]; !strings.Contains(h, `"max-age=63072000; includeSubDomains; preload"`) {
		t.Errorf("HSTS-Snippet: %s", h)
	}
	if h := files["snippets/hsts-waf.example.com.conf"]; strings.Contains(h, "preload") {
		t.Errorf("preload darf nicht Standard sein: %s", h)
	}
	if h := files["snippets/hsts-nohsts-sub.example.com.conf"]; !strings.Contains(h, `"max-age=300"`) {
		t.Errorf("HSTS ohne Subdomains: %s", h)
	}
	if !strings.Contains(files["coraza/coraza.conf"], "SecRuleEngine On") {
		t.Error("SecRuleEngine folgt nicht dem globalen Modus")
	}
	if strings.Contains(files["coraza/coraza.conf"], "(?!") {
		t.Error("Coraza nutzt RE2: keine Lookaheads rendern")
	}
	if !strings.Contains(files["coraza/crs-overrides.conf"], "blocking_paranoia_level=2") || strings.Contains(files["coraza/crs-overrides.conf"], "SecRuleRemoveById") {
		t.Error("Overrides vor den Regeln falsch aufgeteilt")
	}
	if !strings.Contains(files["coraza/crs-overrides-after.conf"], "SecRuleRemoveById 920350") {
		t.Error("Overrides nach den Regeln fehlen")
	}
	main := files["coraza/main.conf"]
	if strings.Index(main, "crs-overrides.conf") > strings.Index(main, "/rules/*.conf") || strings.Index(main, "crs-overrides-after.conf") < strings.Index(main, "/rules/*.conf") {
		t.Error("Reihenfolge der Includes in main.conf falsch")
	}
}

func TestHashAndMaterialize(t *testing.T) {
	a, _ := Render(scenarios["standard"])
	b, _ := Render(scenarios["standard"])
	if Hash(a) != Hash(b) {
		t.Error("Rendering ist nicht deterministisch")
	}
	changed := scenarios["standard"]
	changed.Hosts = []Host{host("app.example.com", func(h *Host) { h.CertFingerprint = "bb22" })}
	c, _ := Render(changed)
	if Hash(a) == Hash(c) {
		t.Error("ein erneuertes Zertifikat muss den Hash aendern (sonst kein Reload)")
	}
	m := Materialize(a, "/run/nrp/render/gen-7")
	for name, content := range m {
		if strings.Contains(content, GenPlaceholder) {
			t.Errorf("%s enthaelt noch den Platzhalter", name)
		}
	}
	if !strings.Contains(m["http.d/host-app.example.com.conf"], "include /run/nrp/render/gen-7/snippets/hsts-app.example.com.conf;") {
		t.Error("Generationspfad nicht eingesetzt")
	}
}

func TestRenderRejectsUnsafeInput(t *testing.T) {
	for name, mod := range map[string]func(*Host){
		"fqdn":      func(h *Host) { h.FQDN = "a.example.com; include /etc/passwd" },
		"address":   func(h *Host) { h.Address = "10.0.0.1/;}" },
		"scheme":    func(h *Host) { h.Scheme = "http://x;" },
		"body size": func(h *Host) { h.ClientMaxBodySize = "1M; root /" },
		"port":      func(h *Host) { h.Port = 0 },
	} {
		if _, err := Render(Input{WAFMode: "Off", Paths: paths, Hosts: []Host{host("a.example.com", mod)}}); err == nil {
			t.Errorf("%s: unsichere Eingabe wurde gerendert", name)
		}
	}
	if _, err := Render(Input{WAFMode: "Banana", Paths: paths}); err == nil {
		t.Error("ungueltiger WAF-Modus wurde gerendert")
	}
}

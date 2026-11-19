package importer_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/audit"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/domain"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/importer"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/testutil"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/wireguard"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fixture ergaenzt die statischen v2-Configs um Schluessel und Zertifikate.
func fixture(t *testing.T) (importer.Options, string, string) {
	t.Helper()
	tmp := t.TempDir()
	hubPriv, hubPub, _ := wireguard.GenerateKeyPair()
	_, sitePub, _ := wireguard.GenerateKeyPair()
	psk, _ := wireguard.GeneratePSK()
	write(t, tmp+"/wireguard/wg0.conf", "[Interface]\nAddress = 10.240.0.1/16\nListenPort = 51825\nPrivateKey = "+hubPriv+
		"\n# IP forwarding is handled by nrp setup\n\n# Site: home\n[Peer]\nPublicKey = "+sitePub+"\nPresharedKey = "+psk+"\nAllowedIPs = 10.240.0.16/28\n")
	sites, _ := json.Marshal(map[string]any{"sites": []map[string]any{
		{"name": "home", "subnet": "10.240.0.16/28", "connector_ip": "10.240.0.18", "wg_interface": "wg0", "public_key": sitePub,
			"preshared_key": psk, "status": "online", "targets": 8, "email": nil, "os_hint": "debian", "lan_cidr": nil,
			"created_at": "2026-03-01T10:00:00+00:00", "last_seen_at": nil, "notes": nil},
		{"name": "pending", "subnet": "10.240.0.32/28", "connector_ip": "10.240.0.34", "public_key": nil, "preshared_key": "",
			"status": "pending", "created_at": "2026-03-02T10:00:00+00:00"},
	}})
	write(t, tmp+"/nrp/sites.json", string(sites))
	chain, key := testutil.SelfSigned(t, "app.example.com", time.Now().Add(30*24*time.Hour))
	write(t, tmp+"/letsencrypt/live/app.example.com/fullchain.pem", chain)
	write(t, tmp+"/letsencrypt/live/app.example.com/privkey.pem", key)
	return importer.Options{ConfDir: "testdata/v2/conf.d", Letsencrypt: tmp + "/letsencrypt", SitesFile: tmp + "/nrp/sites.json",
		WGConf: tmp + "/wireguard/wg0.conf", OverlayCIDR: "10.240.0.0/16"}, hubPub, psk
}

func TestParseHostConfig(t *testing.T) {
	raw, err := os.ReadFile("testdata/v2/conf.d/tunnel.example.com.conf")
	if err != nil {
		t.Fatal(err)
	}
	h, err := importer.ParseHostConfig(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if h.FQDN != "tunnel.example.com" || h.Scheme != "https" || h.Address != "10.240.0.18" || h.Port != 443 || h.ExternalPort != 8444 ||
		!h.WAF || !h.Websockets || h.ClientMaxBodySize != "2g" || h.HSTS == nil || !h.HSTS.Preload || h.HSTS.MaxAge != 31536000 {
		t.Fatalf("Custom-Port-Host: %+v", h)
	}
	raw, _ = os.ReadFile("testdata/v2/conf.d/app.example.com.conf")
	h, err = importer.ParseHostConfig(string(raw))
	// Auskommentierte Direktiven (coraza on, Upgrade) zaehlen nicht.
	if err != nil || h.WAF || h.Websockets || h.ExternalPort != 443 || h.Address != "192.168.1.10" || h.Port != 8080 || h.Scheme != "http" {
		t.Fatalf("Standard-Host: %+v %v", h, err)
	}
	raw, _ = os.ReadFile("testdata/v2/conf.d/manual.conf")
	if _, err := importer.ParseHostConfig(string(raw)); err == nil {
		t.Fatal("nicht eindeutige Config muss abgelehnt werden")
	}
}

func TestAnalyzeAndApply(t *testing.T) {
	opt, hubPub, psk := fixture(t)
	plan, err := importer.Analyze(opt)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.HubFound || len(plan.Sites) != 2 || len(plan.Hosts) != 2 || len(plan.Certs) != 1 {
		t.Fatalf("Plan: hub=%v sites=%d hosts=%d certs=%d", plan.HubFound, len(plan.Sites), len(plan.Hosts), len(plan.Certs))
	}
	if _, ok := plan.Skipped["manual.conf"]; !ok || len(plan.Skipped) != 1 {
		t.Fatalf("Bericht ueber nicht importierbare Dateien: %v", plan.Skipped)
	}
	byName := map[string]importer.Host{}
	for _, h := range plan.Hosts {
		byName[h.FQDN] = h
	}
	// Upstream im Site-Subnetz wird der Site zugeordnet.
	if byName["tunnel.example.com"].Site != "home" || byName["app.example.com"].Site != "" || !byName["app.example.com"].HasCertificate {
		t.Fatalf("Hosts: %+v", byName)
	}
	if len(plan.Warnings) != 1 || !strings.Contains(plan.Warnings[0], "tunnel.example.com") {
		t.Fatalf("Warnungen: %v", plan.Warnings)
	}

	st, box := testutil.Store(t), testutil.Box(t)
	ctx := context.Background()
	actor := audit.Entry{RequestID: "import", ActorType: "offline", ActorID: "uid=0"}
	res, err := plan.Apply(ctx, st, box, opt, actor)
	if err != nil {
		t.Fatal(err)
	}
	if res.Hub != 1 || res.Sites != 2 || res.Hosts != 2 || res.Certs != 1 || res.Jobs != 1 {
		t.Fatalf("Ergebnis: %+v", res)
	}
	q := st.Read()
	hub, _ := q.GetWgHub(ctx)
	// Hub-Schluessel und Port bleiben: bestehende Sites muessen nichts aendern.
	if hub.PublicKey != hubPub || hub.ListenPort != 51825 || hub.Address != "10.240.0.1/16" || hub.OverlayCidr != "10.240.0.0/16" {
		t.Fatalf("Hub: %+v", hub)
	}
	home, _ := q.GetSite(ctx, "home")
	gotPSK, _ := box.Open(home.PskEnc)
	if home.Subnet != "10.240.0.16/28" || home.ConnectorIp != "10.240.0.18" || string(gotPSK) != psk || home.PublicKey == nil {
		t.Fatalf("Site home: %+v", home)
	}
	if pend, _ := q.GetSite(ctx, "pending"); pend.Status != "pending" || len(pend.PskEnc) != 0 {
		t.Fatalf("Site pending: %+v", pend)
	}
	app, _ := q.GetHost(ctx, "app.example.com")
	if app.Status != domain.HostActive || app.HstsJson == nil || !strings.Contains(*app.HstsJson, `"preload":true`) {
		t.Fatalf("Host app: %+v", app)
	}
	cert, err := q.GetCertificate(ctx, "app.example.com")
	if err != nil || cert.Source != "imported" {
		t.Fatalf("Zertifikat: %+v %v", cert, err)
	}
	tun, _ := q.GetHost(ctx, "tunnel.example.com")
	if tun.Status != domain.HostPending || tun.SiteName == nil || *tun.SiteName != "home" || tun.Waf != 1 || tun.Websockets != 1 || tun.ExternalPort != 8444 {
		t.Fatalf("Host tunnel: %+v", tun)
	}
	if n, _ := q.CountOpenJobsFor(ctx, struct {
		Resource string
		Kind     string
	}{"tunnel.example.com", "cert_issue"}); n != 1 {
		t.Errorf("fuer den Host ohne Zertifikat fehlt der Ausstellungsjob")
	}
	v, _ := audit.Verify(ctx, q)
	if !v.OK || v.Entries != 5 {
		t.Fatalf("Audit nach Import: %+v", v)
	}
	// Zweiter Import aendert nichts.
	res, err = plan.Apply(ctx, st, box, opt, actor)
	if err != nil || res.Hosts+res.Sites+res.Hub+res.Certs != 0 || len(res.Existing) != 5 {
		t.Fatalf("erneuter Import: %+v %v", res, err)
	}
	// Die Quellen bleiben unveraendert.
	if raw, _ := os.ReadFile(opt.WGConf); !strings.Contains(string(raw), "ListenPort = 51825") {
		t.Error("Quelle wurde veraendert")
	}
}

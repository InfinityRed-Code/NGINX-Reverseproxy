package wireguard

import (
	"net/netip"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestPrefixForTargets(t *testing.T) {
	for targets, want := range map[int]int{1: 30, 2: 30, 3: 29, 6: 29, 7: 28, 14: 28, 15: 27, 100: 25, 254: 24, 1000: 24} {
		if got := PrefixForTargets(targets); got != want {
			t.Errorf("PrefixForTargets(%d) = /%d, erwartet /%d", targets, got, want)
		}
	}
}

func TestAllocateSubnet(t *testing.T) {
	overlay := netip.MustParsePrefix("10.240.0.0/16")
	var allocated []netip.Prefix
	want := []string{"10.240.0.0/28", "10.240.0.16/28", "10.240.0.32/28"}
	for _, w := range want {
		got, err := AllocateSubnet(overlay, 28, allocated)
		if err != nil || got.String() != w {
			t.Fatalf("AllocateSubnet = %v, %v; erwartet %s", got, err, w)
		}
		allocated = append(allocated, got)
	}
	// Ein groesseres Netz darf kein bereits vergebenes ueberlappen.
	got, err := AllocateSubnet(overlay, 26, allocated)
	if err != nil || got.String() != "10.240.0.64/26" {
		t.Fatalf("AllocateSubnet(/26) = %v, %v", got, err)
	}
	if ip := ConnectorIP(netip.MustParsePrefix("10.240.0.16/28")); ip.String() != "10.240.0.18" {
		t.Errorf("ConnectorIP = %s", ip)
	}
	if a := HubAddress(overlay); a != "10.240.0.1/16" {
		t.Errorf("HubAddress = %s", a)
	}
	if _, err := AllocateSubnet(overlay, 8, nil); err == nil {
		t.Error("Praefix groesser als das Overlay sollte abgelehnt werden")
	}
	// Erschoepfung
	small := netip.MustParsePrefix("10.0.0.0/29")
	a1, _ := AllocateSubnet(small, 30, nil)
	a2, _ := AllocateSubnet(small, 30, []netip.Prefix{a1})
	if _, err := AllocateSubnet(small, 30, []netip.Prefix{a1, a2}); err == nil {
		t.Error("volles Overlay sollte einen Fehler liefern")
	}
}

func TestInstallScript(t *testing.T) {
	p := ScriptParams{Name: "home", Subnet: "10.240.0.16/28", ConnectorIP: "10.240.0.18", LANCIDR: "192.168.1.0/24",
		OverlayCIDR: "10.240.0.0/16", HubPublic: "HUBKEY=", PSK: "PSKVALUE=", PublicEndpoint: "proxy.example.com", ListenPort: 51820, OS: "debian"}
	s, err := InstallScript(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Address = 10.240.0.18/28", "PublicKey = HUBKEY=", "Endpoint = proxy.example.com:51820",
		"AllowedIPs = 10.240.0.0/16", "PresharedKey = PSKVALUE=", "wg-quick@wg-site-home", "apt-get install -y wireguard",
		"nrp site set-pubkey home $PUBLIC_KEY", "awk '/^default/ {print $5}'"} {
		if !strings.Contains(s, want) {
			t.Errorf("Script enthaelt %q nicht", want)
		}
	}
	if strings.Contains(s, "apk add") {
		t.Error("debian-Script sollte kein apk enthalten")
	}
	p.PublicEndpoint = ""
	if _, err := InstallScript(p); err == nil {
		t.Error("fehlender NRP_PUBLIC_ENDPOINT sollte ein Fehler sein")
	}
	if ep, _ := Endpoint("1.2.3.4:51999", 51820); ep != "1.2.3.4:51999" {
		t.Errorf("Endpoint mit Port = %s", ep)
	}
	if n := InterfaceName("a-very-long-site-name"); len(n) > 15 {
		t.Errorf("Interface-Name %q ist laenger als 15 Zeichen", n)
	}
}

func TestKeys(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := PublicFromPrivate(priv); err != nil || got != pub {
		t.Errorf("PublicFromPrivate = %s, %v", got, err)
	}
	if ValidateKey(pub) != nil || ValidateKey("not-a-key") == nil {
		t.Error("ValidateKey falsch")
	}
}

func TestPlanPeersLeavesUnchangedPeersAlone(t *testing.T) {
	_, pubA, _ := GenerateKeyPair()
	_, pubB, _ := GenerateKeyPair()
	_, pubC, _ := GenerateKeyPair()
	psk, _ := GeneratePSK()
	desired := []Peer{
		{Name: "a", PublicKey: pubA, PSK: psk, AllowedIPs: []string{"10.240.0.0/28", "192.168.1.0/24"}},
		{Name: "b", PublicKey: pubB, AllowedIPs: []string{"10.240.0.16/28"}},
	}
	plan, err := PlanPeers(nil, desired)
	if err != nil || len(plan) != 2 || plan[0].UpdateOnly || plan[0].Remove || !plan[0].ReplaceAllowedIPs || len(plan[0].AllowedIPs) != 2 {
		t.Fatalf("Erstkonfiguration: %+v %v", plan, err)
	}
	// Zustand nach dem Anwenden nachbilden.
	var current []wgtypes.Peer
	for _, pc := range plan {
		current = append(current, wgtypes.Peer{PublicKey: pc.PublicKey, PresharedKey: *pc.PresharedKey, AllowedIPs: pc.AllowedIPs})
	}
	// Unveraendert: keine Aenderung, damit Endpoint und Sitzung erhalten bleiben.
	if plan, _ = PlanPeers(current, desired); len(plan) != 0 {
		t.Fatalf("unveraenderte Peers werden neu konfiguriert: %+v", plan)
	}
	// Geaenderte AllowedIPs, rotierter PSK, entfernte und neue Site.
	newPSK, _ := GeneratePSK()
	changed := []Peer{
		{Name: "a", PublicKey: pubA, PSK: newPSK, AllowedIPs: []string{"10.240.0.0/28"}},
		{Name: "c", PublicKey: pubC, AllowedIPs: []string{"10.240.0.32/28"}},
	}
	plan, err = PlanPeers(current, changed)
	if err != nil || len(plan) != 3 {
		t.Fatalf("Aenderungsplan: %+v %v", plan, err)
	}
	byKey := map[string]wgtypes.PeerConfig{}
	for _, pc := range plan {
		byKey[pc.PublicKey.String()] = pc
	}
	if a := byKey[pubA]; !a.UpdateOnly || a.PresharedKey.String() != newPSK || len(a.AllowedIPs) != 1 {
		t.Errorf("Site a: %+v", a)
	}
	if !byKey[pubB].Remove {
		t.Errorf("entfernte Site b wird nicht geloescht: %+v", byKey[pubB])
	}
	if c := byKey[pubC]; c.UpdateOnly || c.Remove {
		t.Errorf("neue Site c: %+v", c)
	}
	if _, err := PlanPeers(nil, []Peer{{Name: "x", PublicKey: pubA}, {Name: "y", PublicKey: pubA}}); err == nil {
		t.Error("doppelter Public Key muss abgelehnt werden")
	}
	if _, err := PlanPeers(nil, []Peer{{Name: "x", PublicKey: "kaputt"}}); err == nil {
		t.Error("ungueltiger Schluessel muss abgelehnt werden")
	}
}

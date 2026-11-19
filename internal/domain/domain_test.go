package domain

import "testing"

func TestValidateFQDN(t *testing.T) {
	for _, ok := range []string{"example.com", "sub.example.com", "api.test.example.com", "xn--mnchen-3ya.de"} {
		if err := ValidateFQDN(ok); err != nil {
			t.Errorf("%q sollte gueltig sein: %v", ok, err)
		}
	}
	for _, bad := range []string{"example", "example.", "", "192.168.1.1", "Example.com", "a..b.com", "-a.example.com",
		"a.example.com;", "a.example.com/x", "a b.example.com", "*.example.com", "../etc/passwd"} {
		if ValidateFQDN(bad) == nil {
			t.Errorf("%q sollte ungueltig sein", bad)
		}
	}
	if got := NormalizeFQDN(" Example.COM. "); got != "example.com" {
		t.Errorf("NormalizeFQDN = %q", got)
	}
}

func TestValidateUpstreamAddress(t *testing.T) {
	for _, ok := range []string{"192.168.1.1", "10.0.0.1", "0.0.0.0", "255.255.255.255", "fd00::1", "backend", "app.internal", "my_service"} {
		if err := ValidateUpstreamAddress(ok); err != nil {
			t.Errorf("%q sollte gueltig sein: %v", ok, err)
		}
	}
	for _, bad := range []string{"256.1.1.1", "192.168.1", "192.168.1.1.1", "", "a b", "host;", "host/path", "host:80", "fe80::1%eth0", "$host", "a{b}"} {
		if ValidateUpstreamAddress(bad) == nil {
			t.Errorf("%q sollte ungueltig sein", bad)
		}
	}
	if got := UpstreamHost("fd00::1"); got != "[fd00::1]" {
		t.Errorf("UpstreamHost(IPv6) = %q", got)
	}
}

func TestValidatePortAndScheme(t *testing.T) {
	for _, p := range []int{1, 80, 443, 8080, 65535} {
		if ValidatePort(p) != nil {
			t.Errorf("Port %d sollte gueltig sein", p)
		}
	}
	for _, p := range []int{0, -1, 65536} {
		if ValidatePort(p) == nil {
			t.Errorf("Port %d sollte ungueltig sein", p)
		}
	}
	for _, p := range []int{80, 8443, 0} {
		if ValidateExternalPort(p) == nil {
			t.Errorf("externer Port %d sollte abgelehnt werden", p)
		}
	}
	if ValidateScheme("http") != nil || ValidateScheme("https") != nil {
		t.Error("http/https sollten gueltig sein")
	}
	for _, s := range []string{"ftp", "", "http://", "HTTP"} {
		if ValidateScheme(s) == nil {
			t.Errorf("Schema %q sollte ungueltig sein", s)
		}
	}
}

func TestMisc(t *testing.T) {
	for _, ok := range []string{"100M", "1g", "512k", "0", "1048576"} {
		if ValidateBodySize(ok) != nil {
			t.Errorf("%q sollte gueltig sein", ok)
		}
	}
	for _, bad := range []string{"", "100MB", "M", "1 0M", "10M;"} {
		if ValidateBodySize(bad) == nil {
			t.Errorf("%q sollte ungueltig sein", bad)
		}
	}
	for in, want := range map[string]string{"on": "On", "ON": "On", "detection-only": "DetectionOnly", "DetectionOnly": "DetectionOnly", "off": "Off"} {
		if got, err := NormalizeWAFMode(in); err != nil || got != want {
			t.Errorf("NormalizeWAFMode(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := NormalizeWAFMode("block"); err == nil {
		t.Error("unbekannter Modus sollte abgelehnt werden")
	}
	if ValidateSiteName("home") != nil || ValidateSiteName("Home") == nil || ValidateSiteName("a_b") == nil || ValidateSiteName("") == nil {
		t.Error("Site-Namen-Validierung falsch")
	}
	if ValidateHSTS(HSTS{MaxAge: 300, Preload: true, IncludeSubdomains: true}) == nil {
		t.Error("preload mit kurzer max_age sollte abgelehnt werden")
	}
	if ValidateHSTS(HSTS{MaxAge: 31536000, Preload: true, IncludeSubdomains: true}) != nil {
		t.Error("gueltige preload-Konfiguration abgelehnt")
	}
	if !AddressInSubnets("10.240.0.18", "10.240.0.16/28") || AddressInSubnets("10.240.0.40", "10.240.0.16/28", "192.168.1.0/24") || AddressInSubnets("host", "10.0.0.0/8") {
		t.Error("AddressInSubnets falsch")
	}
}

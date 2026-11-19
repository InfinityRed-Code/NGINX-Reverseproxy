package wireguard

import (
	"bytes"
	_ "embed"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"text/template"
)

//go:embed install.sh.tmpl
var installTmplText string

var installTmpl = template.Must(template.New("install").Parse(installTmplText))

type ScriptParams struct {
	Name        string
	Subnet      string
	ConnectorIP string
	LANCIDR     string
	OverlayCIDR string
	HubPublic   string
	PSK         string
	// PublicEndpoint aus NRP_PUBLIC_ENDPOINT (host oder host:port).
	PublicEndpoint string
	ListenPort     int
	OS             string
}

type scriptData struct {
	ScriptParams
	Iface    string
	Prefix   int
	Endpoint string
}

// InterfaceName haelt die Linux-Grenze von 15 Zeichen ein.
func InterfaceName(site string) string {
	if n := "wg-site-" + site; len(n) <= 15 {
		return n
	}
	if len(site) > 11 {
		site = site[:11]
	}
	return "nrp-" + site
}

// Endpoint ergaenzt den WireGuard-Port, falls NRP_PUBLIC_ENDPOINT keinen nennt.
func Endpoint(public string, port int) (string, error) {
	if public == "" {
		return "", fmt.Errorf("NRP_PUBLIC_ENDPOINT ist nicht gesetzt")
	}
	if _, _, err := net.SplitHostPort(public); err == nil {
		return public, nil
	}
	return net.JoinHostPort(public, strconv.Itoa(port)), nil
}

// InstallScript erzeugt das Shell-Script fuer den Site-Host (Port von v2).
func InstallScript(p ScriptParams) (string, error) {
	subnet, err := netip.ParsePrefix(p.Subnet)
	if err != nil {
		return "", err
	}
	ep, err := Endpoint(p.PublicEndpoint, p.ListenPort)
	if err != nil {
		return "", err
	}
	if p.OS == "" {
		p.OS = "auto"
	}
	var buf bytes.Buffer
	err = installTmpl.Execute(&buf, scriptData{ScriptParams: p, Iface: InterfaceName(p.Name), Prefix: subnet.Bits(), Endpoint: ep})
	return buf.String(), err
}

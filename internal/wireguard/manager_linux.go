//go:build linux

package wireguard

import (
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// routeProto markiert von NRP gesetzte Routen, damit nur diese abgeglichen werden.
const routeProto = 98

type linuxManager struct{}

// NewManager steuert wg0 direkt ueber Netlink (kein wg/wg-quick/ip).
func NewManager() Manager { return linuxManager{} }

func ensureLink(address string) (netlink.Link, error) {
	link, err := netlink.LinkByName(Interface)
	if err != nil {
		var nf netlink.LinkNotFoundError
		if !errors.As(err, &nf) {
			return nil, err
		}
		attrs := netlink.NewLinkAttrs()
		attrs.Name = Interface
		if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: attrs}); err != nil {
			return nil, fmt.Errorf("wg0 anlegen (NET_ADMIN und WireGuard-Kernelmodul noetig): %w", err)
		}
		if link, err = netlink.LinkByName(Interface); err != nil {
			return nil, err
		}
	}
	addr, err := netlink.ParseAddr(address)
	if err != nil {
		return nil, err
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return nil, fmt.Errorf("Adresse %s setzen: %w", address, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, err
	}
	return link, nil
}

func (linuxManager) Apply(d Desired) error {
	link, err := ensureLink(d.Address)
	if err != nil {
		return err
	}
	key, err := wgtypes.ParseKey(d.PrivateKey)
	if err != nil {
		return err
	}
	c, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer c.Close()
	dev, err := c.Device(Interface)
	if err != nil {
		return err
	}
	var cfg wgtypes.Config
	changed := false
	if dev.PrivateKey != key {
		cfg.PrivateKey, changed = &key, true
	}
	if dev.ListenPort != d.ListenPort {
		cfg.ListenPort, changed = &d.ListenPort, true
	}
	if cfg.Peers, err = PlanPeers(dev.Peers, d.Peers); err != nil {
		return err
	}
	if changed || len(cfg.Peers) > 0 {
		if err := c.ConfigureDevice(Interface, cfg); err != nil {
			return fmt.Errorf("wg0 konfigurieren: %w", err)
		}
	}
	return syncRoutes(link, d.Routes)
}

func syncRoutes(link netlink.Link, want []string) error {
	wanted := map[string]*net.IPNet{}
	for _, r := range want {
		_, n, err := net.ParseCIDR(r)
		if err != nil {
			return err
		}
		wanted[n.String()] = n
	}
	existing, err := netlink.RouteList(link, unix.AF_INET)
	if err != nil {
		return err
	}
	for _, r := range existing {
		if r.Protocol != routeProto || r.Dst == nil {
			continue
		}
		if _, ok := wanted[r.Dst.String()]; !ok {
			if err := netlink.RouteDel(&r); err != nil {
				return err
			}
		}
	}
	for _, n := range wanted {
		route := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: n, Scope: netlink.SCOPE_LINK, Protocol: routeProto}
		if err := netlink.RouteReplace(route); err != nil {
			return fmt.Errorf("Route %s: %w", n, err)
		}
	}
	return nil
}

func (linuxManager) Stats() (map[string]PeerStat, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	dev, err := c.Device(Interface)
	if err != nil {
		return nil, err
	}
	out := make(map[string]PeerStat, len(dev.Peers))
	for _, p := range dev.Peers {
		st := PeerStat{LastHandshake: p.LastHandshakeTime, Rx: p.ReceiveBytes, Tx: p.TransmitBytes}
		if p.Endpoint != nil {
			st.Endpoint = p.Endpoint.String()
		}
		out[p.PublicKey.String()] = st
	}
	return out, nil
}

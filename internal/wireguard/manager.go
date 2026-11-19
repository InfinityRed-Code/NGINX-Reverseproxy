package wireguard

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/audit"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/secrets"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store"
	"github.com/SoftENGINE-IT/NGINX-Reverseproxy/internal/store/dbq"
)

const (
	Interface = "wg0"
	// OnlineWindow: eine Site gilt als online, wenn der letzte Handshake juenger ist.
	OnlineWindow = 3 * time.Minute
)

type Peer struct {
	Name       string
	PublicKey  string
	PSK        string
	AllowedIPs []string
}

// Desired ist der Sollzustand von wg0, vollstaendig aus der DB abgeleitet.
type Desired struct {
	PrivateKey string
	ListenPort int
	Address    string
	Peers      []Peer
	Routes     []string
}

type PeerStat struct {
	LastHandshake time.Time
	Endpoint      string
	Rx, Tx        int64
}

func (p PeerStat) Online() bool {
	return !p.LastHandshake.IsZero() && time.Since(p.LastHandshake) < OnlineWindow
}

// Manager steuert das Interface. Apply ist idempotent (ReplacePeers).
type Manager interface {
	Apply(d Desired) error
	// Stats liefert den Zustand je Public Key.
	Stats() (map[string]PeerStat, error)
}

func GenerateKeyPair() (priv, pub string, err error) {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", err
	}
	return k.String(), k.PublicKey().String(), nil
}

func GeneratePSK() (string, error) {
	k, err := wgtypes.GenerateKey()
	return k.String(), err
}

func ValidateKey(s string) error {
	if _, err := wgtypes.ParseKey(s); err != nil {
		return fmt.Errorf("ungueltiger WireGuard-Schluessel: %w", err)
	}
	return nil
}

func PublicFromPrivate(priv string) (string, error) {
	k, err := wgtypes.ParseKey(priv)
	if err != nil {
		return "", err
	}
	return k.PublicKey().String(), nil
}

// EnsureHub legt beim Erststart den Hub an (Schluessel, Port, Adresse).
func EnsureHub(ctx context.Context, st *store.Store, box *secrets.Box, overlayCIDR string, port int) (dbq.WgHub, error) {
	hub, err := st.Read().GetWgHub(ctx)
	if err == nil || !errors.Is(err, sql.ErrNoRows) {
		return hub, err
	}
	overlay, err := netip.ParsePrefix(overlayCIDR)
	if err != nil || !overlay.Addr().Is4() {
		return hub, fmt.Errorf("NRP_WG_OVERLAY_CIDR %q ist kein IPv4-Netz", overlayCIDR)
	}
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		return hub, err
	}
	enc, err := box.Seal([]byte(priv))
	if err != nil {
		return hub, err
	}
	hub = dbq.WgHub{ID: 1, PrivateKeyEnc: enc, PublicKey: pub, ListenPort: int64(port),
		Address: HubAddress(overlay), OverlayCidr: overlay.Masked().String()}
	var row dbq.AuditLog
	err = st.Write(ctx, func(q *dbq.Queries) error {
		if err := q.UpsertWgHub(ctx, dbq.UpsertWgHubParams{PrivateKeyEnc: enc, PublicKey: pub,
			ListenPort: hub.ListenPort, Address: hub.Address, OverlayCidr: hub.OverlayCidr}); err != nil {
			return err
		}
		row, err = audit.Append(ctx, q, audit.Entry{RequestID: "system", ActorType: audit.ActorSystem, ActorID: "nrpd",
			Action: "wireguard.hub_init", ResourceType: "wireguard", ResourceID: Interface,
			After: map[string]any{"public_key": pub, "listen_port": port, "address": hub.Address}})
		return err
	})
	if err == nil {
		audit.Emit(row)
	}
	return hub, err
}

// BuildDesired leitet den Sollzustand aus Hub und Sites ab. Sites ohne Public
// Key oder deaktivierte Sites erhalten keinen Peer.
func BuildDesired(hub dbq.WgHub, sites []dbq.Site, box *secrets.Box) (Desired, error) {
	priv, err := box.Open(hub.PrivateKeyEnc)
	if err != nil {
		return Desired{}, fmt.Errorf("Hub-Schluessel: %w", err)
	}
	d := Desired{PrivateKey: string(priv), ListenPort: int(hub.ListenPort), Address: hub.Address}
	for _, s := range sites {
		if s.Enabled == 0 || s.PublicKey == nil || *s.PublicKey == "" {
			continue
		}
		p := Peer{Name: s.Name, PublicKey: *s.PublicKey, AllowedIPs: []string{s.Subnet}}
		if s.LanCidr != nil && *s.LanCidr != "" {
			p.AllowedIPs = append(p.AllowedIPs, *s.LanCidr)
			d.Routes = append(d.Routes, *s.LanCidr)
		}
		if len(s.PskEnc) > 0 {
			psk, err := box.Open(s.PskEnc)
			if err != nil {
				return Desired{}, fmt.Errorf("PSK der Site %s: %w", s.Name, err)
			}
			p.PSK = string(psk)
		}
		d.Peers = append(d.Peers, p)
	}
	return d, nil
}

// UpdateStatuses uebernimmt den Handshake-Zustand in die Tabelle sites und
// protokolliert Statuswechsel als Systemaktion.
func UpdateStatuses(ctx context.Context, st *store.Store, m Manager) error {
	stats, err := m.Stats()
	if err != nil {
		return err
	}
	sites, err := st.Read().ListSites(ctx)
	if err != nil {
		return err
	}
	for _, s := range sites {
		if s.Enabled == 0 || s.PublicKey == nil {
			continue
		}
		ps := stats[*s.PublicKey]
		status := "offline"
		if ps.Online() {
			status = "online"
		} else if ps.LastHandshake.IsZero() && s.Status == "pending" {
			status = "pending"
		}
		lastSeen := s.LastSeenAt
		if !ps.LastHandshake.IsZero() {
			t := store.FormatTime(ps.LastHandshake)
			lastSeen = &t
		}
		if status == s.Status && (lastSeen == nil) == (s.LastSeenAt == nil) && (lastSeen == nil || *lastSeen == *s.LastSeenAt) {
			continue
		}
		var row *dbq.AuditLog
		err := st.Write(ctx, func(q *dbq.Queries) error {
			if err := q.UpdateSiteStatus(ctx, dbq.UpdateSiteStatusParams{Status: status, LastSeenAt: lastSeen, Name: s.Name}); err != nil {
				return err
			}
			if status == s.Status {
				return nil
			}
			r, err := audit.Append(ctx, q, audit.Entry{RequestID: "system", ActorType: audit.ActorSystem, ActorID: "nrpd",
				Action: "site.status", ResourceType: "site", ResourceID: s.Name,
				Before: map[string]any{"status": s.Status}, After: map[string]any{"status": status}})
			row = &r
			return err
		})
		if err != nil {
			return err
		}
		if row != nil {
			audit.Emit(*row)
		}
	}
	return nil
}

// PlanPeers berechnet die noetigen Aenderungen gegenueber dem laufenden Interface.
// Unveraenderte Peers werden nicht angefasst: ein vollstaendiges Ersetzen
// (ReplacePeers) wuerde bei jedem Abgleich Endpoint und Sitzung aller Sites
// verwerfen und die Tunnel unterbrechen.
func PlanPeers(current []wgtypes.Peer, desired []Peer) ([]wgtypes.PeerConfig, error) {
	cur := make(map[wgtypes.Key]wgtypes.Peer, len(current))
	for _, p := range current {
		cur[p.PublicKey] = p
	}
	var out []wgtypes.PeerConfig
	want := make(map[wgtypes.Key]bool, len(desired))
	for _, p := range desired {
		pub, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("Site %s: %w", p.Name, err)
		}
		if want[pub] {
			return nil, fmt.Errorf("Site %s: Public Key mehrfach vergeben", p.Name)
		}
		want[pub] = true
		var psk wgtypes.Key
		if p.PSK != "" {
			if psk, err = wgtypes.ParseKey(p.PSK); err != nil {
				return nil, fmt.Errorf("Site %s (PSK): %w", p.Name, err)
			}
		}
		var nets []net.IPNet
		ips := map[string]bool{}
		for _, a := range p.AllowedIPs {
			pfx, err := netip.ParsePrefix(a)
			if err != nil {
				return nil, fmt.Errorf("Site %s: %w", p.Name, err)
			}
			pfx = pfx.Masked()
			ips[pfx.String()] = true
			nets = append(nets, net.IPNet{IP: pfx.Addr().AsSlice(), Mask: net.CIDRMask(pfx.Bits(), pfx.Addr().BitLen())})
		}
		existing, exists := cur[pub]
		if exists && existing.PresharedKey == psk && len(existing.AllowedIPs) == len(ips) {
			same := true
			for _, n := range existing.AllowedIPs {
				same = same && ips[n.String()]
			}
			if same {
				continue
			}
		}
		out = append(out, wgtypes.PeerConfig{PublicKey: pub, UpdateOnly: exists, PresharedKey: &psk,
			ReplaceAllowedIPs: true, AllowedIPs: nets})
	}
	for key := range cur {
		if !want[key] {
			out = append(out, wgtypes.PeerConfig{PublicKey: key, Remove: true})
		}
	}
	return out, nil
}

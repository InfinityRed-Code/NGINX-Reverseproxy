// Package wireguard verwaltet den Hub (wg0), die Subnetz-Vergabe fuer Sites
// und das Install-Script fuer die Gegenstellen.
package wireguard

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// PrefixForTargets liefert das kleinste Subnetz (/30 bis /24), das targets Hosts fasst.
func PrefixForTargets(targets int) int {
	for prefix := 30; prefix >= 24; prefix-- {
		if (1<<(32-prefix))-2 >= targets {
			return prefix
		}
	}
	return 24
}

func addrAdd(a netip.Addr, n uint32) netip.Addr {
	b := a.As4()
	binary.BigEndian.PutUint32(b[:], binary.BigEndian.Uint32(b[:])+n)
	return netip.AddrFrom4(b)
}

// AllocateSubnet findet das erste freie /prefix-Netz im Overlay (wie v2).
func AllocateSubnet(overlay netip.Prefix, prefix int, allocated []netip.Prefix) (netip.Prefix, error) {
	if !overlay.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("Overlay %s ist kein IPv4-Netz", overlay)
	}
	if prefix < overlay.Bits() || prefix > 30 {
		return netip.Prefix{}, fmt.Errorf("Subnetz-Praefix /%d liegt nicht zwischen /%d und /30", prefix, overlay.Bits())
	}
	step := uint32(1) << (32 - prefix)
	count := uint64(1) << (prefix - overlay.Bits())
	base := overlay.Masked().Addr()
	for i := uint64(0); i < count; i++ {
		cand := netip.PrefixFrom(addrAdd(base, uint32(i)*step), prefix)
		free := true
		for _, a := range allocated {
			if cand.Overlaps(a) {
				free = false
				break
			}
		}
		if free {
			return cand, nil
		}
	}
	return netip.Prefix{}, fmt.Errorf("kein freies /%d-Subnetz in %s", prefix, overlay)
}

// ConnectorIP ist die zweite Host-Adresse des Subnetzes (Netz+2).
func ConnectorIP(subnet netip.Prefix) netip.Addr {
	return addrAdd(subnet.Masked().Addr(), 2)
}

// HubAddress ist die erste Host-Adresse des Overlays mit dessen Praefixlaenge.
func HubAddress(overlay netip.Prefix) string {
	return fmt.Sprintf("%s/%d", addrAdd(overlay.Masked().Addr(), 1), overlay.Bits())
}

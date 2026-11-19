"""
WireGuard site management for NRP.

Manages the hub-and-spoke WireGuard overlay network used to expose
services from remote sites through this VPS reverse proxy.
"""
import ipaddress
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from nrp.config import (
    NRP_DATA_DIR,
    SITES_DB_PATH,
    WG_CONFIG_PATH,
    WG_INTERFACE_NAME,
    WG_OVERLAY_CIDR,
    WG_PORT,
)


# ---------------------------------------------------------------------------
# Site DB helpers
# ---------------------------------------------------------------------------

def _load_db() -> Dict:
    """Load the sites database from disk, creating it if absent."""
    NRP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not SITES_DB_PATH.exists():
        SITES_DB_PATH.write_text(json.dumps({"sites": []}, indent=2))
    return json.loads(SITES_DB_PATH.read_text())


def _save_db(db: Dict) -> None:
    """Persist the sites database to disk."""
    NRP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    SITES_DB_PATH.write_text(json.dumps(db, indent=2, default=str))


def _all_sites(db: Dict) -> List[Dict]:
    return db.get("sites", [])


def _find_site(db: Dict, name: str) -> Optional[Dict]:
    for s in _all_sites(db):
        if s["name"] == name:
            return s
    return None


# ---------------------------------------------------------------------------
# Subnet allocation
# ---------------------------------------------------------------------------

def _prefix_for_targets(targets: int) -> int:
    """Return the smallest subnet prefix that fits *targets* hosts."""
    # hosts in /N = 2^(32-N) - 2
    for prefix in range(30, 23, -1):  # /30 → /24
        usable = (2 ** (32 - prefix)) - 2
        if usable >= targets:
            return prefix
    return 24  # fallback


def _allocated_subnets(db: Dict) -> List[ipaddress.IPv4Network]:
    result = []
    for site in _all_sites(db):
        if site.get("subnet"):
            result.append(ipaddress.ip_network(site["subnet"], strict=False))
    return result


def _pick_subnet(prefix: int, allocated: List[ipaddress.IPv4Network]) -> ipaddress.IPv4Network:
    """Find the first unused /prefix subnet inside WG_OVERLAY_CIDR."""
    overlay = ipaddress.ip_network(WG_OVERLAY_CIDR, strict=False)
    for candidate in overlay.subnets(new_prefix=prefix):
        overlap = any(candidate.overlaps(a) for a in allocated)
        if not overlap:
            return candidate
    raise RuntimeError(
        f"No free /{prefix} subnet available inside {WG_OVERLAY_CIDR}"
    )


def _connector_ip(subnet: ipaddress.IPv4Network) -> str:
    """Return the second host address in *subnet* as the site connector IP."""
    hosts = list(subnet.hosts())
    if len(hosts) < 2:
        raise ValueError(f"Subnet {subnet} is too small to assign a connector IP")
    return str(hosts[1])  # network+2 (hosts[0] = network+1 = hub side)


def _hub_ip(subnet: ipaddress.IPv4Network) -> str:
    """Return the first host address in *subnet* as the hub IP."""
    return str(list(subnet.hosts())[0])


# ---------------------------------------------------------------------------
# WireGuard config helpers
# ---------------------------------------------------------------------------

def _wg_conf_exists() -> bool:
    return WG_CONFIG_PATH.exists()


def _read_wg_conf() -> str:
    if WG_CONFIG_PATH.exists():
        return WG_CONFIG_PATH.read_text()
    return ""


def _write_wg_conf(content: str) -> None:
    WG_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    WG_CONFIG_PATH.write_text(content)
    WG_CONFIG_PATH.chmod(0o600)


def _peer_block(site: Dict) -> str:
    """Render a WireGuard [Peer] config block for *site*."""
    public_key = site.get("public_key") or "<PENDING - run nrp site install-script>"
    allowed_ips = site["subnet"]
    if site.get("lan_cidr"):
        allowed_ips += f", {site['lan_cidr']}"
    lines = [
        f"# Site: {site['name']}",
        "[Peer]",
        f"PublicKey = {public_key}",
        f"AllowedIPs = {allowed_ips}",
    ]
    if site.get("preshared_key"):
        lines.insert(3, f"PresharedKey = {site['preshared_key']}")
    return "\n".join(lines) + "\n"


def _add_site_routes(site: Dict) -> None:
    """Add kernel routes for the site's overlay subnet and optional LAN CIDR via wg0."""
    for cidr in [site.get("lan_cidr")]:
        if not cidr:
            continue
        try:
            subprocess.run(
                ["ip", "route", "replace", cidr, "dev", WG_INTERFACE_NAME],
                check=True, capture_output=True
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass


def _remove_site_routes(site: Dict) -> None:
    """Remove kernel routes that were added for the site's LAN CIDR."""
    if site.get("lan_cidr"):
        try:
            subprocess.run(
                ["ip", "route", "del", site["lan_cidr"], "dev", WG_INTERFACE_NAME],
                capture_output=True
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass


def _remove_peer_block(conf: str, site_name: str) -> str:
    """Remove the [Peer] block belonging to *site_name* from conf string."""
    # Match from "# Site: <name>" up to (but not including) the next non-empty block
    pattern = rf"\n*# Site: {re.escape(site_name)}\n\[Peer\].*?(?=\n\n[^\n]|\Z)"
    result = re.sub(pattern, "", conf, flags=re.DOTALL)
    # Collapse more than two consecutive newlines to two
    result = re.sub(r"\n{3,}", "\n\n", result)
    return result.rstrip() + "\n"


def _ensure_wg_interface() -> None:
    """
    Ensure the hub wg0 interface exists.

    If /etc/wireguard/wg0.conf is missing, create a minimal one with a
    newly generated private key and the overlay IP of the hub.
    """
    if _wg_conf_exists():
        return

    # Generate private key
    result = subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True)
    private_key = result.stdout.strip()

    # Hub IP: first host in the overlay /16 itself – use .0.1
    hub_ip = str(ipaddress.ip_network(WG_OVERLAY_CIDR, strict=False).network_address + 1)

    conf = (
        "[Interface]\n"
        f"Address = {hub_ip}/16\n"
        f"ListenPort = {WG_PORT}\n"
        f"PrivateKey = {private_key}\n"
        "# IP forwarding is handled by nrp setup\n"
    )
    _write_wg_conf(conf)


def _apply_wg_conf() -> None:
    """Apply the current wg0.conf to the running interface (if it is up)."""
    try:
        subprocess.run(
            ["wg", "syncconf", WG_INTERFACE_NAME, str(WG_CONFIG_PATH)],
            check=True, capture_output=True, text=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Interface might not be up yet – that is fine
        pass


def _wg_hub_pubkey() -> str:
    """Return the hub's WireGuard public key (derived from wg0.conf private key)."""
    conf = _read_wg_conf()
    m = re.search(r"PrivateKey\s*=\s*(\S+)", conf)
    if not m:
        return "<UNKNOWN>"
    private_key = m.group(1)
    try:
        result = subprocess.run(
            ["wg", "pubkey"], input=private_key, capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "<UNKNOWN>"


def _generate_psk() -> str:
    """Generate a WireGuard preshared key."""
    try:
        result = subprocess.run(["wg", "genpsk"], capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_site(
    name: str,
    targets: Optional[int] = None,
    subnet_prefix: Optional[int] = None,
    email: Optional[str] = None,
    os_hint: Optional[str] = None,
    lan_cidr: Optional[str] = None,
) -> Dict:
    """
    Create a new WireGuard site (spoke).

    Allocates a subnet, picks a connector IP, updates wg0.conf with a new
    [Peer] block, and persists the site metadata.

    Returns the created site dict.
    """
    db = _load_db()

    if _find_site(db, name):
        raise ValueError(f"Site '{name}' already exists")

    # Determine subnet prefix
    if subnet_prefix is None:
        if targets is None:
            targets = 6  # default: fits a /28
        subnet_prefix = _prefix_for_targets(targets)

    allocated = _allocated_subnets(db)
    subnet = _pick_subnet(subnet_prefix, allocated)
    connector_ip = _connector_ip(subnet)

    # Optionally generate preshared key (requires wg to be installed)
    psk = ""
    try:
        psk = _generate_psk()
    except Exception:
        pass

    site = {
        "name": name,
        "subnet": str(subnet),
        "connector_ip": connector_ip,
        "wg_interface": WG_INTERFACE_NAME,
        "public_key": None,
        "preshared_key": psk,
        "status": "pending",
        "targets": targets,
        "email": email,
        "os_hint": os_hint,
        "lan_cidr": lan_cidr or None,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_seen_at": None,
        "notes": None,
    }

    # Update WireGuard config
    _ensure_wg_interface()
    conf = _read_wg_conf()
    conf = conf.rstrip() + "\n\n" + _peer_block(site)
    _write_wg_conf(conf)
    _apply_wg_conf()

    db["sites"].append(site)
    _save_db(db)
    return site


def list_sites() -> List[Dict]:
    """Return all sites from the DB."""
    db = _load_db()
    return _all_sites(db)


def get_site(name: str) -> Optional[Dict]:
    """Return a single site by name, or None."""
    db = _load_db()
    return _find_site(db, name)


def set_public_key(name: str, public_key: str) -> Dict:
    """
    Store the site's WireGuard public key and update wg0.conf.

    Called after the install-script has been executed on the site and the
    operator has obtained the site's public key.
    """
    db = _load_db()
    site = _find_site(db, name)
    if site is None:
        raise ValueError(f"Site '{name}' not found")

    site["public_key"] = public_key

    # Rewrite peer block with real key
    conf = _read_wg_conf()
    conf = _remove_peer_block(conf, name)
    conf = conf.rstrip() + "\n\n" + _peer_block(site)
    _write_wg_conf(conf)
    _apply_wg_conf()
    _add_site_routes(site)

    _save_db(db)
    return site


def delete_site(name: str, keep_config: bool = False) -> None:
    """
    Delete or deactivate a site.

    keep_config=True keeps the DB record (marks status=offline) but removes
    the WireGuard peer from wg0.conf.
    keep_config=False removes everything.
    """
    db = _load_db()
    site = _find_site(db, name)
    if site is None:
        raise ValueError(f"Site '{name}' not found")

    # Remove peer from WireGuard config
    conf = _read_wg_conf()
    conf = _remove_peer_block(conf, name)
    _write_wg_conf(conf)
    _apply_wg_conf()
    _remove_site_routes(site)

    if keep_config:
        site["status"] = "offline"
    else:
        db["sites"] = [s for s in db["sites"] if s["name"] != name]

    _save_db(db)


def refresh_site_status(site: Dict) -> str:
    """
    Ping the site's connector IP, persist the result and return 'online' or 'offline'.
    """
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", site["connector_ip"]],
            capture_output=True,
        )
        status = "online" if result.returncode == 0 else "offline"
    except Exception:
        status = "offline"

    # Persist status and last_seen_at
    db = _load_db()
    s = _find_site(db, site["name"])
    if s is not None:
        s["status"] = status
        if status == "online":
            s["last_seen_at"] = datetime.now(timezone.utc).isoformat()
        _save_db(db)
        site.update(s)

    return status


def generate_install_script(name: str, os_hint: Optional[str] = None) -> str:
    """
    Generate a shell script that sets up the WireGuard tunnel on the site host.

    The script:
      1. Installs wireguard-tools
      2. Generates a private/public key pair
      3. Writes /etc/wireguard/wg-site-<NAME>.conf
      4. Enables and starts wg-quick
      5. Prints the public key so the operator can register it via
         `nrp site set-pubkey <NAME> <KEY>`
    """
    db = _load_db()
    site = _find_site(db, name)
    if site is None:
        raise ValueError(f"Site '{name}' not found")

    hub_pubkey = _wg_hub_pubkey()
    vps_ip = get_vps_public_ip()
    subnet = ipaddress.ip_network(site["subnet"], strict=False)
    prefix = subnet.prefixlen
    connector_ip = site["connector_ip"]
    iface_name = f"wg-site-{name}"

    # Determine the effective OS hint
    effective_os = os_hint or site.get("os_hint") or "auto"

    if effective_os in ("debian", "ubuntu"):
        install_cmd = "apt-get update -qq && apt-get install -y wireguard"
    elif effective_os == "alpine":
        install_cmd = "apk add --no-cache wireguard-tools"
    else:
        # auto-detect at runtime
        install_cmd = (
            'if command -v apt-get &>/dev/null; then\n'
            '    apt-get update -qq && apt-get install -y wireguard\n'
            'elif command -v apk &>/dev/null; then\n'
            '    apk add --no-cache wireguard-tools\n'
            'else\n'
            '    echo "Unsupported package manager – install wireguard-tools manually" >&2\n'
            '    exit 1\n'
            'fi'
        )

    psk_block = ""
    if site.get("preshared_key"):
        psk_block = f"PresharedKey = {site['preshared_key']}\n"

    lan_cidr = site.get("lan_cidr") or ""

    script = f"""\
#!/usr/bin/env bash
# NRP WireGuard site install script
# Site   : {name}
# Subnet : {site['subnet']}
# Hub    : {WG_OVERLAY_CIDR}
# LAN    : {lan_cidr or "(not set – add with nrp site set-lan <NAME> <CIDR>)"}
# Generated by: nrp site install-script
set -euo pipefail

echo "=== NRP Site Installer: {name} ==="

# ── 1. Install WireGuard ──────────────────────────────────────────────────
echo "[1/6] Installing WireGuard..."
{install_cmd}

# ── 2. Enable IP forwarding ───────────────────────────────────────────────
echo "[2/6] Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-nrp-forwarding.conf

# ── 3. Generate key pair ──────────────────────────────────────────────────
echo "[3/6] Generating key pair..."
PRIVATE_KEY=$(wg genkey)
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | wg pubkey)

# ── 4. Write WireGuard config ─────────────────────────────────────────────
echo "[4/6] Writing /etc/wireguard/{iface_name}.conf..."
mkdir -p /etc/wireguard
cat > /etc/wireguard/{iface_name}.conf << WGEOF
[Interface]
Address = {connector_ip}/{prefix}
PrivateKey = $PRIVATE_KEY

[Peer]
PublicKey = {hub_pubkey}
Endpoint = {vps_ip}:{WG_PORT}
AllowedIPs = {WG_OVERLAY_CIDR}
{psk_block}PersistentKeepalive = 25
WGEOF
chmod 600 /etc/wireguard/{iface_name}.conf

# ── 5. Enable and start tunnel ────────────────────────────────────────────
echo "[5/6] Starting WireGuard tunnel..."
if command -v systemctl &>/dev/null; then
    systemctl enable --now wg-quick@{iface_name}
else
    wg-quick up {iface_name}
fi

# ── 6. Set up NAT masquerade (LAN traffic forwarding) ─────────────────────
echo "[6/6] Configuring NAT masquerade..."
LAN_IFACE=$(ip route show default | awk '/^default/ {{print $5}}' | head -1)
if [ -z "$LAN_IFACE" ]; then
    echo "  Warning: could not detect LAN interface – skipping NAT setup"
    echo "  Run manually: nft add rule ip nat POSTROUTING ip saddr {WG_OVERLAY_CIDR} oif <LAN_IFACE> masquerade"
else
    echo "  Detected LAN interface: $LAN_IFACE"
    if command -v nft &>/dev/null; then
        nft add table ip nat 2>/dev/null || true
        nft add chain ip nat POSTROUTING '{{ type nat hook postrouting priority srcnat; policy accept; }}' 2>/dev/null || true
        nft add rule ip nat POSTROUTING ip saddr {WG_OVERLAY_CIDR} oif "$LAN_IFACE" masquerade 2>/dev/null || true
        nft list ruleset > /etc/nftables.conf
        systemctl enable nftables 2>/dev/null || true
        echo "  NAT masquerade configured via nftables"
    elif command -v iptables &>/dev/null; then
        iptables -t nat -C POSTROUTING -s {WG_OVERLAY_CIDR} -o "$LAN_IFACE" -j MASQUERADE 2>/dev/null || \\
            iptables -t nat -A POSTROUTING -s {WG_OVERLAY_CIDR} -o "$LAN_IFACE" -j MASQUERADE
        if command -v iptables-save &>/dev/null; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || \\
            iptables-save > /etc/iptables.rules 2>/dev/null || true
        fi
        echo "  NAT masquerade configured via iptables"
    else
        echo "  Warning: neither nft nor iptables found – NAT not configured"
        echo "  Install nftables or iptables and re-run this section manually"
    fi
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  IMPORTANT: Register this site's public key on the VPS hub!     ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "  Site public key: $PUBLIC_KEY"
echo ""
echo "  Run on the VPS hub:"
echo "  nrp site set-pubkey {name} $PUBLIC_KEY"
echo ""
echo "  Then verify with:"
echo "  nrp site show {name}"
"""
    return script


def get_vps_public_ip() -> str:
    """Best-effort detection of the VPS public IP (prefers routable public IP)."""
    # Try external IP detection services first (handles NAT/cloud VMs)
    for url in [
        "https://api4.my-ip.io/ip",
        "https://checkip.amazonaws.com",
        "https://ipv4.icanhazip.com",
    ]:
        try:
            result = subprocess.run(
                ["curl", "-s", "--max-time", "3", url],
                capture_output=True, text=True, check=True
            )
            ip = result.stdout.strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                # Skip RFC-1918 private addresses
                addr = ipaddress.ip_address(ip)
                if not addr.is_private:
                    return ip
        except Exception:
            pass

    # Fallback: local routing table (may return private IP behind NAT)
    try:
        result = subprocess.run(
            ["ip", "route", "get", "1"],
            capture_output=True, text=True, check=True
        )
        m = re.search(r"src\s+(\d+\.\d+\.\d+\.\d+)", result.stdout)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "<VPS_PUBLIC_IP>"

GOAL
Extend NRP (NGINX Reverse Proxy Management Tool) with:

Management of “Sites” as WireGuard‑based tunnels (hub‑and‑spoke, VPS = hub).

Ability to use tunnel IPs (10.x) as upstreams for nrp add, in addition to existing LAN IPs.

CLI extensions in the same style as existing nrp commands (Click‑based CLI).

Minimal changes to existing NGINX/Certbot logic (reuse it; only upstream IP changes).

PROJECT CONTEXT (FROM CURRENT README)
CLI entry: nrp/cli.py

Commands: nrp/commands/

add.py, remove.py, list_cmd.py, status.py, setup.py, remote_setup.py, completion.py

Core: nrp/core/

nginx.py, certbot.py, validation.py

Configuration: nrp/config.py

Templates: nrp/templates/

Existing CLI highlights:

nrp setup

nrp add

nrp remove

nrp list

nrp status

nrp remote-setup

nrp completion

NEW FUNCTIONAL REQUIREMENTS
New entity “Site”:

Represents a WireGuard “site” (spoke) attached to the VPS (hub) via a tunnel.

Each Site has:

Name (e.g. home, office).

Overlay subnet in 10.x (e.g. 10.240.12.0/28).

Connector IP inside this subnet (e.g. 10.240.12.2).

Public key (site).

Status (online/offline/pending).

Meta info (targets, email, created_at, optional OS hint).

WireGuard topology:

Hub‑and‑spoke: the VPS has a central WireGuard interface (e.g. wg0).

Each Site is a peer on wg0 with a unique AllowedIPs subnet.

Overlay network is in 10.0.0.0/8, for example fixed 10.240.0.0/16.

Do not assume that site LANs (192.168.0.0/16, etc.) are globally unique; by default, the system should use the overlay IP as upstream and not route arbitrary site LANs through the hub.

CLI extensions:

New nrp site subcommands:

nrp site create

nrp site list

nrp site show

nrp site delete

nrp site install-script

Extend nrp add with option --site (and accept 10.x tunnel IPs as --internal-ip upstreams).

Upstream behavior:

Existing NGINX templates remain mostly unchanged.

proxy_pass will often point to a tunnel IP (10.240.x.x) instead of a raw LAN IP.

Let’s Encrypt / Certbot remains on the VPS; TLS termination stays on the VPS.

SITE DATA MODEL
Create a new persistence layer for Sites (simple JSON/YAML/SQLite – whichever fits the project best). The important part is a simple and stable API.

Minimum fields per Site:

name: str # e.g. "home"

subnet: str # CIDR, e.g. "10.240.12.0/28"

connector_ip: str # e.g. "10.240.12.2"

wg_interface: str # e.g. "wg0" (on the VPS)

public_key: str # site’s public key

status: str # "pending" | "online" | "offline"

targets: int | None # estimated number of internal targets

email: str | None

created_at: datetime

Optional:

os_hint: str | None # "debian", "ubuntu", "alpine"

last_seen_at: datetime | None

notes: str | None

Additionally, maintain a view of allocated subnets, e.g.:

allocated_subnets: List[str] or a mapping Site → subnet.

NEW CLI COMMANDS (DETAIL)
1. nrp site create
Purpose: create a new Site, assign a subnet, configure a WireGuard peer for this Site on the VPS, persist Site metadata.

Syntax:

bash
nrp site create NAME [OPTIONS]
Options:

--targets INTEGER

Estimated number of internal services/targets behind the Site.

Used to choose a subnet prefix:

1–2 targets → /29

3–6 targets → /28

7–14 targets → /27

etc.

--subnet-prefix INTEGER

Explicit prefix for the Site subnet (e.g. 28 for /28).

If set, it overrides --targets.

--email TEXT

Optional email for metadata/notifications.

Example usage:

bash
# Site "home" with ~8 internal targets
nrp site create home --targets 8

# Site "office" with fixed /27 subnet
nrp site create office --subnet-prefix 27

# Site "lab" with targets and email
nrp site create lab --targets 4 --email admin@example.com
Implementation notes:

Implement CLI (Click) in a new command module nrp/commands/site.py or separate modules like site_create.py, similar to existing commands.

Add a core module nrp/core/wireguard.py with create_site(...).

WireGuard config logic in create_site:

Add new config defaults in nrp/config.py:

WG_OVERLAY_CIDR = "10.240.0.0/16"

WG_INTERFACE_NAME = "wg0"

WG_CONFIG_PATH = "/etc/wireguard/wg0.conf"

Pick an unused subnet from WG_OVERLAY_CIDR based on the desired prefix and a list of already allocated subnets.

Choose a connector IP inside that subnet (e.g. first host: network + 2).

Persist Site metadata.

Prepare WireGuard peer config on the VPS for this Site (the peer will later get its public key from the Site; initially you can store a placeholder or add the key once the Site reports it back).

A simple approach is:

At site create assign subnet and connector IP, generate a pre‑shared key if desired.

At site install-script generate the site private/public key pair on the Site and provide a mechanism for the Site to send its public key back (manual or automated).

2. nrp site list
Purpose: list all Sites.

Syntax:

bash
nrp site list
Example output (for README style):

text
NAME     SUBNET          CONNECTOR_IP   STATUS
home     10.240.12.0/28  10.240.12.2    online
office   10.240.20.0/27  10.240.20.2    offline
lab      10.240.30.0/29  10.240.30.2    pending
Implementation:

Read all Sites from the Site DB.

Optionally refresh status (e.g. via wg show, ping, or a health check) before displaying.

3. nrp site show
Purpose: show details of a single Site.

Syntax:

bash
nrp site show NAME
Example:

bash
nrp site show home
Example output:

text
Name:           home
Subnet:         10.240.12.0/28
Connector IP:   10.240.12.2
Tunnel Device:  wg0
Public Key:     <site-public-key>
Status:         online
Targets:        8
E-Mail:         admin@example.com
Created:        2026-03-10 10:15:00
Implementation:

Fetch Site from DB by name.

Optionally enrich with live status (WireGuard, connectivity).

4. nrp site delete
Purpose: delete or deactivate a Site.

Syntax:

bash
nrp site delete NAME [--keep-config]
Options:

--keep-config

Remove the active WireGuard peer from wg0.conf but keep Site metadata in the DB (useful for temporary deactivation).

Implementation:

Remove peer from WireGuard config (or mark it as disabled).

Remove any IP forwarding/firewall rules related to this Site subnet.

Delete Site from DB or mark it as deactivated depending on --keep-config.

5. nrp site install-script
Purpose: generate a shell script that will be executed on the Site host to set up the WireGuard tunnel.

Syntax:

bash
nrp site install-script NAME [--os debian|ubuntu|alpine]
Options:

--os (optional)

OS hint to adjust package install commands (e.g. apt vs apk).

Example usage:

bash
# Generate script for Site "home" (OS auto-detection in script)
nrp site install-script home > install-home.sh

# Generate script with explicit Ubuntu hint
nrp site install-script office --os ubuntu > install-office.sh
Typical workflow:

bash
# 1. Create Site
nrp site create home --targets 8

# 2. Generate install script
nrp site install-script home > install-home.sh

# 3. Copy to site and execute
scp install-home.sh user@home:/tmp/
ssh user@home 'bash /tmp/install-home.sh'

# 4. Check status
nrp site show home
nrp site list
Script skeleton (high‑level):

Install WireGuard:

Debian/Ubuntu: apt update && apt install -y wireguard

Alpine: apk add wireguard-tools etc.

Generate private/public key on the Site (wg genkey / wg pubkey).

Write wg-quick config at /etc/wireguard/wg-site-<NAME>.conf:

text
[Interface]
Address = <connector_ip>/<prefix>
PrivateKey = <SITE_PRIVATE_KEY>
DNS = optional

[Peer]
PublicKey = <HUB_PUBLIC_KEY>
Endpoint = <VPS_PUBLIC_IP>:<WG_PORT>
AllowedIPs = <WG_OVERLAY_CIDR>  # or more specific routes
PersistentKeepalive = 25
Set file permissions (chmod 600).

Enable and start interface: systemctl enable --now wg-quick@wg-site-NAME.

Optionally run a quick health check: ping the hub WG IP, run wg show.

There must be a defined mechanism for the Site’s public key to reach the hub / NRP:

Simple version: the script prints the public key and the operator manually pastes it into an nrp site set-public-key command (optional future extension).

Advanced version: script calls back to NRP via SSH/HTTP.

CHANGES TO nrp add
Current definition from README (simplified):

bash
nrp add [FQDN] [OPTIONS]

Options:
-i, --internal-ip TEXT       Internal IP address
-p, --internal-port INTEGER  Internal port
-e, --external-port INTEGER  External port (default: 443)
-s, --protocol [http|https]  Forward scheme (default: http)
-w, --websockets / -nw, --no-websockets
--email TEXT                 Email for Let’s Encrypt notifications
-o, --overwrite
-f, --full-interactive
New option:

--site TEXT

Name of an existing Site.

If set, --internal-ip must be within that Site’s subnet (validation).

Examples:

bash
# Classic use (LAN directly reachable from VPS)
nrp add api.example.com -i 192.168.1.10 -p 8080

# Using Site "home" with tunnel IP as upstream
nrp add app.example.com \
  --site home \
  --internal-ip 10.240.12.10 \
  --internal-port 3000

# Short form
nrp add app.example.com -i 10.240.12.10 -p 3000 --site home
Implementation details:

In nrp/commands/add.py:

Add a Click option --site.

If site is provided:

Load the Site from the Site DB.

Validate that internal_ip belongs to site.subnet (CIDR containment check).

Optionally check that the Site is online (e.g. ping connector_ip).

Pass internal_ip and internal_port to the NGINX template renderer exactly as today.

No changes needed in the NGINX templates if they already use variables like internal_ip and internal_port in proxy_pass.

NGINX / CERTBOT / SETUP
nrp setup:

Keep existing behavior: install NGINX, Certbot, dependencies, dummy cert, catch‑all, remove default config.

Optionally extend to:

Install WireGuard packages on the VPS.

Create a base wg0 config for the hub (or let this be done lazily on first site create).

Let’s Encrypt:

No change required; certificates terminate at the VPS.

nrp add continues to request/renew certs as before.

SECURITY / ROUTING NOTES
VPS:

Enable IP forwarding (net.ipv4.ip_forward=1).

Add firewall rules to allow traffic from wg0 to the relevant local ports, but do not expose the wireguard interface services to the public unnecessarily.

WireGuard AllowedIPs:

Each Site has a unique subnet, set as AllowedIPs for that peer.

No overlapping AllowedIPs on the same interface.

Overlay vs LAN:

Overlay: 10.240.0.0/16 (configurable).

Site LANs (192.168.x.x etc.) are not globally routable by default; the default model is that the VPS talks to the Site’s overlay IP, and the Site then forwards traffic locally.

README EXTENSIONS (SUMMARY)
Add a new section “Site management (WireGuard tunnels)” with examples:

bash
# Create site
nrp site create home --targets 8

# Generate install script
nrp site install-script home > install-home.sh

# Run on site
scp install-home.sh user@home:/tmp/
ssh user@home 'bash /tmp/install-home.sh'

# Show sites
nrp site list
nrp site show home
Extend “Proxy host creation” with a tunnel example:

bash
# Proxy host via WireGuard site "home"
nrp add app.example.com \
  --site home \
  --internal-ip 10.240.12.10 \
  --internal-port 3000 \
  --external-port 443 \
  --protocol http
IMPLEMENTATION TODO LIST
Create nrp/core/wireguard.py

Functions:

create_site(name, targets, subnet_prefix, email)

list_sites()

get_site(name)

delete_site(name, keep_config)

generate_install_script(name, os_hint=None)

Helpers for subnet allocation and WireGuard config updates.

Site persistence

Implement a simple Site DB:

JSON or SQLite file in a folder already used by NRP.

Provide CRUD operations.

Create new command modules

nrp/commands/site.py (or separate modules) with Click commands for:

site create

site list

site show

site delete

site install-script

Update nrp/cli.py

Register the site command group, consistent with existing style.

Update nrp/commands/add.py

Add --site option.

Implement Site lookup and internal IP validation.

Update nrp/config.py

Add:

WG_OVERLAY_CIDR

WG_INTERFACE_NAME

WG_CONFIG_PATH

WG_PORT (default WireGuard UDP port).
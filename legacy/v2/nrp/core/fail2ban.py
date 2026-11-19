"""
Fail2Ban core logic - manage NRP-managed jails and filter definitions
"""
import subprocess
from pathlib import Path

from nrp.config import (
    F2B_NRP_JAIL_CONF,
    F2B_FILTER_404,
    F2B_FILTER_SCANNERS,
    F2B_JAIL_DIR,
    F2B_FILTER_DIR,
)

# ── Jail configuration ────────────────────────────────────────────────────────

_JAIL_BASE = """\
# NRP-managed Fail2Ban configuration
# Do not edit manually - use 'nrp f2b enable/disable'

[DEFAULT]
bantime  = 24h
findtime = 10m
maxretry = 5
backend  = auto
banaction = iptables-allports

[nginx-http-auth]
enabled = true

[nginx-botsearch]
enabled = true

[nginx-404]
enabled  = true
port     = http,https
filter   = nginx-404
logpath  = /var/log/nginx/access.log
maxretry = 30
findtime = 60
bantime  = 12h
"""

_JAIL_SCANNERS = """
[nginx-scanners]
enabled  = true
port     = http,https
filter   = nginx-scanners
logpath  = /var/log/nginx/access.log
maxretry = 2
findtime = 10m
bantime  = 24h
"""

# ── Filter definitions ────────────────────────────────────────────────────────

_FILTER_404 = """\
# NRP-managed filter - do not edit manually
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*" 404
ignoreregex =
"""

_FILTER_SCANNERS = """\
# NRP-managed filter - do not edit manually
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*\\/wp-login\\.php
            ^<HOST> -.*"(GET|POST).*\\/wp-admin
            ^<HOST> -.*"(GET|POST).*\\/xmlrpc\\.php
            ^<HOST> -.*"(GET|POST).*\\/wordpress
            ^<HOST> -.*"(GET|POST).*\\/phpmyadmin
            ^<HOST> -.*"(GET|POST).*\\/.env
            ^<HOST> -.*"(GET|POST).*\\/.git
ignoreregex =
"""


def _fail2ban_installed() -> bool:
    result = subprocess.run(
        ["which", "fail2ban-client"], capture_output=True
    )
    return result.returncode == 0


def _fail2ban_running() -> bool:
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", "fail2ban"], capture_output=True
    )
    return result.returncode == 0


def enable(with_scanners: bool = False) -> dict:
    """
    Install fail2ban (if needed), write config files, enable and start the service.
    Returns a dict with info about what was done.
    """
    result = {"installed_package": False, "with_scanners": with_scanners, "jails": []}

    # Install fail2ban if not present
    if not _fail2ban_installed():
        subprocess.run(["apt", "update"], check=True, capture_output=True)
        subprocess.run(["apt", "install", "-y", "fail2ban"], check=True)
        result["installed_package"] = True

    # Ensure directories exist
    F2B_JAIL_DIR.mkdir(parents=True, exist_ok=True)
    F2B_FILTER_DIR.mkdir(parents=True, exist_ok=True)

    # Write jail config
    jail_content = _JAIL_BASE
    if with_scanners:
        jail_content += _JAIL_SCANNERS
    F2B_NRP_JAIL_CONF.write_text(jail_content)

    # Write filter: nginx-404
    F2B_FILTER_404.write_text(_FILTER_404)

    # Write filter: nginx-scanners (always write so it's available)
    F2B_FILTER_SCANNERS.write_text(_FILTER_SCANNERS)

    # Enable and start fail2ban
    subprocess.run(["systemctl", "enable", "fail2ban"], check=True, capture_output=True)
    subprocess.run(["systemctl", "start", "fail2ban"], check=True, capture_output=True)

    # Reload to pick up new jails
    subprocess.run(["fail2ban-client", "reload"], check=True, capture_output=True)

    result["jails"] = ["nginx-http-auth", "nginx-botsearch", "nginx-404"]
    if with_scanners:
        result["jails"].append("nginx-scanners")

    return result


def disable() -> None:
    """
    Remove NRP-managed jail config and filter files, reload fail2ban.
    Does NOT stop or remove fail2ban itself.
    """
    removed = []

    if F2B_NRP_JAIL_CONF.exists():
        F2B_NRP_JAIL_CONF.unlink()
        removed.append(str(F2B_NRP_JAIL_CONF))

    if F2B_FILTER_404.exists():
        F2B_FILTER_404.unlink()
        removed.append(str(F2B_FILTER_404))

    if F2B_FILTER_SCANNERS.exists():
        F2B_FILTER_SCANNERS.unlink()
        removed.append(str(F2B_FILTER_SCANNERS))

    if _fail2ban_running():
        subprocess.run(["fail2ban-client", "reload"], check=True, capture_output=True)

    return removed


def is_enabled() -> bool:
    """Returns True if the NRP jail config exists."""
    return F2B_NRP_JAIL_CONF.exists()


def has_scanners() -> bool:
    """Returns True if the scanner jail is active in the NRP config."""
    if not F2B_NRP_JAIL_CONF.exists():
        return False
    return "nginx-scanners" in F2B_NRP_JAIL_CONF.read_text()


def get_status() -> dict:
    """
    Returns current status: whether enabled, which jails are active,
    and (if fail2ban is running) live ban counts from fail2ban-client.
    """
    status = {
        "enabled": is_enabled(),
        "running": _fail2ban_running(),
        "with_scanners": has_scanners(),
        "jails": {},
    }

    if not status["running"]:
        return status

    active_jails = ["nginx-http-auth", "nginx-botsearch", "nginx-404"]
    if status["with_scanners"]:
        active_jails.append("nginx-scanners")

    for jail in active_jails:
        result = subprocess.run(
            ["fail2ban-client", "status", jail],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            banned = 0
            for line in result.stdout.splitlines():
                if "Currently banned" in line:
                    try:
                        banned = int(line.split(":")[-1].strip())
                    except ValueError:
                        pass
            status["jails"][jail] = {"banned": banned}
        else:
            status["jails"][jail] = {"banned": "?"}

    return status

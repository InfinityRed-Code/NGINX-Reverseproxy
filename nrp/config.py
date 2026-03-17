"""
Configuration settings for NRP
"""
from pathlib import Path

# NGINX Configuration
NGINX_CONF_DIR = Path("/etc/nginx/conf.d")
NGINX_HTML_DIR = Path("/usr/share/nginx/html")
NGINX_SSL_DIR = Path("/etc/nginx/ssl")

# LetsEncrypt Configuration
LETSENCRYPT_DIR = Path("/etc/letsencrypt")
LETSENCRYPT_LIVE_DIR = LETSENCRYPT_DIR / "live"
LETSENCRYPT_OPTIONS_SSL = LETSENCRYPT_DIR / "options-ssl-nginx.conf"
LETSENCRYPT_SSL_DHPARAM = LETSENCRYPT_DIR / "ssl-dhparams.pem"

# Remote Execution Settings
DEFAULT_REMOTE_USER = "autonginx"
DEFAULT_SCRIPT_PATH = "/opt/NGINX-Reverseproxy"

# Template Directory (relative to this file)
TEMPLATE_DIR = Path(__file__).parent / "templates"

# Default Values
DEFAULT_CLIENT_MAX_BODY_SIZE = "100M"
DEFAULT_HSTS_MAX_AGE = 31536000  # 1 year in seconds

# WireGuard Configuration
WG_OVERLAY_CIDR = "10.240.0.0/16"
WG_INTERFACE_NAME = "wg0"
WG_CONFIG_PATH = Path("/etc/wireguard/wg0.conf")
WG_PORT = 51825

# NRP Data Directory (Site DB etc.)
NRP_DATA_DIR = Path("/var/lib/nrp")
SITES_DB_PATH = NRP_DATA_DIR / "sites.json"

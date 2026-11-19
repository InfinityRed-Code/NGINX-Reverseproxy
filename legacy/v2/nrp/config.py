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

# Fail2Ban Configuration
F2B_JAIL_DIR = Path("/etc/fail2ban/jail.d")
F2B_FILTER_DIR = Path("/etc/fail2ban/filter.d")
F2B_NRP_JAIL_CONF = F2B_JAIL_DIR / "nrp.conf"
F2B_FILTER_404 = F2B_FILTER_DIR / "nginx-404.conf"
F2B_FILTER_SCANNERS = F2B_FILTER_DIR / "nginx-scanners.conf"

# Coraza WAF Configuration
WAF_BUILD_DIR = Path("/usr/local/src/nrp-coraza")
WAF_CONF_DIR = Path("/etc/nginx/coraza")
WAF_MAIN_CONF = WAF_CONF_DIR / "main.conf"
WAF_CORAZA_CONF = WAF_CONF_DIR / "coraza.conf"
WAF_CRS_DIR = WAF_CONF_DIR / "coreruleset"
WAF_CRS_SETUP_CONF = WAF_CONF_DIR / "crs-setup.conf"
WAF_AUDIT_LOG = Path("/var/log/nginx/coraza_audit.log")
WAF_MODULE_PATH = Path("/usr/lib/nginx/modules/ngx_http_coraza_module.so")
WAF_MODULE_LOAD_CONF = Path("/etc/nginx/modules-enabled/50-mod-http-coraza.conf")
WAF_LIBCORAZA_REPO = "https://github.com/corazawaf/libcoraza"
WAF_CORAZA_NGINX_REPO = "https://github.com/corazawaf/coraza-nginx"
WAF_CRS_REPO = "https://github.com/coreruleset/coreruleset"
WAF_CRS_VERSION = "v4.16.0"  # OWASP Core Rule Set Release-Tag

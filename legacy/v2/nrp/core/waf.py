"""
Coraza WAF core logic - build the coraza-nginx module and manage
the globally shared rule set (Coraza recommended config + OWASP CRS).

Upstream projects:
  - https://github.com/corazawaf/coraza-nginx  (NGINX connector, dynamic module)
  - https://github.com/corazawaf/libcoraza     (C library around the Coraza engine)
  - https://github.com/coreruleset/coreruleset (OWASP Core Rule Set)
"""
import re
import shutil
import subprocess
from pathlib import Path

from nrp.config import (
    WAF_BUILD_DIR,
    WAF_CONF_DIR,
    WAF_MAIN_CONF,
    WAF_CORAZA_CONF,
    WAF_CRS_DIR,
    WAF_CRS_SETUP_CONF,
    WAF_AUDIT_LOG,
    WAF_MODULE_PATH,
    WAF_MODULE_LOAD_CONF,
    WAF_LIBCORAZA_REPO,
    WAF_CORAZA_NGINX_REPO,
    WAF_CRS_REPO,
    WAF_CRS_VERSION,
    NGINX_CONF_DIR,
)

# ── Global rule set ───────────────────────────────────────────────────────────
# Basiert auf der Coraza recommended configuration. Blocking erfolgt über das
# Anomaly-Scoring des OWASP CRS (Paranoia Level 1), nicht über SecDefaultAction.

_CORAZA_CONF_TEMPLATE = """\
# NRP-managed Coraza base configuration
# Do not edit manually - use 'nrp waf enable/disable'
# Engine-Modus: On = blockieren, DetectionOnly = nur loggen, Off = deaktiviert

SecRuleEngine {engine}

# Request-Body-Inspektion (POST-Daten, JSON, Uploads)
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyLimitAction Reject

# Response-Body-Inspektion (teuer, standardmaessig aus)
SecResponseBodyAccess Off

# Audit-Log: nur relevante Ereignisse (4xx/5xx ausser 404)
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecAuditLogFormat JSON
SecAuditLog {audit_log}

SecArgumentSeparator &
SecCookieFormat 0
"""

_MAIN_CONF = """\
# NRP-managed Coraza rule chain
# Do not edit manually - use 'nrp waf enable/disable'
# Eingebunden pro Proxy-Host via: coraza_rules_file {main_conf}

Include {coraza_conf}
Include {crs_setup}
Include {crs_rules}/*.conf
"""

_LOAD_MODULE_CONF = """\
# NRP-managed - loads the Coraza WAF dynamic module
load_module modules/ngx_http_coraza_module.so;
"""

# Build-Abhaengigkeiten fuer libcoraza (Go, autotools) und das NGINX-Modul
_BUILD_PACKAGES = [
    "git", "build-essential", "autoconf", "automake", "libtool",
    "pkg-config", "golang-go", "libpcre2-dev", "zlib1g-dev", "libssl-dev",
]

_MIN_GO_VERSION = (1, 24)


# ── Status helpers ────────────────────────────────────────────────────────────

def is_module_built() -> bool:
    """True wenn das kompilierte NGINX-Modul vorhanden ist."""
    return WAF_MODULE_PATH.exists()


def is_installed() -> bool:
    """True wenn Modul UND globales Regelwerk vorhanden sind."""
    return (
        is_module_built()
        and WAF_MODULE_LOAD_CONF.exists()
        and WAF_MAIN_CONF.exists()
        and WAF_CORAZA_CONF.exists()
    )


def get_engine_mode() -> str:
    """Liest den SecRuleEngine-Modus aus der Basis-Konfiguration."""
    if not WAF_CORAZA_CONF.exists():
        return "not-installed"
    match = re.search(r"^SecRuleEngine\s+(\S+)", WAF_CORAZA_CONF.read_text(), re.MULTILINE)
    return match.group(1) if match else "unknown"


def list_waf_hosts() -> list[str]:
    """Listet alle Proxy-Hosts, in deren Konfiguration Coraza aktiviert ist."""
    hosts = []
    if not NGINX_CONF_DIR.exists():
        return hosts
    for conf_file in NGINX_CONF_DIR.glob("*.conf"):
        if conf_file.name == "catch-all.conf":
            continue
        try:
            content = conf_file.read_text()
        except OSError:
            continue
        if re.search(r"^\s*coraza\s+on\s*;", content, re.MULTILINE):
            hosts.append(conf_file.stem)
    return sorted(hosts)


def get_status() -> dict:
    return {
        "module_built": is_module_built(),
        "module_loaded_conf": WAF_MODULE_LOAD_CONF.exists(),
        "rules_installed": WAF_MAIN_CONF.exists() and WAF_CORAZA_CONF.exists(),
        "crs_installed": WAF_CRS_DIR.exists() and any(WAF_CRS_DIR.glob("rules/*.conf")),
        "engine": get_engine_mode(),
        "hosts": list_waf_hosts(),
        "audit_log": str(WAF_AUDIT_LOG),
    }


# ── Build steps ───────────────────────────────────────────────────────────────

def _run(cmd: list[str], cwd: Path = None, capture: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, cwd=str(cwd) if cwd else None, check=True,
        capture_output=capture, text=True,
    )


def check_go_version() -> tuple[bool, str]:
    """Prueft ob Go in ausreichender Version vorhanden ist."""
    try:
        out = _run(["go", "version"], capture=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False, "nicht gefunden"
    match = re.search(r"go(\d+)\.(\d+)", out)
    if not match:
        return False, out.strip()
    version = (int(match.group(1)), int(match.group(2)))
    return version >= _MIN_GO_VERSION, f"{version[0]}.{version[1]}"


def install_build_dependencies() -> None:
    _run(["apt", "update"])
    _run(["apt", "install", "-y"] + _BUILD_PACKAGES)


def get_nginx_version() -> str:
    """Ermittelt die installierte NGINX-Version (z.B. '1.26.3')."""
    result = subprocess.run(["nginx", "-v"], capture_output=True, text=True)
    # nginx schreibt die Version nach stderr: "nginx version: nginx/1.26.3"
    output = result.stderr or result.stdout
    match = re.search(r"nginx/(\d+\.\d+\.\d+)", output)
    if not match:
        raise RuntimeError(f"NGINX-Version nicht erkennbar: {output.strip()}")
    return match.group(1)


def _clone_or_update(repo: str, dest: Path, branch: str = None) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    cmd = ["git", "clone", "--depth", "1"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [repo, str(dest)]
    _run(cmd)


def build_libcoraza() -> None:
    """Klont und baut libcoraza, installiert nach /usr/local."""
    src = WAF_BUILD_DIR / "libcoraza"
    _clone_or_update(WAF_LIBCORAZA_REPO, src)
    _run(["./build.sh"], cwd=src)
    _run(["./configure"], cwd=src)
    _run(["make"], cwd=src)
    _run(["make", "install"], cwd=src)
    _run(["ldconfig"])


def build_nginx_module() -> None:
    """
    Laedt den NGINX-Quellcode passend zur installierten Version herunter
    und baut coraza-nginx als dynamisches Modul (--with-compat).
    """
    version = get_nginx_version()
    connector = WAF_BUILD_DIR / "coraza-nginx"
    _clone_or_update(WAF_CORAZA_NGINX_REPO, connector)

    tarball = WAF_BUILD_DIR / f"nginx-{version}.tar.gz"
    src = WAF_BUILD_DIR / f"nginx-{version}"
    _run([
        "curl", "-fsSL", "-o", str(tarball),
        f"https://nginx.org/download/nginx-{version}.tar.gz",
    ])
    if src.exists():
        shutil.rmtree(src)
    _run(["tar", "-xzf", str(tarball), "-C", str(WAF_BUILD_DIR)])

    _run([
        "./configure", "--with-compat",
        f"--add-dynamic-module={connector}",
    ], cwd=src)
    _run(["make", "modules"], cwd=src)

    WAF_MODULE_PATH.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src / "objs" / "ngx_http_coraza_module.so", WAF_MODULE_PATH)


def write_module_load_conf() -> bool:
    """
    Schreibt die load_module-Konfiguration. Debian laedt Module ueber
    'include /etc/nginx/modules-enabled/*.conf;' in der nginx.conf.
    Returns True wenn nginx.conf das Include bereits enthaelt.
    """
    WAF_MODULE_LOAD_CONF.parent.mkdir(parents=True, exist_ok=True)
    WAF_MODULE_LOAD_CONF.write_text(_LOAD_MODULE_CONF)

    nginx_conf = Path("/etc/nginx/nginx.conf")
    if nginx_conf.exists() and "modules-enabled" in nginx_conf.read_text():
        return True
    return False


def install_crs(crs_version: str = WAF_CRS_VERSION) -> None:
    """Laedt das OWASP Core Rule Set und aktiviert die Standard-Konfiguration."""
    WAF_CONF_DIR.mkdir(parents=True, exist_ok=True)
    _clone_or_update(WAF_CRS_REPO, WAF_CRS_DIR, branch=crs_version)
    # Beispiel-Setup ist der offizielle Standard: Anomaly Scoring, Paranoia Level 1
    example = WAF_CRS_DIR / "crs-setup.conf.example"
    if not WAF_CRS_SETUP_CONF.exists():
        shutil.copy2(example, WAF_CRS_SETUP_CONF)


def write_rule_configs(detection_only: bool = False) -> None:
    """Schreibt Basis-Konfiguration und globale Regelkette."""
    WAF_CONF_DIR.mkdir(parents=True, exist_ok=True)
    engine = "DetectionOnly" if detection_only else "On"
    WAF_CORAZA_CONF.write_text(
        _CORAZA_CONF_TEMPLATE.format(engine=engine, audit_log=WAF_AUDIT_LOG)
    )
    WAF_MAIN_CONF.write_text(_MAIN_CONF.format(
        main_conf=WAF_MAIN_CONF,
        coraza_conf=WAF_CORAZA_CONF,
        crs_setup=WAF_CRS_SETUP_CONF,
        crs_rules=WAF_CRS_DIR / "rules",
    ))


def set_engine_mode(mode: str) -> None:
    """Setzt SecRuleEngine auf On, DetectionOnly oder Off."""
    if not WAF_CORAZA_CONF.exists():
        raise RuntimeError("Coraza-Basis-Konfiguration nicht gefunden - zuerst 'nrp waf enable' ausführen.")
    content = WAF_CORAZA_CONF.read_text()
    content = re.sub(r"^SecRuleEngine\s+\S+", f"SecRuleEngine {mode}", content, flags=re.MULTILINE)
    WAF_CORAZA_CONF.write_text(content)

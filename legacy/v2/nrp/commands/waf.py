"""
waf command group - manage the Coraza WAF integration for NGINX
"""
import os
import sys
import subprocess
import click

from nrp.core import waf as waf_core
from nrp.core.nginx import NginxManager
from nrp.config import WAF_CRS_VERSION, WAF_MAIN_CONF, WAF_BUILD_DIR


@click.group()
def waf():
    """
    Verwaltet die Coraza WAF-Integration für NGINX

    Kompiliert das coraza-nginx Modul, installiert das OWASP
    Core Rule Set und stellt ein globales Regelwerk bereit,
    das pro Proxy-Host aktiviert werden kann (nrp add --waf).

    Typischer Workflow:

    \b
        sudo nrp waf enable
        sudo nrp waf enable --detection-only
        nrp waf status
        sudo nrp waf disable
    """
    pass


# ── enable ────────────────────────────────────────────────────────────────────

@waf.command(name="enable")
@click.option("--detection-only", is_flag=True, default=False,
              help="Angriffe nur loggen statt blockieren (SecRuleEngine DetectionOnly)")
@click.option("--crs-version", default=WAF_CRS_VERSION, show_default=True,
              help="Release-Tag des OWASP Core Rule Set")
@click.option("--rebuild", is_flag=True, default=False,
              help="Modul neu kompilieren, auch wenn es bereits existiert (z.B. nach NGINX-Update)")
def waf_enable(detection_only, crs_version, rebuild):
    """
    Aktiviert die Coraza WAF mit global sinnvollen Regeln

    Baut libcoraza und das coraza-nginx Modul (einmalig, dauert
    einige Minuten), installiert das OWASP Core Rule Set und
    schreibt das globale Regelwerk:

    \b
        Coraza recommended config  – Engine, Body-Limits, Audit-Log
        OWASP CRS (Paranoia Level 1) – SQLi, XSS, RCE, LFI/RFI,
                                       Protokoll-Anomalien, Scanner

    Die WAF wird danach pro Proxy-Host aktiviert:

    \b
        nrp add example.com --waf ...
        (oder interaktive Abfrage bei 'nrp add')

    Beispiele:

    \b
        sudo nrp waf enable
        sudo nrp waf enable --detection-only
        sudo nrp waf enable --rebuild
    """
    _require_root()

    click.echo("\n=== Coraza WAF aktivieren ===\n")

    build_needed = rebuild or not waf_core.is_module_built()

    if build_needed:
        click.echo("1. Installiere Build-Abhängigkeiten (git, golang, autotools, ...)...")
        try:
            waf_core.install_build_dependencies()
        except subprocess.CalledProcessError as e:
            click.echo(click.style(f"  ✗ Paketinstallation fehlgeschlagen: {e}", fg="red"))
            sys.exit(1)
        click.echo(click.style("  ✓ Build-Abhängigkeiten installiert", fg="green"))

        go_ok, go_version = waf_core.check_go_version()
        if not go_ok:
            click.echo(click.style(
                f"  ⚠ Go-Version {go_version} ist möglicherweise zu alt für libcoraza. "
                "Falls der Build fehlschlägt, aktuelles Go von https://go.dev/dl/ installieren.",
                fg="yellow"
            ))

        WAF_BUILD_DIR.mkdir(parents=True, exist_ok=True)

        click.echo("\n2. Baue libcoraza (Coraza-Engine)...")
        try:
            waf_core.build_libcoraza()
        except subprocess.CalledProcessError as e:
            click.echo(click.style(f"  ✗ libcoraza-Build fehlgeschlagen: {e}", fg="red"))
            sys.exit(1)
        click.echo(click.style("  ✓ libcoraza installiert", fg="green"))

        click.echo("\n3. Baue coraza-nginx als dynamisches Modul...")
        try:
            waf_core.build_nginx_module()
        except (subprocess.CalledProcessError, RuntimeError) as e:
            click.echo(click.style(f"  ✗ Modul-Build fehlgeschlagen: {e}", fg="red"))
            sys.exit(1)
        click.echo(click.style("  ✓ ngx_http_coraza_module.so installiert", fg="green"))
    else:
        click.echo("1.-3. Modul bereits gebaut, Build übersprungen (--rebuild erzwingt Neubau)")

    click.echo("\n4. Aktiviere Modul in NGINX...")
    include_present = waf_core.write_module_load_conf()
    if include_present:
        click.echo(click.style("  ✓ load_module-Konfiguration geschrieben", fg="green"))
    else:
        click.echo(click.style(
            "  ⚠ /etc/nginx/nginx.conf enthält kein 'include /etc/nginx/modules-enabled/*.conf;'.\n"
            "    Bitte folgende Zeile manuell an den Anfang der nginx.conf setzen:\n"
            "    load_module modules/ngx_http_coraza_module.so;",
            fg="yellow"
        ))

    click.echo(f"\n5. Installiere OWASP Core Rule Set ({crs_version})...")
    try:
        waf_core.install_crs(crs_version)
    except subprocess.CalledProcessError as e:
        click.echo(click.style(f"  ✗ CRS-Download fehlgeschlagen: {e}", fg="red"))
        sys.exit(1)
    click.echo(click.style("  ✓ Core Rule Set installiert", fg="green"))

    click.echo("\n6. Schreibe globales Regelwerk...")
    engine = "DetectionOnly" if detection_only else "On"
    waf_core.write_rule_configs(detection_only=detection_only)
    click.echo(click.style(f"  ✓ Regelwerk geschrieben (SecRuleEngine {engine})", fg="green"))

    click.echo("\n7. Teste Konfiguration und starte NGINX neu...")
    nginx = NginxManager()
    if not nginx.test_config():
        click.echo(click.style("  ✗ nginx -t fehlgeschlagen - bitte Ausgabe prüfen", fg="red"))
        sys.exit(1)
    try:
        # Neustart statt Reload: dynamische Module werden erst beim Start geladen
        subprocess.run(["systemctl", "restart", "nginx"], check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        click.echo(click.style(f"  ✗ NGINX-Neustart fehlgeschlagen: {e}", fg="red"))
        sys.exit(1)
    click.echo(click.style("  ✓ NGINX neu gestartet", fg="green"))

    click.echo(click.style("\n✓ Coraza WAF erfolgreich aktiviert!", fg="green", bold=True))
    if detection_only:
        click.echo(click.style(
            "\nModus: DetectionOnly - Angriffe werden nur geloggt, nicht blockiert.\n"
            "Nach einer Beobachtungsphase blockierend schalten mit:\n"
            "  sudo nrp waf enable",
            fg="yellow"
        ))
    click.echo("\nWAF pro Proxy-Host aktivieren mit:")
    click.echo("  nrp add example.com --waf ...")
    click.echo("\nBestehende Hosts erhalten die WAF durch erneutes Anlegen:")
    click.echo("  nrp add example.com --waf --overwrite ...")


# ── disable ───────────────────────────────────────────────────────────────────

@waf.command(name="disable")
@click.option("--yes", "-y", is_flag=True, default=False,
              help="Ohne Bestätigungsfrage deaktivieren")
def waf_disable(yes):
    """
    Deaktiviert die Coraza WAF global (SecRuleEngine Off)

    Setzt die Engine auf Off - alle Regeln bleiben installiert,
    Requests werden aber nicht mehr geprüft oder blockiert.
    Modul und Regelwerk bleiben erhalten, damit bestehende
    Host-Konfigurationen gültig bleiben.

    Beispiel:

    \b
        sudo nrp waf disable
    """
    _require_root()

    if not waf_core.is_installed():
        click.echo(click.style("Coraza WAF ist nicht installiert.", fg="yellow"))
        return

    if not yes:
        confirmed = click.confirm(
            "Coraza WAF wirklich global deaktivieren (SecRuleEngine Off)?", default=False
        )
        if not confirmed:
            click.echo("Abgebrochen.")
            return

    try:
        waf_core.set_engine_mode("Off")
    except RuntimeError as e:
        click.echo(click.style(f"Fehler: {e}", fg="red"))
        sys.exit(1)

    nginx = NginxManager()
    if not nginx.test_config() or not nginx.reload():
        click.echo(click.style("Fehler beim Neuladen von NGINX.", fg="red"))
        sys.exit(1)

    click.echo(click.style("\n✓ Coraza WAF deaktiviert (SecRuleEngine Off).", fg="green"))
    click.echo("Wieder aktivieren mit: sudo nrp waf enable")


# ── status ────────────────────────────────────────────────────────────────────

@waf.command(name="status")
def waf_status():
    """
    Zeigt den aktuellen WAF-Status

    Listet Modul-, Regelwerk- und Engine-Status sowie alle
    Proxy-Hosts mit aktivierter WAF auf.

    Beispiel:

    \b
        nrp waf status
    """
    status = waf_core.get_status()

    def mark(ok: bool) -> str:
        return click.style("✓", fg="green") if ok else click.style("✗", fg="red")

    engine = status["engine"]
    engine_color = {"On": "green", "DetectionOnly": "yellow"}.get(engine, "red")

    click.echo()
    click.echo(f"Modul gebaut:        {mark(status['module_built'])}")
    click.echo(f"Modul geladen:       {mark(status['module_loaded_conf'])}")
    click.echo(f"Regelwerk:           {mark(status['rules_installed'])}")
    click.echo(f"OWASP CRS:           {mark(status['crs_installed'])}")
    click.echo(f"Engine-Modus:        {click.style(engine, fg=engine_color)}")
    click.echo(f"Audit-Log:           {status['audit_log']}")

    click.echo()
    if status["hosts"]:
        click.echo(f"Hosts mit aktiver WAF ({len(status['hosts'])}):")
        for host in status["hosts"]:
            click.echo(click.style(f"  ✓ {host}", fg="green"))
    else:
        click.echo("Keine Proxy-Hosts mit aktivierter WAF.")
        if waf_core.is_installed():
            click.echo("Aktivieren mit: nrp add <FQDN> --waf ...")
        else:
            click.echo("WAF installieren mit: sudo nrp waf enable")
    click.echo()


# ── helper ────────────────────────────────────────────────────────────────────

def _require_root():
    if os.geteuid() != 0:
        click.echo(click.style("Fehler: Dieser Befehl muss als root ausgeführt werden.", fg="red"))
        click.echo("Bitte verwenden Sie: sudo nrp waf ...")
        sys.exit(1)

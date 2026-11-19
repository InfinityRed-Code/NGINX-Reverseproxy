"""
f2b command group - manage Fail2Ban integration for NGINX
"""
import sys
import subprocess
import click

from nrp.core import fail2ban as f2b_core


@click.group()
def f2b():
    """
    Verwaltet die Fail2Ban-Integration für NGINX

    Schützt den Reverse Proxy automatisch vor Brute-Force,
    Bot-Scans und weiteren Angriffsmustern.

    Typischer Workflow:

    \b
        nrp f2b enable
        nrp f2b enable --with-scanners
        nrp f2b status
        nrp f2b disable
    """
    pass


# ── enable ────────────────────────────────────────────────────────────────────

@f2b.command(name="enable")
@click.option("--with-scanners", is_flag=True, default=False,
              help="Zusätzlich den Scanner-Jail aktivieren (erkennt WP, phpMyAdmin, .env, .git, …)")
def f2b_enable(with_scanners):
    """
    Aktiviert Fail2Ban mit NRP-Standard-Jails

    Installiert fail2ban falls nötig, schreibt alle Jail- und
    Filter-Konfigurationen und startet den Dienst.

    Aktivierte Jails (Standard):

    \b
        nginx-http-auth   – Brute-Force auf HTTP-Auth
        nginx-botsearch   – Bot/Scanner-Erkennung (built-in)
        nginx-404         – IP-Banning bei vielen 404-Fehlern

    Mit --with-scanners zusätzlich:

    \b
        nginx-scanners    – WP-Login, phpMyAdmin, .env, .git, …

    Beispiele:

    \b
        sudo nrp f2b enable
        sudo nrp f2b enable --with-scanners
    """
    _require_root()

    click.echo("\n=== Fail2Ban aktivieren ===\n")

    if f2b_core.is_enabled():
        click.echo(click.style("Fail2Ban ist bereits aktiviert.", fg="yellow"))
        current_scanners = f2b_core.has_scanners()
        if with_scanners and not current_scanners:
            click.echo("Aktualisiere Konfiguration mit Scanner-Jail...")
        elif not with_scanners and current_scanners:
            click.echo("Hinweis: Scanner-Jail war aktiv, wird deaktiviert.")
        else:
            click.echo("Konfiguration wird neu geschrieben und neu geladen.")

    click.echo("1. Schreibe Konfiguration...")
    try:
        result = f2b_core.enable(with_scanners=with_scanners)
    except subprocess.CalledProcessError as e:
        click.echo(click.style(f"  ✗ Fehler: {e}", fg="red"))
        sys.exit(1)

    if result["installed_package"]:
        click.echo(click.style("  ✓ fail2ban installiert", fg="green"))
    click.echo(click.style("  ✓ Jail-Konfiguration geschrieben", fg="green"))
    click.echo(click.style("  ✓ Filter nginx-404 geschrieben", fg="green"))
    click.echo(click.style("  ✓ Filter nginx-scanners geschrieben", fg="green"))

    click.echo("\n2. Aktivierte Jails:")
    for jail in result["jails"]:
        click.echo(click.style(f"  ✓ {jail}", fg="green"))

    click.echo(click.style("\n✓ Fail2Ban erfolgreich aktiviert!", fg="green", bold=True))
    click.echo("\nStatus anzeigen mit:")
    click.echo("  nrp f2b status")


# ── disable ───────────────────────────────────────────────────────────────────

@f2b.command(name="disable")
@click.option("--yes", "-y", is_flag=True, default=False,
              help="Ohne Bestätigungsfrage deaktivieren")
def f2b_disable(yes):
    """
    Deaktiviert Fail2Ban (entfernt NRP-Konfiguration)

    Entfernt die von NRP verwalteten Jail- und Filter-Dateien
    und lädt fail2ban neu. fail2ban selbst wird nicht deinstalliert.

    Beispiel:

    \b
        sudo nrp f2b disable
    """
    _require_root()

    if not f2b_core.is_enabled():
        click.echo(click.style("Fail2Ban ist nicht aktiviert.", fg="yellow"))
        return

    if not yes:
        confirmed = click.confirm(
            "NRP-Fail2Ban-Konfiguration wirklich entfernen?", default=False
        )
        if not confirmed:
            click.echo("Abgebrochen.")
            return

    try:
        removed = f2b_core.disable()
    except subprocess.CalledProcessError as e:
        click.echo(click.style(f"Fehler: {e}", fg="red"))
        sys.exit(1)

    click.echo(click.style("\n✓ Fail2Ban-Konfiguration entfernt.", fg="green"))
    for path in removed:
        click.echo(f"  - {path}")
    click.echo("\nfail2ban läuft weiter, aber ohne NRP-Jails.")


# ── status ────────────────────────────────────────────────────────────────────

@f2b.command(name="status")
def f2b_status():
    """
    Zeigt den aktuellen Fail2Ban-Status

    Listet aktive Jails und die Anzahl aktuell gebannter IPs auf.

    Beispiel:

    \b
        nrp f2b status
    """
    status = f2b_core.get_status()

    click.echo()
    enabled_str = click.style("aktiviert", fg="green") if status["enabled"] else click.style("deaktiviert", fg="red")
    running_str = click.style("läuft", fg="green") if status["running"] else click.style("gestoppt", fg="red")
    scanners_str = click.style("ja", fg="green") if status["with_scanners"] else "nein"

    click.echo(f"NRP-Konfiguration:  {enabled_str}")
    click.echo(f"Fail2Ban-Dienst:    {running_str}")
    click.echo(f"Scanner-Jail:       {scanners_str}")

    if status["jails"]:
        click.echo()
        col = (22, 14)
        header = f"{'JAIL':<{col[0]}}{'GEBANNTE IPs':<{col[1]}}"
        click.echo(header)
        click.echo("─" * sum(col))
        for jail, info in status["jails"].items():
            banned = info["banned"]
            color = "red" if isinstance(banned, int) and banned > 0 else "white"
            click.echo(
                f"{jail:<{col[0]}}"
                + click.style(f"{banned:<{col[1]}}", fg=color)
            )
        click.echo()
    elif status["enabled"] and not status["running"]:
        click.echo(click.style(
            "\nfail2ban ist nicht aktiv. Starten mit: systemctl start fail2ban",
            fg="yellow"
        ))
    elif not status["enabled"]:
        click.echo("\nAktivieren mit: sudo nrp f2b enable")


# ── helper ────────────────────────────────────────────────────────────────────

def _require_root():
    import os
    if os.geteuid() != 0:
        click.echo(click.style("Fehler: Dieser Befehl muss als root ausgeführt werden.", fg="red"))
        click.echo("Bitte verwenden Sie: sudo nrp f2b ...")
        sys.exit(1)

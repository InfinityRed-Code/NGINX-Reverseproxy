"""
Site command group - manage WireGuard tunnel sites
"""
import sys
import click

from nrp.core import wireguard as wg


@click.group()
def site():
    """
    Verwaltet WireGuard-Tunnel-Sites (Hub-and-Spoke)

    Sites verbinden entfernte Netzwerke über verschlüsselte WireGuard-Tunnel
    mit diesem VPS. Upstream-IPs (10.x) können dann als Backend für
    'nrp add --site <NAME>' genutzt werden.

    Typischer Workflow:

    \b
        nrp site create home --targets 8
        nrp site install-script home > install-home.sh
        scp install-home.sh user@home:/tmp/
        ssh user@home 'bash /tmp/install-home.sh'
        nrp site list
    """
    pass


# ── create ────────────────────────────────────────────────────────────────

@site.command(name="create")
@click.argument("name")
@click.option("--targets", type=int, default=None,
              help="Geschätzte Anzahl interner Dienste (bestimmt Subnetz-Präfix)")
@click.option("--subnet-prefix", "subnet_prefix", type=int, default=None,
              help="Expliziter Subnetz-Präfix (z.B. 28 für /28). Überschreibt --targets")
@click.option("--email", default=None, help="E-Mail-Adresse für Metadaten/Benachrichtigungen")
@click.option("--os", "os_hint", type=click.Choice(["debian", "ubuntu", "alpine"]),
              default=None, help="OS-Hinweis für Install-Script")
@click.option("--lan-cidr", "lan_cidr", default=None,
              help="LAN-Subnetz hinter dem Remote-Host (z.B. 192.168.1.0/24). "
                   "Wird in AllowedIPs und Routing aufgenommen.")
def site_create(name, targets, subnet_prefix, email, os_hint, lan_cidr):
    """
    Erstellt eine neue WireGuard-Site

    Beispiele:

    \b
        nrp site create home --targets 8
        nrp site create home --targets 4 --lan-cidr 192.168.1.0/24
        nrp site create office --subnet-prefix 27
        nrp site create lab --targets 4 --email admin@example.com
    """
    try:
        s = wg.create_site(
            name=name,
            targets=targets,
            subnet_prefix=subnet_prefix,
            email=email,
            os_hint=os_hint,
            lan_cidr=lan_cidr,
        )
    except ValueError as e:
        click.echo(click.style(f"Fehler: {e}", fg="red"))
        sys.exit(1)
    except RuntimeError as e:
        click.echo(click.style(f"Fehler: {e}", fg="red"))
        sys.exit(1)

    click.echo(click.style(f"\n✓ Site '{name}' erfolgreich erstellt!", fg="green"))
    click.echo(f"\n  Subnetz:       {s['subnet']}")
    click.echo(f"  Connector-IP:  {s['connector_ip']}")
    click.echo(f"  WG-Interface:  {s['wg_interface']}")
    if s.get("lan_cidr"):
        click.echo(f"  LAN-CIDR:      {s['lan_cidr']}")
    click.echo(f"  Status:        {s['status']}")
    click.echo(f"\nNächster Schritt:")
    click.echo(f"  nrp site install-script {name} > install-{name}.sh")


# ── list ──────────────────────────────────────────────────────────────────

@site.command(name="list")
def site_list():
    """
    Listet alle konfigurierten Sites auf

    Beispiel:

        nrp site list
    """
    sites = wg.list_sites()
    if not sites:
        click.echo("Keine Sites konfiguriert.")
        return

    # Header
    col = (12, 20, 16, 10)
    header = (
        f"{'NAME':<{col[0]}}"
        f"{'SUBNET':<{col[1]}}"
        f"{'CONNECTOR_IP':<{col[2]}}"
        f"{'STATUS':<{col[3]}}"
    )
    click.echo("\n" + header)
    click.echo("─" * sum(col))

    for s in sites:
        status = s.get("status", "unknown")
        color = {"online": "green", "offline": "red", "pending": "yellow"}.get(status, "white")
        click.echo(
            f"{s['name']:<{col[0]}}"
            f"{s['subnet']:<{col[1]}}"
            f"{s['connector_ip']:<{col[2]}}"
            + click.style(f"{status:<{col[3]}}", fg=color)
        )
    click.echo()


# ── show ──────────────────────────────────────────────────────────────────

@site.command(name="show")
@click.argument("name")
@click.option("--live", is_flag=True, default=False,
              help="Live-Konnektivität prüfen (Ping)")
def site_show(name, live):
    """
    Zeigt Details einer Site

    Beispiel:

        nrp site show home
    """
    s = wg.get_site(name)
    if s is None:
        click.echo(click.style(f"Site '{name}' nicht gefunden.", fg="red"))
        sys.exit(1)

    status = s.get("status", "unknown")
    if live:
        status = wg.refresh_site_status(s)

    color = {"online": "green", "offline": "red", "pending": "yellow"}.get(status, "white")

    click.echo(f"\nName:           {s['name']}")
    click.echo(f"Subnetz:        {s['subnet']}")
    click.echo(f"Connector-IP:   {s['connector_ip']}")
    click.echo(f"Tunnel-Device:  {s['wg_interface']}")
    click.echo(f"LAN-CIDR:       {s.get('lan_cidr') or '-'}")
    click.echo(f"Public Key:     {s.get('public_key') or '(ausstehend)'}")
    click.echo(f"Status:         " + click.style(status, fg=color))
    click.echo(f"Targets:        {s.get('targets') or '-'}")
    click.echo(f"E-Mail:         {s.get('email') or '-'}")
    click.echo(f"OS-Hinweis:     {s.get('os_hint') or '-'}")
    click.echo(f"Erstellt:       {s.get('created_at', '-')}")
    if s.get("last_seen_at"):
        click.echo(f"Zuletzt gesehen:{s['last_seen_at']}")
    if s.get("notes"):
        click.echo(f"Notizen:        {s['notes']}")
    click.echo()


# ── delete ────────────────────────────────────────────────────────────────

@site.command(name="delete")
@click.argument("name")
@click.option("--keep-config", is_flag=True, default=False,
              help="Peer aus wg0.conf entfernen, aber Metadaten behalten")
@click.option("--yes", "-y", is_flag=True, default=False,
              help="Ohne Bestätigungsfrage löschen")
def site_delete(name, keep_config, yes):
    """
    Löscht eine Site (entfernt WireGuard-Peer)

    Beispiele:

    \b
        nrp site delete home
        nrp site delete home --keep-config
    """
    s = wg.get_site(name)
    if s is None:
        click.echo(click.style(f"Site '{name}' nicht gefunden.", fg="red"))
        sys.exit(1)

    if not yes:
        action = "deaktivieren (Metadaten behalten)" if keep_config else "vollständig löschen"
        confirmed = click.confirm(f"Site '{name}' wirklich {action}?", default=False)
        if not confirmed:
            click.echo("Abgebrochen.")
            return

    try:
        wg.delete_site(name, keep_config=keep_config)
    except ValueError as e:
        click.echo(click.style(f"Fehler: {e}", fg="red"))
        sys.exit(1)

    if keep_config:
        click.echo(click.style(f"✓ Site '{name}' deaktiviert (Metadaten behalten).", fg="yellow"))
    else:
        click.echo(click.style(f"✓ Site '{name}' vollständig gelöscht.", fg="green"))


# ── install-script ────────────────────────────────────────────────────────

@site.command(name="install-script")
@click.argument("name")
@click.option("--os", "os_hint", type=click.Choice(["debian", "ubuntu", "alpine"]),
              default=None, help="OS-Hinweis für Paketmanager-Befehle")
def site_install_script(name, os_hint):
    """
    Generiert ein Setup-Script für den Site-Host

    Das Script richtet den WireGuard-Tunnel auf dem entfernten Host ein und
    gibt den öffentlichen Schlüssel aus, der anschließend mit
    'nrp site set-pubkey' registriert werden muss.

    Beispiele:

    \b
        nrp site install-script home > install-home.sh
        nrp site install-script office --os ubuntu > install-office.sh
    """
    try:
        script = wg.generate_install_script(name, os_hint=os_hint)
    except ValueError as e:
        click.echo(click.style(f"Fehler: {e}", fg="red"))
        sys.exit(1)

    # Write directly to stdout so the user can pipe to a file
    click.get_text_stream("stdout").write(script)


# ── set-pubkey ────────────────────────────────────────────────────────────

@site.command(name="set-pubkey")
@click.argument("name")
@click.argument("public_key")
def site_set_pubkey(name, public_key):
    """
    Registriert den öffentlichen WireGuard-Schlüssel einer Site

    Wird nach der Ausführung des Install-Scripts auf dem Site-Host aufgerufen.

    Beispiel:

        nrp site set-pubkey home <PUBLIC_KEY>
    """
    try:
        s = wg.set_public_key(name, public_key)
    except ValueError as e:
        click.echo(click.style(f"Fehler: {e}", fg="red"))
        sys.exit(1)

    click.echo(click.style(f"✓ Public Key für Site '{name}' gespeichert.", fg="green"))
    click.echo(f"  Public Key: {s['public_key']}")
    click.echo(f"\nStatus prüfen mit: nrp site show {name} --live")

"""
Add command - Create new proxy host
"""
import ipaddress
import click
from pathlib import Path

from nrp.core.validation import (
    validate_fqdn,
    validate_ip,
    validate_port,
    validate_protocol,
    validate_config_exists
)
from nrp.core.nginx import NginxManager
from nrp.core.certbot import CertbotManager
from nrp.config import NGINX_CONF_DIR


@click.command()
@click.argument('fqdn', required=False)
@click.option('--internal-ip', '-i', help='Interne IP-Adresse des Servers')
@click.option('--internal-port', '-p', type=int, help='Interner Port des Servers')
@click.option('--external-port', '-e', type=int, default=443, help='Externer Port (Standard: 443)')
@click.option('--protocol', '-s', type=click.Choice(['http', 'https'], case_sensitive=False), default='http', help='Forward Scheme (http oder https)')
@click.option('--websockets/--no-websockets', '-w/-nw', default=None, help='Websockets aktivieren')
@click.option('--email', help='E-Mail für LetsEncrypt Benachrichtigungen')
@click.option('--overwrite', '-o', is_flag=True, help='Bestehende Konfiguration überschreiben')
@click.option('--full-interactive', '-f', is_flag=True, help='Alle Optionen interaktiv abfragen')
@click.option('--site', 'site_name', default=None, help='WireGuard-Site-Name (Tunnel-Upstream)')
def add(fqdn, internal_ip, internal_port, external_port, protocol, websockets, email, overwrite, full_interactive, site_name):
    """
    Erstellt einen neuen Proxy-Host

    Beispiele:

    \b
        nrp add example.com -i 192.168.1.10 -p 8080

        nrp add test.example.com -i 192.168.1.20 -p 3000 -e 8443 -s https -w

        nrp add app.example.com --site home -i 10.240.12.10 -p 3000

        nrp add (interaktiv - nur Basis-Optionen)

        nrp add --full-interactive (interaktiv - alle Optionen)
    """
    nginx = NginxManager()
    certbot = CertbotManager()

    # Interactive mode if no FQDN provided
    if not fqdn:
        fqdn = click.prompt('FQDN (z.B. server.example.com)', type=str)

    # Validate FQDN
    if not validate_fqdn(fqdn):
        click.echo(click.style(f'Ungültiger FQDN: {fqdn}', fg='red'))
        return

    # Check if config already exists
    if validate_config_exists(fqdn, NGINX_CONF_DIR):
        if not overwrite:
            choice = click.prompt(
                f'Konfiguration für {fqdn} existiert bereits. Überschreiben?',
                type=click.Choice(['j', 'n'], case_sensitive=False),
                default='n'
            )
            if choice == 'n':
                click.echo('Abgebrochen.')
                return
        # Remove old config
        nginx.remove_config(fqdn)

    # Get remaining parameters interactively if not provided
    if not internal_ip:
        internal_ip = click.prompt('Interne IP-Adresse', type=str)

    if not validate_ip(internal_ip):
        click.echo(click.style(f'Ungültige IP-Adresse: {internal_ip}', fg='red'))
        return

    # Site validation: check that internal_ip is reachable via the site
    if site_name:
        from nrp.core.wireguard import get_site
        site_obj = get_site(site_name)
        if site_obj is None:
            click.echo(click.style(f"Site '{site_name}' nicht gefunden. Bitte zuerst 'nrp site create {site_name}' ausführen.", fg='red'))
            return
        try:
            overlay_net = ipaddress.ip_network(site_obj['subnet'], strict=False)
            lan_cidr = site_obj.get('lan_cidr')
            lan_net = ipaddress.ip_network(lan_cidr, strict=False) if lan_cidr else None
            addr = ipaddress.ip_address(internal_ip)
            in_overlay = addr in overlay_net
            in_lan = lan_net is not None and addr in lan_net
            if not in_overlay and not in_lan:
                # Warn but allow – LAN CIDR may not be stored yet
                click.echo(click.style(
                    f"Hinweis: IP {internal_ip} liegt weder im Overlay-Subnetz ({site_obj['subnet']})"
                    + (f" noch im LAN ({lan_cidr})" if lan_cidr else " noch in einem bekannten LAN der Site")
                    + ". Stelle sicher, dass das Netzwerk über den Tunnel geroutet wird.",
                    fg='yellow'
                ))
        except ValueError as e:
            click.echo(click.style(f"Subnetz-Validierungsfehler: {e}", fg='red'))
            return
        click.echo(click.style(f"✓ Site '{site_name}' gefunden (Subnetz: {site_obj['subnet']})", fg='cyan'))

    if not internal_port:
        internal_port = click.prompt('Interner Port', type=int, default=8080)

    if not validate_port(internal_port):
        click.echo(click.style(f'Ungültiger Port: {internal_port}', fg='red'))
        return

    # Full interactive mode - ask for all options
    if full_interactive:
        click.echo(click.style('\n--- Erweiterte Optionen ---', fg='cyan'))

        # External port
        external_port = click.prompt('Externer Port', type=int, default=443)

        # Protocol
        protocol = click.prompt(
            'Forward Scheme',
            type=click.Choice(['http', 'https'], case_sensitive=False),
            default='http'
        )

        # Email for certificates
        if click.confirm('E-Mail für LetsEncrypt Benachrichtigungen angeben?', default=False):
            email = click.prompt('E-Mail-Adresse', type=str)

        # Websockets
        websockets = click.confirm('Websockets aktivieren?', default=False)
    else:
        # Standard interactive mode - only ask for websockets
        if websockets is None:
            websockets = click.confirm('Websockets aktivieren?', default=False)

    # Validate external port if provided
    if external_port and not validate_port(external_port):
        click.echo(click.style(f'Ungültiger externer Port: {external_port}', fg='red'))
        return

    click.echo(f'\nErstelle Proxy-Host für {fqdn}...')

    # Step 1: Create temporary HTTP config
    click.echo('Erstelle temporäre HTTP-Konfiguration...')
    nginx.create_temp_config(fqdn, external_port)

    if not nginx.reload():
        click.echo(click.style('Fehler beim Neuladen der NGINX-Konfiguration', fg='red'))
        return

    # Step 2: Request SSL certificate
    click.echo('Fordere SSL-Zertifikat an...')
    if not certbot.request_certificate(fqdn, email):
        click.echo(click.style('Fehler bei der Zertifikatsanforderung', fg='red'))
        nginx.remove_config(fqdn)
        nginx.reload()
        return

    # Step 3: Create final configuration
    click.echo('Erstelle finale HTTPS-Konfiguration...')
    nginx.create_config(
        fqdn=fqdn,
        internal_ip=internal_ip,
        internal_port=internal_port,
        external_port=external_port,
        forward_scheme=protocol.lower(),
        websockets_enabled=websockets
    )

    # Step 4: Test and reload
    if not nginx.test_config():
        click.echo(click.style('NGINX-Konfiguration ist ungültig', fg='red'))
        return

    if not nginx.reload():
        click.echo(click.style('Fehler beim Neuladen der NGINX-Konfiguration', fg='red'))
        return

    click.echo(click.style(f'\n✓ Proxy-Host {fqdn} erfolgreich erstellt!', fg='green'))
    click.echo(f'\nKonfiguration: /etc/nginx/conf.d/{fqdn}.conf')
    click.echo(f'Zertifikat: /etc/letsencrypt/live/{fqdn}/')

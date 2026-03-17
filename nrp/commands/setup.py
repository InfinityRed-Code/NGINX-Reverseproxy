"""
Setup command - Install environment on Debian system
"""
import click
import subprocess
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

from nrp.config import (
    NGINX_CONF_DIR,
    NGINX_HTML_DIR,
    NGINX_SSL_DIR,
    TEMPLATE_DIR
)


@click.command()
@click.option('--skip-packages', is_flag=True, help='Paketinstallation überspringen')
@click.option('--with-wireguard', is_flag=True, default=False,
              help='WireGuard für Site-Tunnel-Unterstützung mitinstallieren')
def setup(skip_packages, with_wireguard):
    """
    Installiert die Umgebung auf einem Debian 13 System

    Installiert NGINX, Certbot und alle notwendigen Abhängigkeiten.
    Erstellt Catch-All Konfiguration und selbstsigniertes Dummy-Zertifikat.

    Beispiel:

        sudo nrp setup
    """
    click.echo('\n=== NGINX Reverse Proxy Setup ===\n')

    # Check if running as root
    if subprocess.run(['id', '-u'], capture_output=True, text=True).stdout.strip() != '0':
        click.echo(click.style('Fehler: Dieser Befehl muss als root ausgeführt werden', fg='red'))
        click.echo('Bitte verwenden Sie: sudo nrp setup')
        return

    # Step 1: Install packages
    if not skip_packages:
        click.echo('1. Installiere Pakete...')
        packages = [
            'curl', 'net-tools', 'sudo', 'nginx', 'certbot',
            'python3', 'python3-full', 'python3-certbot-nginx', 'openssl'
        ]
        if with_wireguard:
            packages += ['wireguard', 'wireguard-tools']

        try:
            subprocess.run(['apt', 'update'], check=True)
            subprocess.run(['apt', 'install', '-y'] + packages, check=True)
            click.echo(click.style('  ✓ Pakete installiert', fg='green'))
        except subprocess.CalledProcessError as e:
            click.echo(click.style(f'  ✗ Fehler bei der Paketinstallation', fg='red'))
            return
    else:
        click.echo('1. Paketinstallation übersprungen')

    # Step 2: Enable and start NGINX
    click.echo('\n2. Aktiviere NGINX...')
    try:
        subprocess.run(['systemctl', 'enable', 'nginx'], check=True)
        subprocess.run(['systemctl', 'start', 'nginx'], check=True)
        click.echo(click.style('  ✓ NGINX aktiviert und gestartet', fg='green'))
    except subprocess.CalledProcessError:
        click.echo(click.style('  ✗ Fehler beim Starten von NGINX', fg='red'))
        return

    # Step 3: Create directories
    click.echo('\n3. Erstelle Verzeichnisse...')
    NGINX_HTML_DIR.mkdir(parents=True, exist_ok=True)
    NGINX_CONF_DIR.mkdir(parents=True, exist_ok=True)
    NGINX_SSL_DIR.mkdir(parents=True, exist_ok=True)
    click.echo(click.style('  ✓ Verzeichnisse erstellt', fg='green'))

    # Step 4: Copy 404.html
    click.echo('\n4. Kopiere 404-Seite...')
    src_404 = TEMPLATE_DIR / '404.html'
    dst_404 = NGINX_HTML_DIR / '404.html'
    dst_404.write_text(src_404.read_text())
    click.echo(click.style('  ✓ 404-Seite installiert', fg='green'))

    # Step 5: Create dummy SSL certificate
    click.echo('\n5. Erstelle selbstsigniertes Zertifikat...')
    dummy_cert = NGINX_SSL_DIR / 'dummy.crt'
    dummy_key = NGINX_SSL_DIR / 'dummy.key'

    if not dummy_cert.exists() or not dummy_key.exists():
        try:
            subprocess.run([
                'openssl', 'req', '-x509', '-nodes', '-days', '365',
                '-newkey', 'rsa:2048',
                '-keyout', str(dummy_key),
                '-out', str(dummy_cert),
                '-subj', '/C=DE/ST=RLP/L=Hauenstein/O=SoftENGINE GmbH/OU=IT/CN=SoftENGINE-Reverseproxy'
            ], check=True, capture_output=True)
            click.echo(click.style('  ✓ Zertifikat erstellt', fg='green'))
        except subprocess.CalledProcessError:
            click.echo(click.style('  ✗ Fehler beim Erstellen des Zertifikats', fg='red'))
            return
    else:
        click.echo(click.style('  ✓ Zertifikat existiert bereits', fg='yellow'))

    # Step 6: Create catch-all configuration
    click.echo('\n6. Erstelle Catch-All Konfiguration...')
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    template = env.get_template('catch-all.conf.j2')
    content = template.render(
        nginx_html_dir=NGINX_HTML_DIR,
        dummy_cert=dummy_cert,
        dummy_key=dummy_key
    )

    catch_all_conf = NGINX_CONF_DIR / 'catch-all.conf'
    catch_all_conf.write_text(content)
    click.echo(click.style('  ✓ Catch-All Konfiguration erstellt', fg='green'))

    # Step 7: Remove default configuration
    click.echo('\n7. Entferne Standard-Konfiguration...')
    default_enabled = Path('/etc/nginx/sites-enabled/default')
    default_available = Path('/etc/nginx/sites-available/default')

    if default_enabled.exists():
        default_enabled.unlink()
    if default_available.exists():
        default_available.unlink()
    click.echo(click.style('  ✓ Standard-Konfiguration entfernt', fg='green'))

    # Step 8: Test and reload NGINX
    click.echo('\n8. Teste und lade NGINX neu...')
    try:
        subprocess.run(['nginx', '-t'], check=True, capture_output=True)
        subprocess.run(['nginx', '-s', 'reload'], check=True)
        click.echo(click.style('  ✓ NGINX erfolgreich neu geladen', fg='green'))
    except subprocess.CalledProcessError:
        click.echo(click.style('  ✗ Fehler beim Neuladen von NGINX', fg='red'))
        return

    # Step 9 (optional): WireGuard setup
    if with_wireguard:
        click.echo('\n9. Konfiguriere WireGuard (Hub)...')
        # Enable IP forwarding
        sysctl_conf = Path('/etc/sysctl.d/99-nrp-wireguard.conf')
        sysctl_conf.write_text('net.ipv4.ip_forward = 1\n')
        try:
            subprocess.run(['sysctl', '-p', str(sysctl_conf)], check=True, capture_output=True)
            click.echo(click.style('  ✓ IP-Forwarding aktiviert', fg='green'))
        except subprocess.CalledProcessError:
            click.echo(click.style('  ✗ Fehler beim Aktivieren von IP-Forwarding', fg='yellow'))

        # Create NRP data directory for site DB
        from nrp.config import NRP_DATA_DIR
        NRP_DATA_DIR.mkdir(parents=True, exist_ok=True)
        click.echo(click.style(f'  ✓ Datenverzeichnis erstellt: {NRP_DATA_DIR}', fg='green'))

        # Initialize wg0 interface (lazy – only if wg is available)
        try:
            from nrp.core.wireguard import _ensure_wg_interface, _add_site_routes, list_sites
            _ensure_wg_interface()
            subprocess.run(['systemctl', 'enable', '--now', 'wg-quick@wg0'],
                           check=True, capture_output=True)
            click.echo(click.style('  ✓ WireGuard wg0 aktiviert', fg='green'))

            # Sync kernel routes for all existing sites with lan_cidr
            sites_with_lan = [s for s in list_sites() if s.get("lan_cidr")]
            if sites_with_lan:
                for s in sites_with_lan:
                    _add_site_routes(s)
                click.echo(click.style(f'  ✓ Routen für {len(sites_with_lan)} Site(s) synchronisiert', fg='green'))
        except Exception as e:
            click.echo(click.style(f'  ✗ WireGuard konnte nicht gestartet werden: {e}', fg='yellow'))
            click.echo('    Starten Sie WireGuard manuell mit: systemctl enable --now wg-quick@wg0')

    click.echo(click.style('\n✓ Installation erfolgreich abgeschlossen!', fg='green', bold=True))
    click.echo('\nSie können jetzt Proxy-Hosts hinzufügen mit:')
    click.echo('  nrp add example.com')
    if with_wireguard:
        click.echo('\nWireGuard-Sites verwalten mit:')
        click.echo('  nrp site create <NAME> --targets <N>')

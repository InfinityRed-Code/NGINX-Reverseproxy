"""
Status command - Show NGINX and certificate status
"""
import click
import subprocess

from nrp.core.nginx import NginxManager
from nrp.core.certbot import CertbotManager


@click.command()
@click.option('--detailed', '-d', is_flag=True, help='Zeigt detaillierte Informationen')
def status(detailed):
    """
    Zeigt den Status von NGINX und Zertifikaten

    Beispiele:

        nrp status

        nrp status --detailed
    """
    nginx = NginxManager()
    certbot = CertbotManager()

    click.echo('\n=== NGINX Reverse Proxy Status ===\n')

    # NGINX Status
    click.echo('NGINX Service:')
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'nginx'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            click.echo(click.style('  ✓ Aktiv', fg='green'))
        else:
            click.echo(click.style('  ✗ Inaktiv', fg='red'))
    except Exception as e:
        click.echo(click.style(f'  ? Status unbekannt', fg='yellow'))

    # Configuration Test
    click.echo('\nKonfiguration:')
    if nginx.test_config():
        click.echo(click.style('  ✓ Gültig', fg='green'))
    else:
        click.echo(click.style('  ✗ Ungültig', fg='red'))

    # Configured Hosts
    configs = nginx.list_configs()
    click.echo(f'\nKonfigurierte Hosts: {len(configs)}')

    if detailed and configs:
        click.echo('─' * 50)
        for domain in configs:
            click.echo(f'  • {domain}')

    # Certificates
    if detailed:
        click.echo('\n=== Zertifikate ===\n')
        certs = certbot.list_certificates()
        if certs:
            for cert in certs:
                click.echo(f'  • {cert}')
        else:
            click.echo('  Keine Zertifikate gefunden')

    click.echo()

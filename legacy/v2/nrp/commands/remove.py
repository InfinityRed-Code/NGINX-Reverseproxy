"""
Remove command - Delete proxy host
"""
import click

from nrp.core.nginx import NginxManager
from nrp.core.certbot import CertbotManager
from nrp.core.validation import validate_config_exists
from nrp.config import NGINX_CONF_DIR


def complete_domains(ctx, param, incomplete):
    """
    Auto-complete existing domains for removal

    Args:
        ctx: Click context
        param: Parameter being completed
        incomplete: Current incomplete input

    Returns:
        List of matching domain names
    """
    try:
        nginx = NginxManager()
        domains = nginx.list_configs()
        return [d for d in domains if d.startswith(incomplete)]
    except Exception:
        return []


@click.command()
@click.argument('fqdn', shell_complete=complete_domains)
@click.option('--keep-cert', is_flag=True, help='Zertifikat behalten (nicht löschen)')
def remove(fqdn, keep_cert):
    """
    Entfernt einen Proxy-Host

    Beispiele:

        nrp remove example.com

        nrp remove example.com --keep-cert
    """
    nginx = NginxManager()
    certbot = CertbotManager()

    # Check if config exists
    if not validate_config_exists(fqdn, NGINX_CONF_DIR):
        click.echo(click.style(f'Konfiguration für {fqdn} nicht gefunden', fg='yellow'))
        return

    # Confirm removal
    if not click.confirm(f'Möchten Sie den Proxy-Host {fqdn} wirklich entfernen?'):
        click.echo('Abgebrochen.')
        return

    click.echo(f'\nEntferne Proxy-Host {fqdn}...')

    # Remove NGINX configuration
    if nginx.remove_config(fqdn):
        click.echo('✓ NGINX-Konfiguration entfernt')
    else:
        click.echo(click.style('Fehler beim Entfernen der NGINX-Konfiguration', fg='red'))

    # Reload NGINX
    if nginx.reload():
        click.echo('✓ NGINX neu geladen')
    else:
        click.echo(click.style('Fehler beim Neuladen der NGINX-Konfiguration', fg='red'))

    # Remove certificate if requested
    if not keep_cert:
        click.echo('Entferne SSL-Zertifikat...')
        if certbot.delete_certificate(fqdn):
            click.echo('✓ SSL-Zertifikat entfernt')
        else:
            click.echo(click.style('Fehler beim Entfernen des Zertifikats', fg='yellow'))

    click.echo(click.style(f'\n✓ Proxy-Host {fqdn} erfolgreich entfernt!', fg='green'))

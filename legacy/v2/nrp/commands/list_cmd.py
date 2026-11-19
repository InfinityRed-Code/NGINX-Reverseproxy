"""
List command - Show all proxy hosts
"""
import click

from nrp.core.nginx import NginxManager


@click.command(name='list')
def list_hosts():
    """
    Zeigt alle konfigurierten Proxy-Hosts an

    Beispiel:

        nrp list
    """
    nginx = NginxManager()
    configs = nginx.list_configs()

    if not configs:
        click.echo('Keine Proxy-Hosts konfiguriert.')
        return

    click.echo(f'\nKonfigurierte Proxy-Hosts ({len(configs)}):')
    click.echo('─' * 50)

    for i, domain in enumerate(configs, 1):
        click.echo(f'{i}. {domain}')
        click.echo(f'   Konfiguration: /etc/nginx/conf.d/{domain}.conf')
        click.echo(f'   Zertifikat: /etc/letsencrypt/live/{domain}/')
        click.echo()

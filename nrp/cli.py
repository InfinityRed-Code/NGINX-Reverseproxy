"""
CLI Entry Point for NRP
"""
import click
from nrp import __version__


@click.group()
@click.version_option(version=__version__)
def cli():
    """
    NGINX Reverse Proxy Management Tool

    Verwalten Sie Ihre NGINX Reverse Proxy Konfigurationen einfach über die Kommandozeile.

    Für Shell-Completion (Tab-Vervollständigung):
      nrp completion
    """
    pass


# Import commands after cli group is defined to avoid circular imports
from nrp.commands import add, remove, list_cmd, setup, remote_setup, status, completion
from nrp.commands import site

cli.add_command(add.add)
cli.add_command(remove.remove)
cli.add_command(list_cmd.list_hosts)
cli.add_command(setup.setup)
cli.add_command(remote_setup.remote_setup)
cli.add_command(status.status)
cli.add_command(completion.completion)
cli.add_command(site.site)


if __name__ == '__main__':
    cli()

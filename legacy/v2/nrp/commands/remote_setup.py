"""
Remote Setup command - Configure remote execution via SSH
"""
import click
import subprocess
from pathlib import Path

from nrp.config import DEFAULT_REMOTE_USER, DEFAULT_SCRIPT_PATH


@click.command(name='remote-setup')
@click.option('--user', '-u', default=DEFAULT_REMOTE_USER, help=f'Benutzername (Standard: {DEFAULT_REMOTE_USER})')
@click.option('--script-path', '-s', default=DEFAULT_SCRIPT_PATH, help=f'Installationspfad (Standard: {DEFAULT_SCRIPT_PATH})')
@click.option('--public-key', '-k', help='Pfad zum öffentlichen SSH-Schlüssel')
def remote_setup(user, script_path, public_key):
    """
    Konfiguriert Remote-Ausführung via SSH

    Erstellt einen Benutzer mit eingeschränkten Rechten für die Remote-Verwaltung.

    Beispiele:

        sudo nrp remote-setup

        sudo nrp remote-setup --user myuser --public-key ~/.ssh/id_ed25519.pub
    """
    click.echo('\n=== Reverse Proxy Remote Setup ===\n')

    # Check if running as root
    if subprocess.run(['id', '-u'], capture_output=True, text=True).stdout.strip() != '0':
        click.echo(click.style('Fehler: Dieser Befehl muss als root ausgeführt werden', fg='red'))
        click.echo('Bitte verwenden Sie: sudo nrp remote-setup')
        return

    # Step 1: Create user
    click.echo(f'1. Erstelle Benutzer {user}...')
    try:
        result = subprocess.run(['id', user], capture_output=True)
        if result.returncode == 0:
            click.echo(click.style(f'  ✓ Benutzer {user} existiert bereits', fg='yellow'))
        else:
            subprocess.run([
                'adduser', '--disabled-password', '--gecos', '', user
            ], check=True)
            click.echo(click.style(f'  ✓ Benutzer {user} erstellt', fg='green'))
    except subprocess.CalledProcessError:
        click.echo(click.style('  ✗ Fehler beim Erstellen des Benutzers', fg='red'))
        return

    # Step 2: Setup SSH directory
    click.echo('\n2. Richte SSH-Verzeichnis ein...')
    ssh_dir = Path(f'/home/{user}/.ssh')
    ssh_dir.mkdir(mode=0o700, exist_ok=True)

    try:
        subprocess.run(['chown', f'{user}:{user}', str(ssh_dir)], check=True)
        click.echo(click.style('  ✓ SSH-Verzeichnis erstellt', fg='green'))
    except subprocess.CalledProcessError:
        click.echo(click.style('  ✗ Fehler beim Erstellen des SSH-Verzeichnisses', fg='red'))
        return

    # Step 3: Add public key
    click.echo('\n3. Füge öffentlichen SSH-Schlüssel hinzu...')

    if public_key:
        # Read from file
        try:
            pub_key_content = Path(public_key).expanduser().read_text().strip()
        except FileNotFoundError:
            click.echo(click.style(f'  ✗ Datei nicht gefunden: {public_key}', fg='red'))
            return
    else:
        # Ask for key
        click.echo('Bitte fügen Sie den PUBLIC SSH-Key ein')
        click.echo('(eine Zeile, beginnt meist mit ssh-ed25519 oder ssh-rsa):')
        pub_key_content = click.prompt('', type=str)

    authorized_keys = ssh_dir / 'authorized_keys'
    authorized_keys.write_text(pub_key_content + '\n')
    authorized_keys.chmod(0o600)

    try:
        subprocess.run(['chown', f'{user}:{user}', str(authorized_keys)], check=True)
        click.echo(click.style('  ✓ SSH-Schlüssel hinzugefügt', fg='green'))
    except subprocess.CalledProcessError:
        click.echo(click.style('  ✗ Fehler beim Setzen der Berechtigungen', fg='red'))
        return

    # Step 4: Get nrp binary path
    nrp_path = subprocess.run(['which', 'nrp'], capture_output=True, text=True).stdout.strip()
    if not nrp_path:
        click.echo(click.style('  ✗ nrp Befehl nicht gefunden', fg='red'))
        click.echo('  Stellen Sie sicher, dass nrp installiert ist')
        return

    # Step 5: Create sudoers entry
    click.echo('\n4. Richte sudoers-Berechtigung ein...')
    sudoers_file = Path(f'/etc/sudoers.d/{user}_nginx')
    sudoers_content = f'{user} ALL=(ALL) NOPASSWD: {nrp_path}\n'

    try:
        sudoers_file.write_text(sudoers_content)
        sudoers_file.chmod(0o440)
        click.echo(click.style('  ✓ sudoers-Eintrag erstellt', fg='green'))
    except Exception as e:
        click.echo(click.style(f'  ✗ Fehler beim Erstellen des sudoers-Eintrags: {e}', fg='red'))
        return

    click.echo(click.style('\n✓ Remote Setup erfolgreich abgeschlossen!', fg='green', bold=True))
    click.echo(f'\nTesten Sie die Verbindung mit:')
    click.echo(f'ssh -i /pfad/zum/privaten_schluessel {user}@<SERVER-IP> "sudo nrp list"')

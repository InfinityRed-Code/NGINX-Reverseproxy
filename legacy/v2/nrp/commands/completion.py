"""
Completion command - Setup shell completion
"""
import click
import os
import subprocess
from pathlib import Path


@click.command()
@click.option('--shell', type=click.Choice(['bash', 'zsh', 'fish']),
              help='Shell type (auto-detected if not specified)')
def completion(shell):
    """
    Installiert Shell-Completion für nrp

    Aktiviert Tab-Completion für alle nrp Befehle und Optionen.

    Beispiele:

        nrp completion

        nrp completion --shell bash
    """
    # Auto-detect shell if not specified
    if not shell:
        shell_env = os.environ.get('SHELL', '')
        if 'bash' in shell_env:
            shell = 'bash'
        elif 'zsh' in shell_env:
            shell = 'zsh'
        elif 'fish' in shell_env:
            shell = 'fish'
        else:
            click.echo(click.style('Shell konnte nicht erkannt werden. Bitte mit --shell angeben.', fg='red'))
            click.echo('\nVerfügbare Shells: bash, zsh, fish')
            return

    click.echo(f'Installiere Completion für {shell}...\n')

    home = Path.home()

    try:
        if shell == 'bash':
            completion_file = home / '.nrp-complete.bash'
            rc_file = home / '.bashrc'
            source_line = f'source {completion_file}'

            # Generate completion script
            env = os.environ.copy()
            env['_NRP_COMPLETE'] = 'bash_source'
            result = subprocess.run(
                ['nrp'],
                capture_output=True,
                text=True,
                env=env
            )

            if result.returncode != 0:
                click.echo(click.style('Fehler beim Generieren der Completion', fg='red'))
                return

            completion_file.write_text(result.stdout)

            # Add source to .bashrc if not already present
            if rc_file.exists():
                rc_content = rc_file.read_text()
                if source_line not in rc_content:
                    with rc_file.open('a') as f:
                        f.write(f'\n# NRP Shell Completion\n{source_line}\n')
                    click.echo(f'✓ Source-Zeile zu {rc_file} hinzugefügt')
                else:
                    click.echo(f'  Source-Zeile bereits in {rc_file} vorhanden')

            click.echo(click.style(f'✓ Completion installiert: {completion_file}', fg='green'))
            click.echo(f'\nAktivieren mit: source {rc_file}')
            click.echo('oder neues Terminal öffnen')

        elif shell == 'zsh':
            completion_file = home / '.nrp-complete.zsh'
            rc_file = home / '.zshrc'
            source_line = f'source {completion_file}'

            env = os.environ.copy()
            env['_NRP_COMPLETE'] = 'zsh_source'
            result = subprocess.run(
                ['nrp'],
                capture_output=True,
                text=True,
                env=env
            )

            if result.returncode != 0:
                click.echo(click.style('Fehler beim Generieren der Completion', fg='red'))
                return

            completion_file.write_text(result.stdout)

            if rc_file.exists():
                rc_content = rc_file.read_text()
                if source_line not in rc_content:
                    with rc_file.open('a') as f:
                        f.write(f'\n# NRP Shell Completion\n{source_line}\n')
                    click.echo(f'✓ Source-Zeile zu {rc_file} hinzugefügt')
                else:
                    click.echo(f'  Source-Zeile bereits in {rc_file} vorhanden')

            click.echo(click.style(f'✓ Completion installiert: {completion_file}', fg='green'))
            click.echo(f'\nAktivieren mit: source {rc_file}')
            click.echo('oder neues Terminal öffnen')

        elif shell == 'fish':
            completion_dir = home / '.config/fish/completions'
            completion_dir.mkdir(parents=True, exist_ok=True)
            completion_file = completion_dir / 'nrp.fish'

            env = os.environ.copy()
            env['_NRP_COMPLETE'] = 'fish_source'
            result = subprocess.run(
                ['nrp'],
                capture_output=True,
                text=True,
                env=env
            )

            if result.returncode != 0:
                click.echo(click.style('Fehler beim Generieren der Completion', fg='red'))
                return

            completion_file.write_text(result.stdout)

            click.echo(click.style(f'✓ Completion installiert: {completion_file}', fg='green'))
            click.echo('\nAktivieren mit: exec fish')
            click.echo('oder neues Terminal öffnen')

    except Exception as e:
        click.echo(click.style(f'Fehler: {e}', fg='red'))
        return

    click.echo(click.style('\n✓ Shell-Completion erfolgreich eingerichtet!', fg='green', bold=True))
    click.echo('\nJetzt verfügbar:')
    click.echo('  nrp <TAB>          - Zeigt alle Befehle')
    click.echo('  nrp add --<TAB>    - Zeigt alle Optionen')
    click.echo('  nrp remove <TAB>   - Zeigt konfigurierte Domains')

import click
from zxcvbn import zxcvbn
import getpass
import sys
from pathlib import Path
from ciphervault.vault_handler import VaultHandler, WrongPassword
from ciphervault.models import Entry
from ciphervault.utils import generate_password, mask_password, copy_to_clipboard
from rich.console import Console
from rich.table import Table

console = Console()
DEFAULT_VAULT = str(Path.home() / ".ciphervault.vault")


@click.group()
@click.option('--vault', '-v', default=DEFAULT_VAULT, help='Path to vault file')
@click.pass_context
def cli(ctx, vault):
    """CipherVault CLI - secure local password manager"""
    ctx.ensure_object(dict)
    ctx.obj['VAULT_PATH'] = vault


@cli.command()
@click.pass_context
def init(ctx):
    """Create a new vault (will fail if one already exists)"""
    vault = VaultHandler(ctx.obj['VAULT_PATH'])
    console.print("Creating new vault at [bold]{}[/]".format(ctx.obj['VAULT_PATH']))

    pw = getpass.getpass("Master password: ")
    confirm = getpass.getpass("Confirm master password: ")

    if pw != confirm:
        console.print("[red]Passwords do not match[/]")
        sys.exit(1)

    # ------------------------
    # PASSWORD STRENGTH CHECK
    # ------------------------
    try:
        result = zxcvbn(pw)
        score = result["score"]
        feedback = result["feedback"]

        console.print(f"\n[bold]Password strength: {score}/4[/]")

        if feedback.get("warning"):
            console.print(f"[yellow]Warning:[/] {feedback['warning']}")
        if feedback.get("suggestions"):
            console.print(f"[cyan]Suggestions:[/] {'; '.join(feedback['suggestions'])}")

        if score < 2:
            console.print("[red]Password too weak. Please choose a stronger password.[/]")
            sys.exit(1)

    except Exception as e:
        console.print(f"[yellow]Could not evaluate password strength ({e})[/]")

    # Continue after strong password
    try:
        vault.init_vault(pw)
        console.print("[green]Vault created successfully[/]")
    except FileExistsError:
        console.print("[red]Vault already exists. Use --vault to choose a different path or import a vault.[/]")
        sys.exit(1)



@cli.command()
@click.argument('name')
@click.option('--username', '-u', prompt=True)
@click.option('--password', '-p', default=None, help='Provide a password or use --generate')
@click.option('--generate', is_flag=True, help='Auto-generate a strong password')
@click.option('--notes', '-n', default='')
@click.option('--copy', is_flag=True, help='Copy password to clipboard after creation')
@click.pass_context
def add(ctx, name, username, password, generate, notes, copy):
    """Add a new entry"""
    vault = VaultHandler(ctx.obj['VAULT_PATH'])

    master = getpass.getpass("Master password: ")

    # If --generate used or password not provided, auto-generate
    if generate or not password:
        password = generate_password()
    else:
        # Evaluate password strength
        try:
            result = zxcvbn(password)
            score = result['score']
            console.print(f"Password strength: [bold]{score}/4[/]")

            if score < 3:
                console.print("[red]Weak password! Consider using --generate[/]")
        except Exception:
            # If zxcvbn fails for any reason, skip silently but continue
            console.print("[yellow]Could not evaluate password strength[/]")

    entry = Entry.create(
        name=name,
        username=username,
        password=password,
        notes=notes
    )

    try:
        vault.add_entry(master, entry)
        console.print(f"[green]Added entry {name}[/]")

        if copy:
            ok = copy_to_clipboard(password, timeout=10)
            if ok:
                console.print("Password copied to clipboard for 10s")
            else:
                console.print("Failed to copy to clipboard")

    except WrongPassword:
        console.print("[red]Wrong master password[/]")
        sys.exit(1)


@cli.command(name='list')
@click.pass_context
def list_entries(ctx):
    """List saved entries"""
    vault = VaultHandler(ctx.obj['VAULT_PATH'])
    master = getpass.getpass("Master password: ")

    try:
        entries = vault.list_entries(master)
    except WrongPassword:
        console.print("[red]Wrong master password[/]")
        sys.exit(1)

    table = Table(title="CipherVault Entries")
    table.add_column("Name")
    table.add_column("Username")
    table.add_column("Password")
    table.add_column("Created At")

    for e in entries:
        table.add_row(e.name, e.username, mask_password(e.password), e.created_at)

    console.print(table)


@cli.command()
@click.argument('name')
@click.option('--show', is_flag=True, help='Show password in plain text')
@click.option('--copy', is_flag=True, help='Copy password to clipboard')
@click.pass_context
def get(ctx, name, show, copy):
    """Retrieve an entry by name"""
    vault = VaultHandler(ctx.obj['VAULT_PATH'])
    master = getpass.getpass("Master password: ")

    try:
        entry = vault.get_entry(master, name)
    except WrongPassword:
        console.print("[red]Wrong master password[/]")
        sys.exit(1)

    if not entry:
        console.print('[yellow]Entry not found[/]')
        sys.exit(1)

    console.print(f"[bold]{entry.name}[/]")
    console.print(f"Username: {entry.username}")
    console.print(f"Password: {entry.password if show else mask_password(entry.password, show=False)}")

    if copy:
        ok = copy_to_clipboard(entry.password, timeout=10)
        if ok:
            console.print("Password copied to clipboard for 10s")
        else:
            console.print("Failed to copy to clipboard")


@cli.command()
@click.argument('name')
@click.option('--username', '-u', default=None)
@click.option('--password', '-p', default=None)
@click.option('--notes', '-n', default=None)
@click.pass_context
def edit(ctx, name, username, password, notes):
    """Edit an existing entry"""
    vault = VaultHandler(ctx.obj['VAULT_PATH'])
    master = getpass.getpass("Master password: ")

    try:
        existing = vault.get_entry(master, name)
    except WrongPassword:
        console.print("[red]Wrong master password[/]")
        sys.exit(1)

    if not existing:
        console.print('[yellow]Entry not found[/]')
        sys.exit(1)

    new_username = username or existing.username
    new_password = password or existing.password
    new_notes = notes if notes is not None else existing.notes

    new_entry = Entry.create(
        name=name,
        username=new_username,
        password=new_password,
        notes=new_notes
    )

    ok = vault.update_entry(master, name, new_entry)

    if ok:
        console.print('[green]Entry updated[/]')
    else:
        console.print('[red]Failed to update entry[/]')


@cli.command()
@click.argument('name')
@click.confirmation_option(prompt='Are you sure you want to delete this entry?')
@click.pass_context
def delete(ctx, name):
    """Delete an entry"""
    vault = VaultHandler(ctx.obj['VAULT_PATH'])
    master = getpass.getpass("Master password: ")

    try:
        ok = vault.delete_entry(master, name)
    except WrongPassword:
        console.print("[red]Wrong master password[/]")
        sys.exit(1)

    if ok:
        console.print('[green]Deleted[/]')
    else:
        console.print('[yellow]Entry not found[/]')


@cli.command()
@click.argument('path')
@click.pass_context
def export(ctx, path):
    """Export the encrypted vault file to PATH"""
    vault = VaultHandler(ctx.obj['VAULT_PATH'])
    master = getpass.getpass("Master password: ")

    try:
        vault.export_vault(master, path)
        console.print(f"[green]Exported to {path}[/]")
    except Exception as e:
        console.print(f"[red]Failed: {e}[/]")
        sys.exit(1)


@cli.command(name='import')
@click.argument('path')
@click.pass_context
def import_vault(ctx, path):
    """Import an encrypted vault file from PATH (overwrites current vault)"""
    vault = VaultHandler(ctx.obj['VAULT_PATH'])

    try:
        vault.import_vault(path)
        console.print('[green]Imported vault[/]')
    except Exception as e:
        console.print(f"[red]Failed: {e}[/]")
        sys.exit(1)


@cli.command()
@click.pass_context
def change_master(ctx):
    """Change master password"""
    vault = VaultHandler(ctx.obj['VAULT_PATH'])

    old = getpass.getpass("Current master password: ")
    new = getpass.getpass("New master password: ")
    confirm = getpass.getpass("Confirm new master password: ")

    if new != confirm:
        console.print('[red]New passwords do not match[/]')
        sys.exit(1)

    try:
        vault.change_master_password(old, new)
        console.print('[green]Master password changed[/]')
    except WrongPassword:
        console.print('[red]Wrong current password[/]')
        sys.exit(1)


@cli.command()
@click.pass_context
def wipe(ctx):
    """Remove the vault file (irreversible)"""
    vault = VaultHandler(ctx.obj['VAULT_PATH'])

    confirm = click.confirm('This will permanently delete your vault file. Continue?')
    if not confirm:
        return

    ok = vault.wipe_vault()

    if ok:
        console.print('[green]Vault wiped[/]')
    else:
        console.print('[yellow]Vault not found[/]')




if __name__ == '__main__':
    cli()

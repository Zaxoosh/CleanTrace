from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated

import typer
from rich import box
from rich.prompt import Confirm, Prompt
from rich.table import Table
from sqlalchemy import Engine
from sqlmodel import Session, select

from cleantrace import __version__
from cleantrace.config import load_config, write_default_config
from cleantrace.db import get_engine, get_profile_by_slug, init_db, list_findings
from cleantrace.models import Finding, Profile
from cleantrace.paths import config_path, database_path, key_path
from cleantrace.plugins.manager import built_in_plugins
from cleantrace.render import (
    acceptable_use_panel,
    actions_panel,
    banner,
    console,
    findings_table,
    profile_table,
    summary_panel,
)
from cleantrace.reports import write_report
from cleantrace.scoring import exposure_score, top_actions
from cleantrace.security import CryptoBox, redact_text
from cleantrace.services import create_profile, scan_username

app = typer.Typer(
    name="cleantrace",
    help="Local-first privacy exposure and OSINT self-assessment.",
    no_args_is_help=True,
    invoke_without_command=True,
)
profile_app = typer.Typer(help="Manage explicit consent profiles.", no_args_is_help=True)
scan_app = typer.Typer(help="Run consent-based local-first scans.", no_args_is_help=True)
plugins_app = typer.Typer(help="Inspect and configure scanner plugins.", no_args_is_help=True)
removal_app = typer.Typer(help="Generate and track removal actions.", no_args_is_help=True)
link_app = typer.Typer(help="Link optional self-owned account connectors.", no_args_is_help=True)
unlink_app = typer.Typer(help="Disconnect linked providers.", no_args_is_help=True)
import_app = typer.Typer(help="Import local account exports.", no_args_is_help=True)

app.add_typer(profile_app, name="profile")
app.add_typer(scan_app, name="scan")
app.add_typer(plugins_app, name="plugins")
app.add_typer(removal_app, name="removal")
app.add_typer(link_app, name="link")
app.add_typer(unlink_app, name="unlink")
app.add_typer(import_app, name="import")


def _engine() -> Engine:
    return get_engine(load_config().database)


def _require_profile(session: Session, slug: str) -> Profile:
    profile = get_profile_by_slug(session, slug)
    if not profile:
        raise typer.BadParameter(
            f"Profile '{slug}' does not exist. Create it with cleantrace profile create."
        )
    if not profile.consent:
        raise typer.BadParameter(
            f"Profile '{slug}' has no consent flag. CleanTrace will not scan it."
        )
    return profile


def _split_csv(values: list[str] | None) -> list[str]:
    if not values:
        return []
    result: list[str] = []
    for value in values:
        result.extend(part.strip() for part in value.split(",") if part.strip())
    return result


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", help="Show version.", is_eager=True),
    ] = False,
) -> None:
    if version:
        console.print(f"CleanTrace {__version__}")
        raise typer.Exit


@app.command("init")
def init_command(
    yes: Annotated[
        bool,
        typer.Option("--yes", "-y", help="Accept ethical guardrails non-interactively."),
    ] = False,
    force: Annotated[
        bool,
        typer.Option("--force", help="Rewrite the default config file."),
    ] = False,
) -> None:
    """Create local config, database, and encryption key."""
    console.print(banner())
    console.print(acceptable_use_panel())
    if not yes and not Confirm.ask(
        "Use CleanTrace only for your own identifiers or with clear consent?"
    ):
        console.print("[yellow]Init cancelled.[/yellow]")
        raise typer.Exit(1)
    cfg = write_default_config(force=force)
    CryptoBox()
    init_db(get_engine(database_path()))
    console.print("[green]CleanTrace is ready.[/green]")
    console.print(f"Config: {cfg}")
    console.print(f"Database: {database_path()}")
    console.print(f"Encryption key: {key_path()}")


@profile_app.command("create")
def profile_create(
    slug: Annotated[
        str | None,
        typer.Option("--slug", help="Profile slug, for example 'default'."),
    ] = None,
    wizard: Annotated[
        bool,
        typer.Option("--wizard", help="Use beginner-friendly prompts."),
    ] = False,
    legal_name: Annotated[str | None, typer.Option("--legal-name")] = None,
    display_name: Annotated[list[str] | None, typer.Option("--display-name")] = None,
    username: Annotated[list[str] | None, typer.Option("--username")] = None,
    email: Annotated[list[str] | None, typer.Option("--email")] = None,
    phone: Annotated[list[str] | None, typer.Option("--phone")] = None,
    location: Annotated[str | None, typer.Option("--location")] = None,
    domain: Annotated[list[str] | None, typer.Option("--domain")] = None,
    social_link: Annotated[list[str] | None, typer.Option("--social-link")] = None,
    role_notes: Annotated[str | None, typer.Option("--role-notes")] = None,
    risk_sensitivity: Annotated[
        str,
        typer.Option("--risk-sensitivity", help="normal, high, or protected-role."),
    ] = "normal",
    consent: Annotated[
        bool,
        typer.Option("--consent", help="Confirm this profile is yours or consented."),
    ] = False,
) -> None:
    """Create an encrypted local consent profile."""
    init_db(_engine())
    if wizard:
        console.print(acceptable_use_panel())
        slug = slug or Prompt.ask("Profile slug", default="default")
        legal_name = legal_name or Prompt.ask("Legal name", default="")
        username = username or [Prompt.ask("Usernames (comma-separated)", default="")]
        email = email or [Prompt.ask("Emails (comma-separated)", default="")]
        phone = phone or [Prompt.ask("Phones (comma-separated, optional)", default="")]
        location = location or Prompt.ask("Approximate location (optional)", default="")
        risk_sensitivity = Prompt.ask(
            "Risk sensitivity",
            choices=["normal", "high", "protected-role"],
            default=risk_sensitivity,
        )
        consent = Confirm.ask(
            "Do you confirm this scan profile is yours or consented?",
            default=True,
        )
    if risk_sensitivity not in {"normal", "high", "protected-role"}:
        raise typer.BadParameter("risk-sensitivity must be normal, high, or protected-role.")
    if not slug:
        raise typer.BadParameter("--slug is required unless --wizard is used.")
    if not consent:
        raise typer.BadParameter("A consent profile requires --consent or wizard confirmation.")
    crypto = CryptoBox()
    with Session(_engine()) as session:
        if get_profile_by_slug(session, slug):
            raise typer.BadParameter(f"Profile '{slug}' already exists.")
        profile = create_profile(
            session,
            crypto,
            slug=slug,
            legal_name=(legal_name or None),
            display_names=_split_csv(display_name),
            usernames=_split_csv(username),
            emails=_split_csv(email),
            phones=_split_csv(phone),
            location=(location or None),
            domains=_split_csv(domain),
            social_links=_split_csv(social_link),
            role_notes=(role_notes or None),
            risk_sensitivity=risk_sensitivity,
            consent=consent,
        )
        console.print(f"[green]Created encrypted profile[/green] [bold]{profile.slug}[/bold].")


@profile_app.command("list")
def profile_list(show_sensitive: Annotated[bool, typer.Option("--show-sensitive")] = False) -> None:
    """List local consent profiles."""
    init_db(_engine())
    crypto = CryptoBox()
    with Session(_engine()) as session:
        profiles = list(session.exec(select(Profile)).all())
        rows = [profile.public_dict(crypto, show_sensitive=show_sensitive) for profile in profiles]
    console.print(profile_table(rows))


@profile_app.command("show")
def profile_show(
    slug: Annotated[str, typer.Argument(help="Profile slug.")],
    show_sensitive: Annotated[bool, typer.Option("--show-sensitive")] = False,
) -> None:
    """Show one local consent profile."""
    init_db(_engine())
    crypto = CryptoBox()
    with Session(_engine()) as session:
        profile = get_profile_by_slug(session, slug)
        if not profile:
            raise typer.BadParameter(f"Profile '{slug}' does not exist.")
        console.print_json(
            json.dumps(profile.public_dict(crypto, show_sensitive=show_sensitive), default=str)
        )


@scan_app.command("username")
def scan_username_command(
    value: Annotated[
        str | None,
        typer.Argument(help="Username to scan. Omit to use profile usernames."),
    ] = None,
    profile_slug: Annotated[
        str,
        typer.Option("--profile", "-p", help="Explicit consent profile slug."),
    ] = "default",
    depth: Annotated[str, typer.Option("--depth", help="quick, standard, or deep.")] = "quick",
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit machine-readable JSON."),
    ] = False,
) -> None:
    """Scan public username profile URLs from local site definitions."""
    if depth not in {"quick", "standard", "deep"}:
        raise typer.BadParameter("depth must be quick, standard, or deep.")
    init_db(_engine())
    crypto = CryptoBox()
    with Session(_engine()) as session:
        profile = _require_profile(session, profile_slug)
        usernames = [value] if value else profile.usernames(crypto)
        if not usernames:
            raise typer.BadParameter("No username supplied and profile has no usernames.")
        all_new: list[Finding] = []
        for username in usernames:
            with console.status(f"Checking public profiles for {username}...", spinner="dots"):
                all_new.extend(
                    asyncio.run(
                        scan_username(session, profile=profile, username=username, depth=depth)
                    )
                )
        findings = list_findings(session, profile)
        if json_output:
            console.print_json(
                json.dumps(
                    {
                        "profile": profile.slug,
                        "new_findings": len(all_new),
                        "exposure_score": exposure_score(findings, profile),
                        "top_actions": top_actions(findings),
                        "findings": [finding.model_dump(mode="json") for finding in findings],
                    },
                    default=str,
                )
            )
            return
        console.print(summary_panel(profile, findings))
        console.print(findings_table(all_new if all_new else findings))
        console.print(actions_panel(findings))


@scan_app.command("all")
def scan_all_command(
    profile_slug: Annotated[
        str,
        typer.Option("--profile", "-p", help="Explicit consent profile slug."),
    ] = "default",
    depth: Annotated[str, typer.Option("--depth", help="quick, standard, or deep.")] = "quick",
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit machine-readable JSON."),
    ] = False,
) -> None:
    """Run all Milestone 1 checks for a profile."""
    scan_username_command(None, profile_slug, depth, json_output)


@scan_app.command("email")
def scan_email_command() -> None:
    """Milestone 2 placeholder for HIBP and safe account exposure checks."""
    console.print(
        "[yellow]Email scanning lands in Milestone 2. "
        "No password reset or login checks will be used.[/yellow]"
    )


@scan_app.command("phone")
def scan_phone_command() -> None:
    """Milestone 2 placeholder for safe phone exposure checks."""
    console.print(
        "[yellow]Phone scanning lands in Milestone 2. "
        "CleanTrace will not send SMS or verify numbers.[/yellow]"
    )


@scan_app.command("name")
def scan_name_command() -> None:
    """Milestone 2 placeholder for search-API-backed public web checks."""
    console.print(
        "[yellow]Name/public web scanning lands in Milestone 2 via configured search APIs.[/yellow]"
    )


@scan_app.command("domain")
def scan_domain_command() -> None:
    """Milestone 2 placeholder for domain exposure checks."""
    console.print("[yellow]Domain scanning lands in Milestone 2.[/yellow]")


@app.command("findings")
def findings_command(
    profile_slug: Annotated[str | None, typer.Option("--profile", "-p")] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List stored findings."""
    init_db(_engine())
    with Session(_engine()) as session:
        profile = get_profile_by_slug(session, profile_slug) if profile_slug else None
        findings = list_findings(session, profile)
        if json_output:
            console.print_json(
                json.dumps([finding.model_dump(mode="json") for finding in findings], default=str)
            )
            return
        if profile:
            console.print(summary_panel(profile, findings))
        console.print(findings_table(findings))
        console.print(actions_panel(findings))


@app.command("report")
def report_command(
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    fmt: Annotated[str, typer.Option("--format", help="markdown or html.")] = "markdown",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    """Generate a local Markdown or HTML report."""
    init_db(_engine())
    if fmt == "md":
        fmt = "markdown"
    if fmt not in {"markdown", "html"}:
        raise typer.BadParameter("format must be markdown or html.")
    with Session(_engine()) as session:
        profile = get_profile_by_slug(session, profile_slug)
        if not profile:
            raise typer.BadParameter(f"Profile '{profile_slug}' does not exist.")
        findings = list_findings(session, profile)
        default_name = f"cleantrace-{profile.slug}.{'md' if fmt == 'markdown' else 'html'}"
        target = output or Path(default_name)
        write_report(profile, findings, fmt, target)
        console.print(f"[green]Report written:[/green] {target.resolve()}")


@app.command("config")
def config_command() -> None:
    """Show local configuration paths."""
    cfg = load_config()
    console.print_json(
        json.dumps(
            {
                "config": str(config_path()),
                "database": str(cfg.database),
                "user_sites_dir": str(cfg.user_sites_dir),
                "ai_provider": cfg.ai_provider,
            }
        )
    )


@plugins_app.command("list")
def plugins_list() -> None:
    """List built-in plugins and their risk labels."""
    table = Table(title="Plugins", box=box.SIMPLE_HEAVY)
    table.add_column("Name", style="bold")
    table.add_column("Inputs")
    table.add_column("Risk")
    table.add_column("API key")
    table.add_column("Default")
    table.add_column("Description")
    for plugin in built_in_plugins():
        table.add_row(
            plugin.meta.name,
            ", ".join(plugin.meta.input_types),
            plugin.meta.risk_level,
            "yes" if plugin.meta.needs_api_key else "no",
            "yes" if plugin.meta.enabled_by_default else "no",
            plugin.meta.description,
        )
    console.print(table)


@plugins_app.command("enable")
def plugins_enable(name: Annotated[str, typer.Argument()]) -> None:
    """Milestone 2 placeholder for user plugin configuration."""
    console.print(f"[yellow]Plugin enable/disable config lands in Milestone 2: {name}[/yellow]")


@plugins_app.command("disable")
def plugins_disable(name: Annotated[str, typer.Argument()]) -> None:
    """Milestone 2 placeholder for user plugin configuration."""
    console.print(f"[yellow]Plugin enable/disable config lands in Milestone 2: {name}[/yellow]")


@removal_app.command("generate")
def removal_generate(
    finding: Annotated[str | None, typer.Option("--finding")] = None,
    broker: Annotated[str | None, typer.Option("--broker")] = None,
) -> None:
    """Milestone 2 placeholder for removal request templates."""
    subject = finding or broker or "manual review"
    console.print(
        "[yellow]Removal templates land in Milestone 2.[/yellow]\n"
        f"Subject: {redact_text(subject)}\n"
        "Planned templates: UK GDPR erasure, rectification, data broker opt-out, forum deletion."
    )


@removal_app.command("track")
def removal_track() -> None:
    """Milestone 2 placeholder for cleanup tracking."""
    console.print("[yellow]Removal tracking lands in Milestone 2.[/yellow]")


@removal_app.command("list")
def removal_list() -> None:
    """Milestone 2 placeholder for removal status listing."""
    console.print("[yellow]Removal status listing lands in Milestone 2.[/yellow]")


@link_app.command("github")
def link_github() -> None:
    console.print(
        "[yellow]GitHub connector lands in Milestone 2 and will use official APIs only.[/yellow]"
    )


@link_app.command("google")
def link_google() -> None:
    console.print(
        "[yellow]Google support lands later via official OAuth or local Takeout import.[/yellow]"
    )


@link_app.command("reddit")
def link_reddit() -> None:
    console.print(
        "[yellow]Reddit connector lands in Milestone 2 using public/API-supported "
        "data only.[/yellow]"
    )


@link_app.command("steam")
def link_steam() -> None:
    console.print(
        "[yellow]Steam connector lands in Milestone 2 using public profile data only.[/yellow]"
    )


@unlink_app.callback(invoke_without_command=True)
def unlink_provider(provider: Annotated[str | None, typer.Argument()] = None) -> None:
    if provider:
        console.print(
            f"[yellow]No stored token for {provider}. "
            "Connector storage lands in Milestone 2.[/yellow]"
        )


@import_app.command("google-takeout")
def import_google_takeout(path: Annotated[Path, typer.Argument()]) -> None:
    console.print(f"[yellow]Google Takeout local parsing lands in Milestone 3:[/yellow] {path}")


@app.command("tui")
def tui_command() -> None:
    """Milestone 3 placeholder for the optional Textual dashboard."""
    console.print("[yellow]Textual TUI dashboard lands in Milestone 3.[/yellow]")


@app.command("wipe")
def wipe_command(
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Do not prompt.")] = False,
) -> None:
    """Delete the local database. The encryption key is kept unless removed manually."""
    if not yes and not Confirm.ask("Delete the local CleanTrace database?"):
        console.print("[yellow]Wipe cancelled.[/yellow]")
        raise typer.Exit(1)
    db = database_path()
    if db.exists():
        db.unlink()
    console.print("[green]Local CleanTrace database removed.[/green]")

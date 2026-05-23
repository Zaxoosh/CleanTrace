from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from typing import Annotated

import typer
from rich import box
from rich.prompt import Confirm, Prompt
from rich.table import Table
from sqlalchemy import Engine
from sqlmodel import Session, select

from cleantrace import __version__
from cleantrace.ai import (
    AIUnavailableError,
    actions_prompt,
    build_findings_context,
    ollama_generate,
    removal_email_prompt,
    summarise_prompt,
)
from cleantrace.alerts import alert_summary
from cleantrace.config import config_get, config_set, get_api_key, load_config, write_default_config
from cleantrace.db import get_engine, get_profile_by_slug, init_db, list_findings
from cleantrace.evidence import import_evidence_file
from cleantrace.models import Finding, Profile, RemovalRequest
from cleantrace.monitoring import load_monitor_state, update_monitor_snapshot
from cleantrace.paths import config_path, database_path, key_path
from cleantrace.phone import parse_phone_number
from cleantrace.plugin_state import load_plugin_states, set_plugin_enabled
from cleantrace.plugins.data_brokers import broker_removal_plan
from cleantrace.plugins.manager import built_in_plugin_metadata
from cleantrace.plugins.pwned_passwords import check_pwned_password
from cleantrace.plugins.tor_public_check import check_tor_urls
from cleantrace.readiness import (
    MODULE_DEPENDENCIES,
    ModuleReadiness,
    config_sections,
    readiness_for,
)
from cleantrace.removal import (
    REMOVAL_STATUSES,
    broker_names,
    find_broker,
    load_brokers,
    render_broker_request,
    render_finding_request,
)
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
from cleantrace.scan_sessions import (
    ScanSession,
    cancel_session,
    create_session,
    latest_resumable_session,
    load_sessions,
    update_session,
)
from cleantrace.scoring import exposure_score, top_actions
from cleantrace.security import CryptoBox, redact_text
from cleantrace.services import (
    add_profile_phone,
    create_profile,
    create_removal_request,
    get_finding,
    get_removal_request,
    link_account,
    list_removal_requests,
    remove_profile_phone,
    scan_brokers,
    scan_email,
    scan_github_linked,
    scan_intel,
    scan_phone_profile,
    scan_social,
    scan_username,
    scan_web_discovery,
    update_removal_status,
    upsert_finding,
)
from cleantrace.services import (
    unlink_provider as unlink_provider_service,
)
from cleantrace.takeout import analyse_google_takeout
from cleantrace.tui import run_tui

app = typer.Typer(
    name="cleantrace",
    help="Local-first privacy exposure and OSINT self-assessment.",
    no_args_is_help=True,
    invoke_without_command=True,
)
profile_app = typer.Typer(help="Manage explicit consent profiles.", no_args_is_help=True)
profile_phone_app = typer.Typer(
    help="Manage encrypted profile phone numbers.",
    no_args_is_help=True,
)
scan_app = typer.Typer(help="Run consent-based local-first scans.", no_args_is_help=True)
plugins_app = typer.Typer(help="Inspect and configure scanner plugins.", no_args_is_help=True)
removal_app = typer.Typer(help="Generate and track removal actions.", no_args_is_help=True)
link_app = typer.Typer(help="Link optional self-owned account connectors.", no_args_is_help=True)
unlink_app = typer.Typer(help="Disconnect linked providers.", no_args_is_help=True)
import_app = typer.Typer(help="Import local account exports.", no_args_is_help=True)
ai_app = typer.Typer(
    help="Local AI assistant commands. Disabled unless explicitly configured.",
    no_args_is_help=True,
)
brokers_app = typer.Typer(
    help="Explore data broker sources and removal plans.",
    no_args_is_help=True,
)
monitor_app = typer.Typer(help="Local monitoring and change detection.", no_args_is_help=True)

app.add_typer(profile_app, name="profile")
profile_app.add_typer(profile_phone_app, name="phone")
app.add_typer(scan_app, name="scan")
app.add_typer(plugins_app, name="plugins")
app.add_typer(removal_app, name="removal")
app.add_typer(link_app, name="link")
app.add_typer(unlink_app, name="unlink")
app.add_typer(import_app, name="import")
app.add_typer(ai_app, name="ai")
app.add_typer(brokers_app, name="brokers")
app.add_typer(monitor_app, name="monitor")


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


def _run_json_command(args: list[str]) -> str | None:
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            check=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    value = completed.stdout.strip()
    return value or None


def _github_from_gh() -> tuple[str | None, str | None]:
    token = _run_json_command(["gh", "auth", "token"])
    username = _run_json_command(["gh", "api", "user", "--jq", ".login"])
    return username, token


def _profile_for_session(session: Session, scan_session: ScanSession) -> Profile:
    profile = session.get(Profile, scan_session.profile_id)
    if not profile:
        raise typer.BadParameter("Saved scan session refers to a missing profile.")
    if not profile.consent:
        raise typer.BadParameter("Saved scan session profile no longer has consent.")
    return profile


def _run_scan_modules(
    session: Session,
    crypto: CryptoBox,
    profile: Profile,
    scan_session: ScanSession,
    modules: list[str],
) -> list[Finding]:
    new_findings: list[Finding] = []
    for module in modules:
        if module in scan_session.completed_modules:
            continue
        ready = readiness_for([module])[0]
        if not ready.ready and not ready.dependency.can_run_without_config:
            if module not in scan_session.pending_setup_modules:
                scan_session.pending_setup_modules.append(module)
            continue
        if module == "username":
            for username in profile.usernames(crypto):
                new_findings.extend(
                    asyncio.run(
                        scan_username(
                            session,
                            profile=profile,
                            username=username,
                            depth=scan_session.depth,
                        )
                    )
                )
        elif module == "social":
            new_findings.extend(
                asyncio.run(
                    scan_social(session, crypto, profile=profile, depth=scan_session.depth)
                )
            )
        elif module == "email":
            key = get_api_key("hibp")
            if key:
                for email in profile.emails(crypto):
                    new_findings.extend(
                        asyncio.run(
                            scan_email(
                                session,
                                profile=profile,
                                email=email,
                                depth=scan_session.depth,
                                api_key=key,
                            )
                        )
                    )
        elif module == "phone":
            new_findings.extend(scan_phone_profile(session, crypto, profile=profile))
        elif module == "web":
            new_findings.extend(
                asyncio.run(
                    scan_web_discovery(
                        session,
                        crypto,
                        profile=profile,
                        depth=scan_session.depth,
                        query_set="all",
                    )
                )
            )
        elif module == "brokers":
            new_findings.extend(
                asyncio.run(
                    scan_brokers(
                        session,
                        crypto,
                        profile=profile,
                        depth=scan_session.depth,
                    )
                )
            )
        elif module == "intel":
            new_findings.extend(
                asyncio.run(
                    scan_intel(session, crypto, profile=profile, depth=scan_session.depth)
                )
            )
        elif module == "github":
            new_findings.extend(asyncio.run(scan_github_linked(session, crypto, profile=profile)))
        else:
            scan_session.skipped_modules.append(module)
            continue
        if module not in scan_session.completed_modules:
            scan_session.completed_modules.append(module)
    requested = set(scan_session.requested_modules)
    complete_or_skipped = set(scan_session.completed_modules) | set(scan_session.skipped_modules)
    if requested <= complete_or_skipped:
        scan_session.status = "complete"
    update_session(scan_session)
    return new_findings


def removal_table(requests: list[RemovalRequest]) -> Table:
    table = Table(title="Removal Requests", box=box.SIMPLE_HEAVY)
    table.add_column("ID", style="dim", no_wrap=True)
    table.add_column("Status")
    table.add_column("Subject")
    table.add_column("Broker")
    table.add_column("Finding")
    for request in requests:
        table.add_row(
            request.id[:10],
            request.status,
            request.subject,
            request.broker_name or "",
            request.finding_id[:10] if request.finding_id else "",
        )
    return table


def readiness_table(readiness: list[ModuleReadiness]) -> Table:
    table = Table(title="Config Readiness", box=box.SIMPLE_HEAVY)
    table.add_column("Module", style="bold")
    table.add_column("Ready")
    table.add_column("Privacy Impact")
    table.add_column("Status")
    table.add_column("Fallback")
    for item in readiness:
        table.add_row(
            item.dependency.label,
            "yes" if item.ready else "no",
            item.dependency.privacy_impact,
            item.reason,
            item.dependency.fallback_mode,
        )
    return table


def session_table(sessions: list[ScanSession]) -> Table:
    table = Table(title="Scan Sessions", box=box.SIMPLE_HEAVY)
    table.add_column("ID")
    table.add_column("Profile")
    table.add_column("Depth")
    table.add_column("Status")
    table.add_column("Completed")
    table.add_column("Pending")
    table.add_column("Resume")
    for session in sessions:
        table.add_row(
            session.scan_session_id[:10],
            str(session.profile_id),
            session.depth,
            session.status,
            ", ".join(session.completed_modules) or "-",
            ", ".join(session.pending_setup_modules) or "-",
            session.resume_token,
        )
    return table


def config_sections_table() -> Table:
    table = Table(title="CleanTrace Configuration Guide", box=box.SIMPLE_HEAVY)
    table.add_column("Section", style="bold")
    table.add_column("Purpose")
    table.add_column("Required")
    table.add_column("Privacy")
    table.add_column("Setting")
    table.add_column("Current")
    for section in config_sections():
        key = str(section["setting"])
        table.add_row(
            str(section["name"]),
            str(section["purpose"]),
            str(section["required"]),
            str(section["privacy"]),
            key,
            str(config_get(key, "see local file")),
        )
    return table


def select_or_create_profile(
    session: Session,
    crypto: CryptoBox,
    profile_slug: str | None,
) -> Profile:
    if profile_slug:
        return _require_profile(session, profile_slug)
    profiles = list(session.exec(select(Profile)).all())
    if profiles:
        choices = [profile.slug for profile in profiles]
        slug = Prompt.ask("Profile", choices=choices, default=choices[0])
        return _require_profile(session, slug)
    console.print("[yellow]No consent profile exists yet. Let's create one.[/yellow]")
    slug = Prompt.ask("Profile slug", default="default")
    username = Prompt.ask("Usernames (comma-separated)", default="")
    email = Prompt.ask("Emails (comma-separated)", default="")
    consent = Confirm.ask(
        "Do you confirm this profile is yours or clearly consented?",
        default=True,
    )
    if not consent:
        raise typer.BadParameter("CleanTrace requires an explicit consent profile.")
    profile = create_profile(
        session,
        crypto,
        slug=slug,
        legal_name=Prompt.ask("Legal name (optional)", default="") or None,
        display_names=[],
        usernames=_split_csv([username]),
        emails=_split_csv([email]),
        phones=[],
        location=Prompt.ask("Approximate location (optional)", default="") or None,
        domains=[],
        social_links=[],
        role_notes=None,
        risk_sensitivity="normal",
        consent=True,
    )
    return profile


def choose_scan_modules(advanced: bool) -> list[str]:
    if Confirm.ask("Run a full broad exposure scan?", default=not advanced):
        return ["username", "social", "phone", "web", "brokers", "intel", "github"]
    options = [
        ("username", "usernames and social profiles"),
        ("social", "expanded social/profile sites"),
        ("email", "email exposure"),
        ("phone", "phone exposure"),
        ("web", "public web exposure"),
        ("brokers", "data brokers and people-search sites"),
        ("intel", "breach intelligence"),
        ("github", "linked GitHub exposure"),
        ("takeout", "Google Takeout exposure"),
        ("tor", "Tor public URL checks"),
    ]
    selected: list[str] = []
    for key, label in options:
        if Confirm.ask(f"Include {label}?", default=key in {"username", "social", "brokers"}):
            selected.append(key)
    return selected or ["username"]


def handle_missing_config(readiness: list[ModuleReadiness]) -> list[str]:
    selected: list[str] = []
    for item in readiness:
        if item.ready or item.dependency.can_run_without_config:
            selected.append(item.dependency.name)
            continue
        console.print(f"\n[yellow]{item.dependency.label} is not ready.[/yellow]")
        console.print(item.dependency.setup_instructions or item.reason)
        action = Prompt.ask(
            "Action",
            choices=["configure", "skip", "fallback", "exit"],
            default="skip",
        )
        if action == "exit":
            raise typer.Exit(1)
        if action == "skip":
            continue
        if action == "fallback":
            selected.append(item.dependency.name)
            continue
        configure_module(item.dependency.name)
        if readiness_for([item.dependency.name])[0].ready:
            selected.append(item.dependency.name)
    return selected


def configure_module(module: str) -> None:
    if module == "web":
        console.print(
            "Public web discovery needs a search provider. Recommended local option: "
            "SearXNG. Recommended API option: Brave Search."
        )
        provider = Prompt.ask(
            "Provider",
            choices=["searxng", "brave", "bing", "google_cse", "serpapi", "skip"],
            default="searxng",
        )
        if provider == "skip":
            return
        config_set("web_discovery.enabled", "true")
        config_set("web_discovery.default_provider", provider)
        config_set(f"web_discovery.providers.{provider}.enabled", "true")
        if provider == "searxng":
            base_url = Prompt.ask("SearXNG base URL", default="http://localhost:8080")
            config_set("web_discovery.providers.searxng.base_url", base_url)
        else:
            key = Prompt.ask(f"{provider} API key", password=True)
            config_set(f"web_discovery.providers.{provider}.api_key", key)
            if provider == "google_cse":
                cx = Prompt.ask("Google Custom Search engine ID")
                config_set("web_discovery.providers.google_cse.search_engine_id", cx)
        set_plugin_enabled("web_discovery", True)
    elif module == "intel":
        config_set("breach_intel.enabled", "true")
        config_set("breach_intel.providers.hibp.enabled", "true")
        key = Prompt.ask("HIBP API key", password=True)
        config_set("breach_intel.providers.hibp.api_key", key)
        config_set("api_keys.hibp", key)
        set_plugin_enabled("breach_intel", True)
        set_plugin_enabled("hibp_email", True)
    elif module == "tor":
        config_set("tor_public_check.enabled", "true")
        proxy = Prompt.ask("Tor SOCKS proxy", default="socks5://127.0.0.1:9050")
        config_set("tor_public_check.socks_proxy", proxy)
        set_plugin_enabled("tor_public_check", True)


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


@profile_phone_app.command("add")
def profile_phone_add(
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    phone: Annotated[str | None, typer.Argument(help="Phone number to add.")] = None,
    country: Annotated[
        str,
        typer.Option("--country", help="Country name, ISO code, or dialling code."),
    ] = "GB",
) -> None:
    """Add and normalise an encrypted phone number for a consent profile."""
    init_db(_engine())
    phone = phone or Prompt.ask("Phone number")
    crypto = CryptoBox()
    with Session(_engine()) as session:
        profile = _require_profile(session, profile_slug)
        try:
            parsed = parse_phone_number(phone, country)
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
        add_profile_phone(session, crypto, profile=profile, phone=phone, country=country)
    console.print(
        "[green]Added phone[/green] "
        f"{redact_text(parsed.international_format)} "
        f"({parsed.region_code}, valid={parsed.is_valid})"
    )


@profile_phone_app.command("list")
def profile_phone_list(
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    show_sensitive: Annotated[bool, typer.Option("--show-sensitive")] = False,
) -> None:
    """List encrypted profile phone numbers with country metadata."""
    init_db(_engine())
    crypto = CryptoBox()
    with Session(_engine()) as session:
        profile = _require_profile(session, profile_slug)
        phones = profile.phone_metadata(crypto)
    table = Table(title=f"Phone Numbers: {profile_slug}", box=box.SIMPLE_HEAVY)
    table.add_column("Phone")
    table.add_column("National")
    table.add_column("Region")
    table.add_column("Calling code")
    table.add_column("Valid")
    for phone in phones:
        table.add_row(
            phone.e164 if show_sensitive else redact_text(phone.e164),
            phone.national_format if show_sensitive else redact_text(phone.national_format),
            phone.region_code,
            str(phone.country_calling_code),
            "yes" if phone.is_valid else "no",
        )
    console.print(table)


@profile_phone_app.command("remove")
def profile_phone_remove(
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    phone: Annotated[str, typer.Argument(help="Phone number or E.164 value to remove.")] = "",
) -> None:
    """Remove a phone number from an encrypted consent profile."""
    init_db(_engine())
    crypto = CryptoBox()
    with Session(_engine()) as session:
        profile = _require_profile(session, profile_slug)
        removed = remove_profile_phone(session, crypto, profile=profile, value=phone)
    console.print(f"[green]Removed {removed} phone number(s).[/green]")


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
    """Run enabled consent-profile exposure checks."""
    if depth not in {"quick", "standard", "deep"}:
        raise typer.BadParameter("depth must be quick, standard, or deep.")
    init_db(_engine())
    crypto = CryptoBox()
    with Session(_engine()) as session:
        profile = _require_profile(session, profile_slug)
        new_findings: list[Finding] = []
        for username in profile.usernames(crypto):
            with console.status(f"Checking public profiles for {username}...", spinner="dots"):
                new_findings.extend(
                    asyncio.run(
                        scan_username(session, profile=profile, username=username, depth=depth)
                    )
                )
        hibp_key = get_api_key("hibp")
        if hibp_key:
            for email in profile.emails(crypto):
                with console.status(
                    "Checking HIBP for configured profile email...",
                    spinner="dots",
                ):
                    new_findings.extend(
                        asyncio.run(
                            scan_email(
                                session,
                                profile=profile,
                                email=email,
                                depth=depth,
                                api_key=hibp_key,
                            )
                        )
                    )
        with console.status("Checking expanded social/profile sites...", spinner="dots"):
            new_findings.extend(
                asyncio.run(scan_social(session, crypto, profile=profile, depth=depth))
            )
        new_findings.extend(scan_phone_profile(session, crypto, profile=profile))
        with console.status("Running enabled public web discovery...", spinner="dots"):
            new_findings.extend(
                asyncio.run(
                    scan_web_discovery(
                        session,
                        crypto,
                        profile=profile,
                        depth=depth,
                        query_set="all",
                    )
                )
            )
        with console.status("Checking enabled breach intelligence providers...", spinner="dots"):
            new_findings.extend(
                asyncio.run(scan_intel(session, crypto, profile=profile, depth=depth))
            )
        with console.status("Building data broker guidance...", spinner="dots"):
            new_findings.extend(
                asyncio.run(scan_brokers(session, crypto, profile=profile, depth=depth))
            )
        with console.status("Checking linked GitHub accounts...", spinner="dots"):
            new_findings.extend(
                asyncio.run(scan_github_linked(session, crypto, profile=profile))
            )
        findings = list_findings(session, profile)
        if json_output:
            console.print_json(
                json.dumps(
                    {
                        "profile": profile.slug,
                        "new_findings": len(new_findings),
                        "exposure_score": exposure_score(findings, profile),
                        "top_actions": top_actions(findings),
                        "findings": [finding.model_dump(mode="json") for finding in findings],
                    },
                    default=str,
                )
            )
            return
        console.print(summary_panel(profile, findings))
        console.print(findings_table(new_findings if new_findings else findings))
        console.print(actions_panel(findings))


@scan_app.command("email")
def scan_email_command(
    value: Annotated[
        str | None,
        typer.Argument(help="Email to scan. Omit to use profile emails."),
    ] = None,
    profile_slug: Annotated[
        str,
        typer.Option("--profile", "-p", help="Explicit consent profile slug."),
    ] = "default",
    depth: Annotated[str, typer.Option("--depth", help="quick, standard, or deep.")] = "quick",
    hibp: Annotated[
        bool,
        typer.Option("--hibp/--no-hibp", help="Use official HIBP API."),
    ] = True,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit machine-readable JSON."),
    ] = False,
) -> None:
    """Check email breach exposure through the official HIBP API when configured."""
    if depth not in {"quick", "standard", "deep"}:
        raise typer.BadParameter("depth must be quick, standard, or deep.")
    init_db(_engine())
    crypto = CryptoBox()
    api_key = get_api_key("hibp") if hibp else None
    if hibp and not api_key:
        console.print(
            "[yellow]HIBP API key not configured.[/yellow] Set api_keys.hibp in "
            f"{config_path()} or CLEANTRACE_HIBP_API_KEY."
        )
    with Session(_engine()) as session:
        profile = _require_profile(session, profile_slug)
        emails = [value] if value else profile.emails(crypto)
        if not emails:
            raise typer.BadParameter("No email supplied and profile has no emails.")
        all_new: list[Finding] = []
        if api_key:
            for email in emails:
                with console.status("Checking HIBP using the official API...", spinner="dots"):
                    all_new.extend(
                        asyncio.run(
                            scan_email(
                                session,
                                profile=profile,
                                email=email,
                                depth=depth,
                                api_key=api_key,
                            )
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


@scan_app.command("github")
def scan_github_command(
    profile_slug: Annotated[
        str,
        typer.Option("--profile", "-p", help="Explicit consent profile slug."),
    ] = "default",
    include_private: Annotated[
        bool,
        typer.Option(
            "--include-private",
            help="Scan private repos only when linked with token opt-in.",
        ),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit machine-readable JSON."),
    ] = False,
) -> None:
    """Scan linked GitHub account public exposure through official GitHub APIs."""
    init_db(_engine())
    crypto = CryptoBox()
    with Session(_engine()) as session:
        profile = _require_profile(session, profile_slug)
        with console.status("Checking linked GitHub accounts...", spinner="dots"):
            new_findings = asyncio.run(
                scan_github_linked(
                    session,
                    crypto,
                    profile=profile,
                    include_private=include_private,
                )
            )
        findings = list_findings(session, profile)
        if json_output:
            console.print_json(
                json.dumps(
                    {
                        "profile": profile.slug,
                        "new_findings": len(new_findings),
                        "exposure_score": exposure_score(findings, profile),
                        "findings": [finding.model_dump(mode="json") for finding in findings],
                    },
                    default=str,
                )
            )
            return
        console.print(summary_panel(profile, findings))
        console.print(findings_table(new_findings if new_findings else findings))
        console.print(actions_panel(findings))


@scan_app.command("phone")
def scan_phone_command(
    value: Annotated[
        str | None,
        typer.Argument(help="Phone number to validate. Omit to use profile phones."),
    ] = None,
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    country: Annotated[str, typer.Option("--country")] = "GB",
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Validate phone metadata and generate safe public-web search variants."""
    init_db(_engine())
    crypto = CryptoBox()
    with Session(_engine()) as session:
        profile = _require_profile(session, profile_slug)
        try:
            new_findings = scan_phone_profile(
                session,
                crypto,
                profile=profile,
                value=value,
                country=country,
            )
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
        findings = list_findings(session, profile)
    if json_output:
        console.print_json(
            json.dumps(
                {
                    "profile": profile_slug,
                    "new_findings": len(new_findings),
                    "findings": [finding.model_dump(mode="json") for finding in new_findings],
                },
                default=str,
            )
        )
        return
    console.print(findings_table(new_findings))
    console.print(actions_panel(findings))


@scan_app.command("web")
def scan_web_command(
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    depth: Annotated[str, typer.Option("--depth", help="quick, standard, or deep.")] = "quick",
    query_set: Annotated[
        str,
        typer.Option("--query-set", help="identity, phone, username, email, or all."),
    ] = "identity",
    provider: Annotated[str | None, typer.Option("--provider")] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run public web discovery through a configured search provider."""
    if depth not in {"quick", "standard", "deep"}:
        raise typer.BadParameter("depth must be quick, standard, or deep.")
    if query_set not in {"identity", "phone", "username", "email", "all"}:
        raise typer.BadParameter("query-set must be identity, phone, username, email, or all.")
    init_db(_engine())
    crypto = CryptoBox()
    with Session(_engine()) as session:
        profile = _require_profile(session, profile_slug)
        with console.status("Running provider-backed public web discovery...", spinner="dots"):
            new_findings = asyncio.run(
                scan_web_discovery(
                    session,
                    crypto,
                    profile=profile,
                    depth=depth,
                    query_set=query_set,
                    provider_name=provider,
                )
            )
        findings = list_findings(session, profile)
    if json_output:
        console.print_json(
            json.dumps(
                {
                    "profile": profile_slug,
                    "new_findings": len(new_findings),
                    "exposure_score": exposure_score(findings, profile),
                    "findings": [finding.model_dump(mode="json") for finding in new_findings],
                },
                default=str,
            )
        )
        return
    console.print(summary_panel(profile, findings))
    console.print(findings_table(new_findings if new_findings else findings))
    console.print(actions_panel(findings))


@scan_app.command("intel")
def scan_intel_command(
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    provider: Annotated[
        str | None,
        typer.Option("--provider", help="hibp, leakcheck, dehashed, or intelx."),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run metadata-only Breach & Dark Web Intelligence checks."""
    if provider and provider not in {"hibp", "leakcheck", "dehashed", "intelx"}:
        raise typer.BadParameter("provider must be hibp, leakcheck, dehashed, or intelx.")
    init_db(_engine())
    crypto = CryptoBox()
    with Session(_engine()) as session:
        profile = _require_profile(session, profile_slug)
        with console.status("Checking breach intelligence metadata providers...", spinner="dots"):
            new_findings = asyncio.run(
                scan_intel(session, crypto, profile=profile, provider=provider)
            )
        findings = list_findings(session, profile)
    if json_output:
        console.print_json(
            json.dumps(
                {
                    "profile": profile_slug,
                    "new_findings": len(new_findings),
                    "findings": [finding.model_dump(mode="json") for finding in new_findings],
                },
                default=str,
            )
        )
        return
    console.print(summary_panel(profile, findings))
    console.print(findings_table(new_findings if new_findings else findings))
    console.print(actions_panel(findings))


@scan_app.command("tor-url")
def scan_tor_url_command(
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    url: Annotated[str, typer.Option("--url", help="Explicit user-provided onion URL.")] = "",
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Confirm safe-use warning.")] = False,
) -> None:
    """Check one explicit public onion URL without crawling."""
    if not url:
        raise typer.BadParameter("--url is required.")
    prompt = (
        "I confirm these URLs are being checked for my own safety and I will not use "
        "this tool to access illegal content."
    )
    if not yes and not Confirm.ask(prompt, default=False):
        raise typer.Exit(1)
    init_db(_engine())
    crypto = CryptoBox()
    with Session(_engine()) as session:
        profile = _require_profile(session, profile_slug)
        plugin_findings = asyncio.run(check_tor_urls(profile, crypto, [url]))
        new_findings = [upsert_finding(session, profile, finding) for finding in plugin_findings]
        session.commit()
        findings = list_findings(session, profile)
    console.print(findings_table(new_findings))
    console.print(actions_panel(findings))


@scan_app.command("tor-list")
def scan_tor_list_command(
    file: Annotated[Path, typer.Option("--file", help="Text file of explicit onion URLs.")],
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Confirm safe-use warning.")] = False,
) -> None:
    """Check explicit public onion URLs from a local file without crawling."""
    prompt = (
        "I confirm these URLs are being checked for my own safety and I will not use "
        "this tool to access illegal content."
    )
    if not yes and not Confirm.ask(prompt, default=False):
        raise typer.Exit(1)
    urls = [line.strip() for line in file.read_text(encoding="utf-8").splitlines() if line.strip()]
    init_db(_engine())
    crypto = CryptoBox()
    with Session(_engine()) as session:
        profile = _require_profile(session, profile_slug)
        plugin_findings = asyncio.run(check_tor_urls(profile, crypto, urls))
        new_findings = [upsert_finding(session, profile, finding) for finding in plugin_findings]
        session.commit()
        findings = list_findings(session, profile)
    console.print(findings_table(new_findings))
    console.print(actions_panel(findings))


@scan_app.command("exposure")
def scan_exposure_command(
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    depth: Annotated[str, typer.Option("--depth", help="quick, standard, or deep.")] = "quick",
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run enabled modules for a broad, consent-profile exposure assessment."""
    if depth not in {"quick", "standard", "deep"}:
        raise typer.BadParameter("depth must be quick, standard, or deep.")
    init_db(_engine())
    crypto = CryptoBox()
    with Session(_engine()) as session:
        profile = _require_profile(session, profile_slug)
        new_findings: list[Finding] = []
        for username in profile.usernames(crypto):
            new_findings.extend(
                asyncio.run(scan_username(session, profile=profile, username=username, depth=depth))
            )
        new_findings.extend(asyncio.run(scan_social(session, crypto, profile=profile, depth=depth)))
        new_findings.extend(scan_phone_profile(session, crypto, profile=profile))
        new_findings.extend(
            asyncio.run(
                scan_web_discovery(
                    session,
                    crypto,
                    profile=profile,
                    depth=depth,
                    query_set="all",
                )
            )
        )
        new_findings.extend(asyncio.run(scan_intel(session, crypto, profile=profile, depth=depth)))
        new_findings.extend(
            asyncio.run(scan_brokers(session, crypto, profile=profile, depth=depth))
        )
        new_findings.extend(asyncio.run(scan_github_linked(session, crypto, profile=profile)))
        findings = list_findings(session, profile)
    if json_output:
        console.print_json(
            json.dumps(
                {
                    "profile": profile_slug,
                    "new_findings": len(new_findings),
                    "overall_exposure_score": exposure_score(findings, profile),
                    "top_actions": top_actions(findings),
                    "findings": [finding.model_dump(mode="json") for finding in findings],
                },
                default=str,
            )
        )
        return
    console.print(summary_panel(profile, findings))
    console.print(findings_table(new_findings if new_findings else findings))
    console.print(actions_panel(findings))


@scan_app.command("social")
def scan_social_command(
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    depth: Annotated[str, typer.Option("--depth", help="quick, standard, or deep.")] = "quick",
    username: Annotated[str | None, typer.Option("--username")] = None,
    category: Annotated[str | None, typer.Option("--category")] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Check broad public social/profile sites for profile usernames."""
    if depth not in {"quick", "standard", "deep"}:
        raise typer.BadParameter("depth must be quick, standard, or deep.")
    init_db(_engine())
    crypto = CryptoBox()
    with Session(_engine()) as session:
        profile = _require_profile(session, profile_slug)
        with console.status("Checking public social/profile sites...", spinner="dots"):
            new_findings = asyncio.run(
                scan_social(
                    session,
                    crypto,
                    profile=profile,
                    depth=depth,
                    username=username,
                    category=category,
                )
            )
        findings = list_findings(session, profile)
    if json_output:
        console.print_json(
            json.dumps([finding.model_dump(mode="json") for finding in new_findings], default=str)
        )
        return
    console.print(summary_panel(profile, findings))
    console.print(findings_table(new_findings if new_findings else findings))
    console.print(actions_panel(findings))


@scan_app.command("brokers")
def scan_brokers_command(
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    country: Annotated[str | None, typer.Option("--country")] = None,
    depth: Annotated[str, typer.Option("--depth", help="quick, standard, or deep.")] = "quick",
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Check data broker/people-search sources or generate manual guidance."""
    if depth not in {"quick", "standard", "deep"}:
        raise typer.BadParameter("depth must be quick, standard, or deep.")
    init_db(_engine())
    crypto = CryptoBox()
    with Session(_engine()) as session:
        profile = _require_profile(session, profile_slug)
        with console.status("Building broker and people-search coverage...", spinner="dots"):
            new_findings = asyncio.run(
                scan_brokers(session, crypto, profile=profile, country=country, depth=depth)
            )
        findings = list_findings(session, profile)
    if json_output:
        console.print_json(
            json.dumps([finding.model_dump(mode="json") for finding in new_findings], default=str)
        )
        return
    console.print(summary_panel(profile, findings))
    console.print(findings_table(new_findings if new_findings else findings))
    console.print(actions_panel(findings))


@scan_app.command("wizard")
def scan_wizard_command(
    profile_slug: Annotated[str | None, typer.Option("--profile", "-p")] = None,
    resume: Annotated[bool, typer.Option("--resume")] = False,
    advanced: Annotated[bool, typer.Option("--advanced")] = False,
) -> None:
    """Guided scan wizard with config readiness and resume support."""
    init_db(_engine())
    crypto = CryptoBox()
    with Session(_engine()) as session:
        if resume:
            saved = latest_resumable_session()
            if not saved:
                console.print("[yellow]No active scan session to resume.[/yellow]")
                return
            profile = _profile_for_session(session, saved)
            modules = [
                module
                for module in saved.requested_modules
                if module not in saved.completed_modules and module not in saved.skipped_modules
            ]
            console.print(f"[green]Resuming scan session[/green] {saved.scan_session_id[:10]}")
            new_findings = _run_scan_modules(session, crypto, profile, saved, modules)
            findings = list_findings(session, profile)
            console.print(summary_panel(profile, findings))
            console.print(findings_table(new_findings if new_findings else findings))
            console.print(actions_panel(findings))
            return
        profile = select_or_create_profile(session, crypto, profile_slug)
        depth = Prompt.ask("Scan depth", choices=["quick", "standard", "deep"], default="quick")
        modules = choose_scan_modules(advanced)
        readiness = readiness_for(modules)
        console.print(readiness_table(readiness))
        modules = handle_missing_config(readiness)
        if profile.id is None:
            raise typer.BadParameter("Profile must be saved before scanning.")
        scan_session = create_session(profile.id, modules, depth)
        new_findings = _run_scan_modules(session, crypto, profile, scan_session, modules)
        findings = list_findings(session, profile)
    console.print(summary_panel(profile, findings))
    console.print(findings_table(new_findings if new_findings else findings))
    console.print(actions_panel(findings))
    console.print(f"[dim]Scan session: {scan_session.scan_session_id[:10]}[/dim]")


@scan_app.command("resume")
def scan_resume_command() -> None:
    """Resume the latest active guided scan session."""
    scan_wizard_command(resume=True)


@scan_app.command("sessions")
def scan_sessions_command() -> None:
    """List local guided scan sessions."""
    console.print(session_table(load_sessions()))


@scan_app.command("cancel")
def scan_cancel_command(session_id: Annotated[str, typer.Argument()]) -> None:
    """Cancel a local guided scan session."""
    if cancel_session(session_id):
        console.print(f"[green]Cancelled scan session[/green] {session_id}")
    else:
        raise typer.BadParameter("Scan session not found.")


@scan_app.command("password")
def scan_password_command(
    password_value: Annotated[
        str | None,
        typer.Option("--password", help="Avoid in shell history; prompt is safer."),
    ] = None,
) -> None:
    """Check a password against HIBP k-anonymity API without storing it."""
    password_value = password_value or Prompt.ask(
        "Password to check locally with HIBP k-anonymity",
        password=True,
    )
    count = asyncio.run(check_pwned_password(password_value))
    if count:
        console.print(
            f"[red]This password hash appears {count:,} time(s) in HIBP data.[/red]\n"
            "Do not reuse it. Change it anywhere it is used and prefer a password manager."
        )
    else:
        console.print(
            "[green]No match returned by the HIBP k-anonymity range API.[/green]\n"
            "This does not prove the password is safe; use a unique generated password."
        )


@scan_app.command("name")
def scan_name_command(
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    depth: Annotated[str, typer.Option("--depth", help="quick, standard, or deep.")] = "quick",
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run identity-query public web discovery for profile names."""
    scan_web_command(
        profile_slug=profile_slug,
        depth=depth,
        query_set="identity",
        provider=None,
        json_output=json_output,
    )


@scan_app.command("domain")
def scan_domain_command(
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    depth: Annotated[str, typer.Option("--depth", help="quick, standard, or deep.")] = "quick",
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run public web discovery for known profile domains."""
    scan_web_command(
        profile_slug=profile_slug,
        depth=depth,
        query_set="identity",
        provider=None,
        json_output=json_output,
    )


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
def config_command(
    action: Annotated[str | None, typer.Argument(help="Use 'set' to update a key.")] = None,
    key: Annotated[
        str | None,
        typer.Argument(help="Config key path, e.g. web_discovery.enabled."),
    ] = None,
    value: Annotated[str | None, typer.Argument(help="Config value.")] = None,
) -> None:
    """Show config paths or set a simple local configuration value."""
    if action == "wizard":
        console.print(config_sections_table())
        for module in ["web", "intel", "tor"]:
            if not readiness_for([module])[0].ready and Confirm.ask(
                f"Configure {MODULE_DEPENDENCIES[module].label} now?",
                default=False,
            ):
                configure_module(module)
        console.print("[green]Config wizard complete.[/green]")
        return
    if action == "check":
        modules = ["username", "social", "phone", "web", "brokers", "intel", "github", "tor"]
        console.print(readiness_table(readiness_for(modules)))
        return
    if action == "explain":
        console.print(config_sections_table())
        return
    if action == "providers":
        console.print(readiness_table(readiness_for(["web", "intel", "github", "tor"])))
        return
    if action == "repair":
        write_default_config(force=False)
        for plugin in ["social_profiles", "data_brokers"]:
            set_plugin_enabled(plugin, True)
        console.print("[green]Config checked. Missing defaults were created if needed.[/green]")
        return
    if action == "set":
        if not key or value is None:
            raise typer.BadParameter("Usage: cleantrace config set <key> <value>")
        path = config_set(key, value)
        console.print(f"[green]Updated config[/green] {key} in {path}")
        return
    if action is not None:
        raise typer.BadParameter("Only 'set' is supported, or run cleantrace config.")
    cfg = load_config()
    console.print_json(
        json.dumps(
            {
                "config": str(config_path()),
                "database": str(cfg.database),
                "user_sites_dir": str(cfg.user_sites_dir),
                "ai_provider": cfg.ai_provider,
                "ollama_url": cfg.ollama_url,
                "ollama_model": cfg.ollama_model,
            }
        )
    )


@plugins_app.command("list")
def plugins_list() -> None:
    """List built-in plugins and their risk labels."""
    states = load_plugin_states()
    table = Table(title="Plugins", box=box.SIMPLE_HEAVY)
    table.add_column("Name", style="bold")
    table.add_column("Inputs")
    table.add_column("Risk")
    table.add_column("API key")
    table.add_column("Enabled")
    table.add_column("Description")
    for meta in built_in_plugin_metadata():
        table.add_row(
            meta.name,
            ", ".join(meta.input_types),
            meta.risk_level,
            "yes" if meta.needs_api_key else "no",
            "yes" if states.get(meta.name, meta.enabled_by_default) else "no",
            meta.description,
        )
    console.print(table)


@plugins_app.command("enable")
def plugins_enable(name: Annotated[str, typer.Argument()]) -> None:
    """Enable a built-in plugin in the local plugin state file."""
    try:
        set_plugin_enabled(name, True)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if name in {"web_discovery", "breach_intel", "tor_public_check"}:
        config_set(f"{name}.enabled", "true")
    if name in {"social_profiles", "data_brokers"}:
        config_set(f"{name}.enabled", "true")
    console.print(f"[green]Enabled plugin[/green] {name}")


@plugins_app.command("disable")
def plugins_disable(name: Annotated[str, typer.Argument()]) -> None:
    """Disable a built-in plugin in the local plugin state file."""
    try:
        set_plugin_enabled(name, False)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if name in {"web_discovery", "breach_intel", "tor_public_check"}:
        config_set(f"{name}.enabled", "false")
    if name in {"social_profiles", "data_brokers"}:
        config_set(f"{name}.enabled", "false")
    console.print(f"[green]Disabled plugin[/green] {name}")


@brokers_app.command("list")
def brokers_list(
    country: Annotated[str | None, typer.Option("--country")] = None,
) -> None:
    """List known data broker and people-search sources."""
    table = Table(title="Data Broker Sources", box=box.SIMPLE_HEAVY)
    table.add_column("Name", style="bold")
    table.add_column("Country")
    table.add_column("Category")
    table.add_column("Risk")
    table.add_column("Manual")
    table.add_column("Opt-out")
    for broker in load_brokers():
        if country and broker.country.upper() not in {country.upper(), "GLOBAL"}:
            continue
        table.add_row(
            broker.name,
            broker.country,
            broker.category,
            broker.risk_level,
            "yes" if broker.manual_only else "no",
            broker.opt_out_url,
        )
    console.print(table)


@brokers_app.command("explain")
def brokers_explain(name: Annotated[str, typer.Argument()]) -> None:
    """Explain one broker source and its removal route."""
    broker = find_broker(name)
    if not broker:
        raise typer.BadParameter(f"Unknown broker. Available: {', '.join(broker_names())}")
    console.print(
        f"[bold]{broker.name}[/bold]\n"
        f"Country: {broker.country}\n"
        f"Category: {broker.category}\n"
        f"Risk: {broker.risk_level}\n"
        f"Opt-out: {broker.opt_out_url}\n"
        f"Required info: {broker.required_evidence or 'varies'}\n"
        f"Expected response: {broker.expected_response_time or 'varies'}\n"
        f"Notes: {broker.notes}\n"
        f"Removal notes: {broker.removal_notes}"
    )


@brokers_app.command("removal-plan")
def brokers_removal_plan_command(
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    country: Annotated[str | None, typer.Option("--country")] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    """Generate a local broker removal plan."""
    init_db(_engine())
    crypto = CryptoBox()
    with Session(_engine()) as session:
        profile = _require_profile(session, profile_slug)
        plan = broker_removal_plan(profile, crypto, country)
    if output:
        output.write_text(plan, encoding="utf-8")
        console.print(f"[green]Broker removal plan written:[/green] {output.resolve()}")
    else:
        console.print(plan)


@removal_app.command("generate")
def removal_generate(
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    finding: Annotated[str | None, typer.Option("--finding")] = None,
    broker: Annotated[str | None, typer.Option("--broker")] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    """Generate a local removal request draft for a finding or broker."""
    if not finding and not broker:
        raise typer.BadParameter("Provide --finding or --broker.")
    init_db(_engine())
    crypto = CryptoBox()
    with Session(_engine()) as session:
        profile = _require_profile(session, profile_slug)
        legal_name = profile.legal_name(crypto)
        recipient = None
        broker_name = None
        finding_id = None
        if finding:
            stored_finding = get_finding(session, finding)
            if not stored_finding or stored_finding.profile_id != profile.id:
                raise typer.BadParameter(f"Finding '{finding}' does not exist for this profile.")
            subject, body = render_finding_request(profile, stored_finding, legal_name)
            finding_id = stored_finding.id
        else:
            broker_record = find_broker(broker or "")
            if not broker_record:
                raise typer.BadParameter(
                    f"Unknown broker. Available brokers: {', '.join(broker_names())}"
                )
            subject, body = render_broker_request(profile, broker_record, legal_name)
            broker_name = broker_record.name
            recipient = broker_record.email or broker_record.opt_out_url
        request = create_removal_request(
            session,
            crypto,
            profile=profile,
            subject=subject,
            body=body,
            finding_id=finding_id,
            broker_name=broker_name,
            recipient=recipient,
        )
    if output:
        output.write_text(body, encoding="utf-8")
        console.print(f"[green]Draft written:[/green] {output.resolve()}")
    console.print(f"[green]Drafted removal request[/green] {request.id[:10]}: {subject}")
    console.print(redact_text(body))


@removal_app.command("track")
def removal_track(
    request_id: Annotated[str | None, typer.Option("--request")] = None,
    finding: Annotated[str | None, typer.Option("--finding")] = None,
    status: Annotated[str, typer.Option("--status")] = "sent",
) -> None:
    """Update a local removal request status."""
    if status not in REMOVAL_STATUSES:
        raise typer.BadParameter(f"Status must be one of: {', '.join(sorted(REMOVAL_STATUSES))}")
    if not request_id and not finding:
        raise typer.BadParameter("Provide --request or --finding.")
    init_db(_engine())
    with Session(_engine()) as session:
        request = get_removal_request(session, request_id) if request_id else None
        if not request and finding:
            request = next(
                (item for item in list_removal_requests(session) if item.finding_id == finding),
                None,
            )
        if not request:
            raise typer.BadParameter("Removal request not found.")
        updated = update_removal_status(session, request, status)
        console.print(f"[green]Updated[/green] {updated.id[:10]} -> {updated.status}")


@removal_app.command("mark")
def removal_mark(
    finding: Annotated[str, typer.Option("--finding")],
    status: Annotated[str, typer.Option("--status")] = "submitted",
) -> None:
    """Mark the removal status for a finding-linked request."""
    removal_track(finding=finding, status=status)


@removal_app.command("plan")
def removal_plan(
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    country: Annotated[str | None, typer.Option("--country")] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    """Generate a broker and finding cleanup plan."""
    brokers_removal_plan_command(profile_slug=profile_slug, country=country, output=output)


@removal_app.command("wizard")
def removal_wizard(
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
) -> None:
    """Walk through high-priority findings and draft removal requests."""
    init_db(_engine())
    with Session(_engine()) as session:
        profile = _require_profile(session, profile_slug)
        findings = sorted(
            list_findings(session, profile),
            key=lambda finding: (finding.severity, finding.confidence),
            reverse=True,
        )
    if not findings:
        console.print("[yellow]No findings yet. Run a scan first.[/yellow]")
        return
    for finding in findings[:10]:
        console.print(f"\n[bold]{finding.id[:10]}[/bold] {finding.title}")
        console.print(f"Severity: {finding.severity}; confidence: {finding.confidence}%")
        if Confirm.ask("Generate removal request for this finding?", default=False):
            removal_generate(profile_slug=profile_slug, finding=finding.id)


@removal_app.command("evidence")
def removal_evidence(
    finding: Annotated[str, typer.Option("--finding")],
    file: Annotated[Path, typer.Option("--file")],
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
) -> None:
    """Attach local evidence metadata to a finding/removal workflow."""
    import_evidence(
        path=file,
        profile_slug=profile_slug,
        status="removal requested",
        attach_finding=finding,
    )


@removal_app.command("followup")
def removal_followup(
    finding: Annotated[str, typer.Option("--finding")],
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    """Generate a local follow-up reminder and optional ICS file."""
    init_db(_engine())
    with Session(_engine()) as session:
        profile = _require_profile(session, profile_slug)
        stored_finding = get_finding(session, finding)
        if not stored_finding or stored_finding.profile_id != profile.id:
            raise typer.BadParameter("Finding not found for this profile.")
    text = (
        "Follow up on CleanTrace removal request\n"
        f"Finding: {stored_finding.id}\n"
        f"Subject: {stored_finding.title}\n"
        "Ask whether the removal, suppression, or correction request has been completed."
    )
    if output:
        output.write_text(text, encoding="utf-8")
        console.print(f"[green]Follow-up reminder written:[/green] {output.resolve()}")
    else:
        console.print(text)


@removal_app.command("list")
def removal_list(
    profile_slug: Annotated[str | None, typer.Option("--profile", "-p")] = None,
    show_sensitive: Annotated[bool, typer.Option("--show-sensitive")] = False,
) -> None:
    """List local removal requests."""
    init_db(_engine())
    crypto = CryptoBox()
    with Session(_engine()) as session:
        profile = get_profile_by_slug(session, profile_slug) if profile_slug else None
        requests = list_removal_requests(session, profile)
        console.print(removal_table(requests))
        if show_sensitive:
            for request in requests:
                console.print(f"\n[bold]{request.id}[/bold] {request.subject}")
                console.print(request.body(crypto))


@link_app.command("github")
def link_github(
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    username: Annotated[str | None, typer.Option("--username")] = None,
    token: Annotated[
        str | None,
        typer.Option("--token", help="GitHub token; prefer gh auth."),
    ] = None,
    from_gh: Annotated[bool, typer.Option("--from-gh/--no-from-gh")] = True,
    private_scan: Annotated[
        bool,
        typer.Option("--private-scan", help="Allow explicit private repo scanning later."),
    ] = False,
) -> None:
    """Link your own GitHub account. Tokens are encrypted locally."""
    init_db(_engine())
    gh_username = None
    gh_token = None
    if from_gh and (not username or not token):
        gh_username, gh_token = _github_from_gh()
    username = username or gh_username
    token = token or gh_token
    if not username:
        username = Prompt.ask("GitHub username")
    if private_scan and not token:
        token = Prompt.ask("GitHub token for private scan opt-in", password=True)
    if private_scan and not Confirm.ask(
        "Private scan can inspect your own private repo metadata and sampled files. Continue?",
        default=False,
    ):
        private_scan = False
    crypto = CryptoBox()
    with Session(_engine()) as session:
        profile = _require_profile(session, profile_slug)
        account = link_account(
            session,
            crypto,
            profile=profile,
            provider="github",
            username=username,
            token=token,
            public_only=not private_scan,
            scopes=["gh-cli"] if token and from_gh else [],
        )
        console.print(
            f"[green]Linked GitHub account[/green] {redact_text(username)} "
            f"for profile [bold]{profile.slug}[/bold] as record {account.id}."
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
def unlink_provider(
    provider: Annotated[str | None, typer.Argument()] = None,
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
) -> None:
    if provider:
        init_db(_engine())
        with Session(_engine()) as session:
            profile = get_profile_by_slug(session, profile_slug)
            if not profile:
                console.print(f"[yellow]No profile found: {profile_slug}[/yellow]")
                return
            removed = unlink_provider_service(session, profile, provider)
        console.print(f"[green]Disconnected {removed} {provider} account(s).[/green]")


@import_app.command("google-takeout")
def import_google_takeout(
    path: Annotated[Path, typer.Argument(help="Path to a Google Takeout .zip archive.")],
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit machine-readable JSON."),
    ] = False,
) -> None:
    """Parse a Google Takeout archive locally and store risk-indicator findings."""
    init_db(_engine())
    with Session(_engine()) as session:
        profile = _require_profile(session, profile_slug)
        if profile.id is None:
            raise typer.BadParameter("Profile must be saved before importing.")
        with console.status("Analysing Google Takeout locally...", spinner="dots"):
            summary = analyse_google_takeout(path, profile.id)
        stored = [upsert_finding(session, profile, finding) for finding in summary.findings]
        session.commit()
        findings = list_findings(session, profile)
        if json_output:
            console.print_json(
                json.dumps(
                    {
                        "archive": str(path),
                        "files_seen": summary.files_seen,
                        "new_findings": len(stored),
                        "findings": [finding.model_dump(mode="json") for finding in stored],
                    },
                    default=str,
                )
            )
            return
        console.print(
            f"[green]Analysed Google Takeout locally.[/green] "
            f"Files seen: {summary.files_seen}; findings stored: {len(stored)}"
        )
        console.print(summary_panel(profile, findings))
        console.print(findings_table(stored if stored else findings))
        console.print(actions_panel(findings))


@import_app.command("evidence")
def import_evidence(
    path: Annotated[Path, typer.Option("--file", help="Evidence file to import locally.")],
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    status: Annotated[
        str,
        typer.Option(
            "--status",
            help="confirmed, false positive, needs review, removal requested, or removed.",
        ),
    ] = "needs review",
    attach_finding: Annotated[str | None, typer.Option("--attach-finding")] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Import user-provided evidence as redacted local metadata only."""
    allowed = {"confirmed", "false positive", "needs review", "removal requested", "removed"}
    if status not in allowed:
        raise typer.BadParameter(f"status must be one of: {', '.join(sorted(allowed))}")
    init_db(_engine())
    crypto = CryptoBox()
    with Session(_engine()) as session:
        profile = _require_profile(session, profile_slug)
        plugin_finding = import_evidence_file(
            profile,
            crypto,
            path,
            status=status,
            attach_finding=attach_finding,
        )
        stored = upsert_finding(session, profile, plugin_finding)
        session.commit()
    if json_output:
        console.print_json(json.dumps(stored.model_dump(mode="json"), default=str))
        return
    if stored.evidence.get("sensitive_values_detected"):
        console.print(
            "[yellow]Sensitive-looking values were detected and redacted. "
            "CleanTrace did not store raw secret values.[/yellow]"
        )
    console.print(f"[green]Imported evidence metadata[/green] {stored.id[:10]} from {path.name}")


@app.command("tui")
def tui_command() -> None:
    """Open the Textual full-screen dashboard."""
    run_tui()


@monitor_app.command("enable")
def monitor_enable(
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
) -> None:
    """Enable local monitoring for a profile."""
    config_set("monitoring.enabled", "true")
    config_set("monitoring.profile", profile_slug)
    console.print(
        "[green]Monitoring enabled locally.[/green]\n"
        "Use cron, Windows Task Scheduler, or systemd user timers to run "
        "`cleantrace monitor run` on your schedule."
    )


@monitor_app.command("disable")
def monitor_disable() -> None:
    """Disable local monitoring."""
    config_set("monitoring.enabled", "false")
    console.print("[green]Monitoring disabled.[/green]")


@monitor_app.command("run")
def monitor_run() -> None:
    """Run local monitoring diff against current stored findings."""
    profile_slug = str(config_get("monitoring.profile", "default") or "default")
    init_db(_engine())
    with Session(_engine()) as session:
        profile = _require_profile(session, profile_slug)
        findings = list_findings(session, profile)
    diff = update_monitor_snapshot(profile_slug, findings)
    changed = [finding for finding in findings if finding.id in set(diff.new + diff.changed)]
    summary = alert_summary(changed)
    console.print(
        f"New: {len(diff.new)} | Removed: {len(diff.removed)} | "
        f"Changed: {len(diff.changed)} | Reappeared: {len(diff.reappeared)}"
    )
    if summary:
        console.print(summary)


@monitor_app.command("status")
def monitor_status() -> None:
    """Show local monitoring status."""
    console.print_json(
        json.dumps(
            {
                "enabled": config_get("monitoring.enabled", False),
                "profile": config_get("monitoring.profile", ""),
                "state": load_monitor_state(),
            },
            default=str,
        )
    )


@monitor_app.command("changes")
def monitor_changes() -> None:
    """Show last local monitoring change summary."""
    state = load_monitor_state()
    profiles = state.get("profiles", {}) if isinstance(state, dict) else {}
    console.print_json(json.dumps(profiles, default=str))


async def _run_ai_command(
    profile_slug: str,
    kind: str,
    finding_id: str | None,
    model: str | None,
) -> str:
    cfg = load_config()
    if cfg.ai_provider == "none":
        raise AIUnavailableError(
            "AI provider is disabled. Set ai.provider = \"ollama\" in config.toml."
        )
    with Session(_engine()) as session:
        profile = _require_profile(session, profile_slug)
        findings = list_findings(session, profile)
        removals = list_removal_requests(session, profile)
    context = build_findings_context(profile, findings, removals)
    if kind == "summarise":
        prompt = summarise_prompt(context)
    elif kind == "actions":
        prompt = actions_prompt(context)
    else:
        prompt = removal_email_prompt(context, finding_id)
    return await ollama_generate(cfg, prompt, model=model)


@ai_app.command("summarise")
def ai_summarise(
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    model: Annotated[str | None, typer.Option("--model")] = None,
) -> None:
    """Summarise stored findings with local Ollama. Personal data is redacted first."""
    try:
        response = asyncio.run(_run_ai_command(profile_slug, "summarise", None, model))
    except AIUnavailableError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(response)


@ai_app.command("actions")
def ai_actions(
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    model: Annotated[str | None, typer.Option("--model")] = None,
) -> None:
    """Generate a prioritized action list with local Ollama."""
    try:
        response = asyncio.run(_run_ai_command(profile_slug, "actions", None, model))
    except AIUnavailableError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(response)


@ai_app.command("removal-email")
def ai_removal_email(
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    finding: Annotated[str | None, typer.Option("--finding")] = None,
    model: Annotated[str | None, typer.Option("--model")] = None,
) -> None:
    """Draft a removal email with local Ollama from redacted local context."""
    try:
        response = asyncio.run(_run_ai_command(profile_slug, "removal-email", finding, model))
    except AIUnavailableError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(response)


@ai_app.command("explain-finding")
def ai_explain_finding(
    finding_id: Annotated[str, typer.Argument()],
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    model: Annotated[str | None, typer.Option("--model")] = None,
) -> None:
    """Explain one finding with optional local AI."""
    try:
        response = asyncio.run(_run_ai_command(profile_slug, "summarise", finding_id, model))
    except AIUnavailableError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(response)


@ai_app.command("cleanup-plan")
def ai_cleanup_plan(
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    model: Annotated[str | None, typer.Option("--model")] = None,
) -> None:
    """Suggest a cleanup plan with optional local AI."""
    ai_actions(profile_slug=profile_slug, model=model)


@ai_app.command("removal-draft")
def ai_removal_draft(
    finding: Annotated[str, typer.Option("--finding")],
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    model: Annotated[str | None, typer.Option("--model")] = None,
) -> None:
    """Draft a removal message with optional local AI."""
    ai_removal_email(profile_slug=profile_slug, finding=finding, model=model)


@ai_app.command("summarise-report")
def ai_summarise_report(
    profile_slug: Annotated[str, typer.Option("--profile", "-p")] = "default",
    model: Annotated[str | None, typer.Option("--model")] = None,
) -> None:
    """Summarise report context with optional local AI."""
    ai_summarise(profile_slug=profile_slug, model=model)


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

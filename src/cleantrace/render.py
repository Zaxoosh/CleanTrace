from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cleantrace.constants import SEVERITY_COLOURS
from cleantrace.models import Finding, Profile
from cleantrace.scoring import exposure_score, score_band, top_actions

console = Console()


def banner() -> Panel:
    text = Text()
    text.append("CleanTrace\n", style="bold cyan")
    text.append(
        "Find public exposure, understand risk, generate removal requests, and track cleanup.",
        style="white",
    )
    return Panel(text, title="Local-first privacy self-assessment", border_style="cyan")


def acceptable_use_panel() -> Panel:
    return Panel(
        "[bold]Acceptable use[/bold]\n"
        "CleanTrace is for your own accounts and identifiers, or for people who have given you "
        "clear permission. It does not delete you from the internet, bypass access controls, "
        "attempt logins, spam password reset endpoints, scrape leaked databases, or upload your "
        "data to a cloud service.",
        title="Ethical Guardrails",
        border_style="yellow",
    )


def profile_table(rows: list[dict[str, object]]) -> Table:
    table = Table(title="Consent Profiles", box=box.SIMPLE_HEAVY)
    table.add_column("Slug", style="bold")
    table.add_column("Risk")
    table.add_column("Consent")
    table.add_column("Usernames")
    table.add_column("Emails")
    for row in rows:
        table.add_row(
            str(row["slug"]),
            str(row["risk_sensitivity"]),
            "yes" if row["consent"] else "no",
            ", ".join(row["usernames"]),  # type: ignore[arg-type]
            ", ".join(row["emails"]),  # type: ignore[arg-type]
        )
    return table


def findings_table(findings: list[Finding]) -> Table:
    table = Table(title="Findings", box=box.SIMPLE_HEAVY)
    table.add_column("ID", style="dim", no_wrap=True)
    table.add_column("Severity")
    table.add_column("Confidence", justify="right")
    table.add_column("Title")
    table.add_column("URL")
    for finding in findings:
        colour = SEVERITY_COLOURS.get(finding.severity, "white")
        table.add_row(
            finding.id[:10],
            f"[{colour}]{finding.severity.upper()}[/{colour}]",
            f"{finding.confidence}%",
            finding.title,
            finding.url or "",
        )
    return table


def summary_panel(profile: Profile, findings: list[Finding]) -> Panel:
    score = exposure_score(findings, profile)
    label, colour = score_band(score)
    high_count = sum(1 for f in findings if f.severity in {"high", "critical"})
    body = (
        f"[bold]Profile:[/bold] {profile.slug}\n"
        f"[bold]Findings:[/bold] {len(findings)} total, {high_count} high or critical\n"
        f"[bold]Exposure score:[/bold] [{colour}]{score}/100 ({label})[/{colour}]"
    )
    return Panel(body, title="Summary", border_style=colour)


def actions_panel(findings: list[Finding]) -> Panel:
    actions = "\n".join(
        f"{idx}. {action}" for idx, action in enumerate(top_actions(findings), start=1)
    )
    return Panel(actions, title="Top 5 actions to reduce exposure", border_style="green")

from __future__ import annotations

from sqlmodel import Session, select
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, Static

from cleantrace.db import get_engine, init_db, list_findings
from cleantrace.models import Finding, Profile, RemovalRequest
from cleantrace.plugins.breach_intel.providers import provider_statuses as intel_provider_statuses
from cleantrace.plugins.web_discovery.providers import provider_statuses as web_provider_statuses
from cleantrace.scoring import exposure_score, score_band
from cleantrace.services import list_removal_requests


class CleanTraceTui(App[None]):
    CSS = """
    Screen {
        layout: vertical;
    }
    #summary {
        height: 5;
        padding: 1 2;
        background: $surface;
        border: solid $accent;
    }
    Horizontal {
        height: 1fr;
    }
    DataTable {
        width: 1fr;
        height: 1fr;
    }
    """
    BINDINGS = [("q", "quit", "Quit"), ("r", "refresh", "Refresh")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("Loading CleanTrace dashboard...", id="summary")
        with Horizontal():
            with Vertical():
                yield DataTable(id="profiles")
                yield DataTable(id="removals")
                yield DataTable(id="providers")
            yield DataTable(id="findings")
        yield Footer()

    def on_mount(self) -> None:
        self.refresh_data()

    def action_refresh(self) -> None:
        self.refresh_data()

    def refresh_data(self) -> None:
        engine = get_engine()
        init_db(engine)
        with Session(engine) as session:
            profiles = list(session.exec(select(Profile)).all())
            findings = list_findings(session)
            removals = list_removal_requests(session)
        self._render_summary(profiles, findings, len(removals))
        self._render_profiles(profiles, findings)
        self._render_findings(findings)
        self._render_removals(removals)
        self._render_providers()

    def _render_summary(
        self,
        profiles: list[Profile],
        findings: list[Finding],
        removal_count: int,
    ) -> None:
        score = exposure_score(findings)
        band, _ = score_band(score)
        self.query_one("#summary", Static).update(
            f"Profiles: {len(profiles)} | Findings: {len(findings)} | "
            f"Removal requests: {removal_count} | Exposure score: {score}/100 ({band})"
        )

    def _render_profiles(self, profiles: list[Profile], findings: list[Finding]) -> None:
        table = self.query_one("#profiles", DataTable)
        table.clear(columns=True)
        table.add_columns("Profile", "Risk", "Findings", "Consent")
        for profile in profiles:
            count = sum(1 for finding in findings if finding.profile_id == profile.id)
            table.add_row(profile.slug, profile.risk_sensitivity, str(count), str(profile.consent))

    def _render_findings(self, findings: list[Finding]) -> None:
        table = self.query_one("#findings", DataTable)
        table.clear(columns=True)
        table.add_columns("Severity", "Confidence", "Title", "Source", "Review")
        for finding in sorted(findings, key=lambda item: item.last_seen, reverse=True)[:100]:
            review = "yes" if {"needs_manual_review", "needs-review"} & set(finding.tags) else ""
            table.add_row(
                finding.severity,
                f"{finding.confidence}%",
                finding.title,
                finding.source_plugin,
                review,
            )

    def _render_removals(self, removals: list[RemovalRequest]) -> None:
        table = self.query_one("#removals", DataTable)
        table.clear(columns=True)
        table.add_columns("Status", "Subject")
        for removal in removals[:100]:
            table.add_row(removal.status, removal.subject)

    def _render_providers(self) -> None:
        table = self.query_one("#providers", DataTable)
        table.clear(columns=True)
        table.add_columns("Provider", "Module", "Enabled")
        for status in web_provider_statuses():
            table.add_row(status["name"], "Web Discovery", "yes" if status["enabled"] else "no")
        for status in intel_provider_statuses():
            enabled = "yes" if status["enabled"] and status["has_api_key"] else "no"
            table.add_row(status["name"], "Breach Intel", enabled)
        table.add_row("tor_public_check", "Tor URL Check", "config/plugin gated")
        table.add_row("manual_evidence", "Manual Evidence", "local")


def run_tui() -> None:
    CleanTraceTui().run()

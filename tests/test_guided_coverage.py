from pathlib import Path

import yaml

from cleantrace.alerts import alert_summary
from cleantrace.models import Finding, build_profile
from cleantrace.monitoring import diff_snapshots
from cleantrace.plugins.data_brokers.service import broker_removal_plan, brokers_for
from cleantrace.plugins.social_profiles.service import (
    classify_social_response,
    load_social_sites,
)
from cleantrace.readiness import config_sections, module_readiness
from cleantrace.reports import render_markdown
from cleantrace.scan_sessions import (
    cancel_session,
    create_session,
    latest_resumable_session,
    load_sessions,
)
from cleantrace.security import CryptoBox, derive_test_key


def test_config_explanation_sections_are_plain_english() -> None:
    sections = config_sections()

    assert any(section["name"] == "Web discovery providers" for section in sections)
    assert any(section["name"] == "Monitoring settings" for section in sections)
    assert all("privacy" in section for section in sections)


def test_missing_web_config_readiness(monkeypatch) -> None:
    def fake_config_get(path: str, default=None):
        values = {
            "web_discovery.enabled": True,
            "web_discovery.default_provider": "brave",
            "web_discovery.providers.brave.enabled": True,
            "web_discovery.providers.brave.api_key": "",
        }
        return values.get(path, default)

    monkeypatch.setattr("cleantrace.readiness.config_get", fake_config_get)

    readiness = module_readiness("web")

    assert not readiness.ready
    assert "web_discovery.providers.brave.api_key" in readiness.missing_config_keys


def test_scan_session_persistence_and_cancel(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "sessions.json"
    monkeypatch.setattr("cleantrace.scan_sessions.scan_sessions_path", lambda: target)

    session = create_session(1, ["social", "brokers"], "quick")

    assert latest_resumable_session() is not None
    assert load_sessions()[0].resume_token == session.resume_token
    assert cancel_session(session.scan_session_id[:8])
    assert load_sessions()[0].status == "cancelled"


def test_social_site_yaml_validation_and_url_generation() -> None:
    sites = load_social_sites()

    assert len(sites) >= 20
    github = next(site for site in sites if site.name == "GitHub")
    assert github.profile_url("alice") == "https://github.com/alice"
    assert github.enabled_by_default


def test_social_false_positive_handling() -> None:
    site = next(site for site in load_social_sites() if site.name == "GitHub")

    confidence, severity, tags = classify_social_response(site, 404, "not found")

    assert confidence < 50
    assert severity == "info"
    assert "possible_false_positive" in tags


def test_data_broker_yaml_validation_and_manual_behaviour() -> None:
    data = yaml.safe_load(Path("src/cleantrace/data/data_brokers.yaml").read_text())

    assert len(data) >= 15
    assert all("manual_only" in item for item in data)
    assert any(item["name"] == "192.com" and item["supports_uk_gdpr"] for item in data)
    assert brokers_for("GB", "quick")


def test_broker_removal_plan_generation() -> None:
    crypto = CryptoBox(derive_test_key())
    profile = build_profile(
        slug="default",
        crypto=crypto,
        legal_name="Alice Example",
        display_names=[],
        usernames=[],
        emails=[],
        phones=[],
        location="London",
        domains=[],
        social_links=[],
        role_notes=None,
        risk_sensitivity="normal",
        consent=True,
    )

    plan = broker_removal_plan(profile, crypto, "GB")

    assert "Broker Removal Plan" in plan
    assert "192.com" in plan


def test_monitoring_diff_logic() -> None:
    previous = {"one": {"severity": "low", "confidence": 50, "false_positive": False}}
    current = {
        "one": {"severity": "high", "confidence": 80, "false_positive": False},
        "two": {"severity": "low", "confidence": 50, "false_positive": False},
    }

    diff = diff_snapshots(previous, current)

    assert diff.new == ["two"]
    assert diff.changed == ["one"]


def test_alert_redaction(monkeypatch) -> None:
    monkeypatch.setattr(
        "cleantrace.alerts.config_get",
        lambda path, default=None: path == "alerts.enabled",
    )
    finding = Finding(
        profile_id=1,
        source_plugin="manual",
        input_type="email",
        input_value_hash="hash",
        title="alice@example.com appeared",
        description="desc",
        confidence=80,
        severity="medium",
        remediation="Review.",
    )

    summary = alert_summary([finding])

    assert summary is not None
    assert "alice@example.com" not in summary
    assert "[redacted-email]" in summary


def test_report_includes_setup_coverage_and_graph() -> None:
    crypto = CryptoBox(derive_test_key())
    profile = build_profile(
        slug="default",
        crypto=crypto,
        legal_name="Alice Example",
        display_names=[],
        usernames=["alice"],
        emails=[],
        phones=[],
        location=None,
        domains=[],
        social_links=[],
        role_notes=None,
        risk_sensitivity="protected-role",
        consent=True,
    )
    finding = Finding(
        profile_id=1,
        source_plugin="social_profiles",
        input_type="username",
        input_value_hash="hash",
        title="GitHub public profile lead",
        description="desc",
        url="https://github.com/alice",
        confidence=82,
        severity="medium",
        remediation="Review.",
        evidence_json='{"username": "al***e", "site": "GitHub", "identity_linking_risk": true}',
        tags_json='["social-profile", "identity-link"]',
    )

    report = render_markdown(profile, [finding])

    assert "Setup Status" in report
    assert "Scan Coverage" in report
    assert "Identity-Link Graph" in report
    assert "Social Profile Findings" in report

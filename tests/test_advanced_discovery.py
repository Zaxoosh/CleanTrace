from pathlib import Path

import pytest

from cleantrace.evidence import import_evidence_file
from cleantrace.models import Finding, Profile, build_profile
from cleantrace.phone import parse_phone_number, phone_search_variants, resolve_region
from cleantrace.plugins.base import ScanTarget
from cleantrace.plugins.breach_intel.providers import provider_settings
from cleantrace.plugins.breach_intel.providers.base import BreachMetadata, metadata_to_finding
from cleantrace.plugins.tor_public_check.service import (
    DOWNLOAD_EXTENSIONS,
    check_one_tor_url,
    is_onion_url,
    looks_unsafe,
)
from cleantrace.plugins.web_discovery.classifier import classify_web_result
from cleantrace.plugins.web_discovery.models import WebResult
from cleantrace.plugins.web_discovery.query import generate_queries
from cleantrace.plugins.web_discovery.urltools import canonical_url
from cleantrace.reports import render_markdown
from cleantrace.scoring import finding_points
from cleantrace.security import CryptoBox, derive_test_key


def make_profile() -> tuple[Profile, CryptoBox]:
    crypto = CryptoBox(derive_test_key())
    profile = build_profile(
        slug="default",
        crypto=crypto,
        legal_name="Alice Example",
        display_names=["Alice E"],
        usernames=["alicehandle"],
        emails=["alice@example.com"],
        phones=["07700 900123"],
        location="London",
        domains=["example.com"],
        social_links=["https://github.com/alicehandle"],
        role_notes="journalist",
        risk_sensitivity="protected-role",
        consent=True,
    )
    profile.id = 1
    return profile, crypto


@pytest.mark.parametrize(
    ("country", "number", "region"),
    [
        ("GB", "07700 900123", "GB"),
        ("US", "(415) 555-2671", "US"),
        ("DE", "030 123456", "DE"),
        ("FR", "01 42 68 53 00", "FR"),
        ("ES", "91 123 45 67", "ES"),
        ("AU", "02 9374 4000", "AU"),
        ("CA", "416 555 0199", "CA"),
    ],
)
def test_phone_parsing_regions(country: str, number: str, region: str) -> None:
    parsed = parse_phone_number(number, country)

    assert parsed.e164.startswith("+")
    assert parsed.region_code == region
    assert parsed.country_calling_code > 0
    assert phone_search_variants(parsed)


def test_country_selector_accepts_name_iso_and_dial_code() -> None:
    assert resolve_region("United Kingdom") == "GB"
    assert resolve_region("us") == "US"
    assert resolve_region("+49") == "DE"


def test_web_query_generation_and_url_deduplication() -> None:
    profile, crypto = make_profile()
    queries = generate_queries(profile, crypto, query_set="all", depth="standard")
    query_text = {query.query for query in queries}

    assert '"Alice Example" "London"' in query_text
    assert '"alice@example.com"' in query_text
    assert 'site:reddit.com "alicehandle"' in query_text
    assert canonical_url("HTTPS://Example.com/a/?utm_source=x&b=1#frag") == (
        "https://example.com/a?b=1"
    )


def test_web_result_classification_and_redaction() -> None:
    result = WebResult(
        title="Alice Example profile",
        url="https://192.com/example?utm_campaign=x",
        snippet="Alice Example in London",
        provider="searxng",
        query='"Alice Example" "London"',
        query_set="identity",
    )

    classified = classify_web_result(result, ["Alice Example", "London"])

    assert classified.classification == "data_broker"
    assert classified.severity in {"medium", "high"}
    assert classified.canonical_url == "https://192.com/example"
    assert "Al***e" in classified.matched_identifiers


def test_breach_intel_metadata_only_finding() -> None:
    target = ScanTarget(profile_id=1, input_type="email", value="a@example.com", value_hash="hash")
    finding = metadata_to_finding(
        target,
        BreachMetadata(
            provider="ProviderName",
            source_name="Example breach",
            data_classes=["Email addresses", "Passwords"],
            verified=True,
        ),
    )

    assert finding.source_plugin == "breach_intel"
    assert finding.evidence["metadata_only"] is True
    assert "Passwords" in finding.evidence["data_classes"]
    assert "a@example.com" not in str(finding.evidence)
    assert finding.severity == "high"


def test_provider_disabled_by_default() -> None:
    settings = provider_settings("leakcheck")

    assert settings.enabled is False
    assert settings.terms_accepted is False


@pytest.mark.asyncio
async def test_tor_module_refuses_non_onion_and_downloads() -> None:
    assert not is_onion_url("https://example.com")
    assert ".sql" in DOWNLOAD_EXTENSIONS

    finding = await check_one_tor_url(
        "https://example.com",
        ["alice@example.com"],
        "socks5://127.0.0.1:9050",
        0.1,
    )

    assert finding.title == "Tor URL rejected"
    assert "no-crawl" in finding.tags


def test_tor_unsafe_page_detection() -> None:
    assert looks_unsafe("credential dump marketplace")


def test_manual_evidence_redaction(tmp_path: Path) -> None:
    profile, crypto = make_profile()
    evidence_path = tmp_path / "evidence.txt"
    evidence_path.write_text(
        "Alice Example alice@example.com password=SuperSecret123 token=abcdefghi",
        encoding="utf-8",
    )

    finding = import_evidence_file(profile, crypto, evidence_path)

    assert finding.evidence["sensitive_values_detected"] is True
    assert finding.evidence["raw_sensitive_values_stored"] is False
    assert "SuperSecret123" not in str(finding.evidence)
    assert "[redacted-email]" in str(finding.evidence)


def test_protected_role_scoring_and_report_sections() -> None:
    profile, _ = make_profile()
    finding = Finding(
        profile_id=1,
        source_plugin="web_discovery",
        input_type="web_query",
        input_value_hash="hash",
        title="Name and location match",
        description="desc",
        url="https://example.com",
        confidence=90,
        severity="medium",
        remediation="Remove it.",
        tags_json='["location", "real-name", "web_discovery", "needs_manual_review"]',
    )

    assert finding_points(finding, profile) > finding_points(finding, None)
    report = render_markdown(profile, [finding])
    assert "Public Web Discovery" in report
    assert "Manual Review Queue" in report
    assert "This is a lead, not proof." in report

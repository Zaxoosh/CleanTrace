from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import yaml

from cleantrace.models import Finding, Profile

REMOVAL_STATUSES = {
    "not started",
    "not_started",
    "drafted",
    "sent",
    "submitted",
    "waiting",
    "removed",
    "refused",
    "needs manual action",
    "needs_manual_action",
    "reappeared",
    "followup_due",
}


@dataclass(frozen=True)
class Broker:
    name: str
    country: str
    opt_out_url: str
    category: str = "data broker"
    region: str = ""
    homepage_url: str = ""
    search_url_template: str = ""
    privacy_url: str | None = None
    email: str | None = None
    removal_method: str = "manual"
    required_evidence: str = ""
    expected_response_time: str = ""
    supports_gdpr: bool = False
    supports_uk_gdpr: bool = False
    supports_ccpa: bool = False
    requires_id_document: bool = False
    manual_only: bool = True
    enabled_by_default: bool = True
    check_method: str = "manual_guidance"
    risk_level: str = "medium"
    notes: str = ""
    risk_notes: str = ""
    removal_notes: str = ""


BROKERS = [
    Broker(
        name="192.com",
        country="UK",
        opt_out_url="https://www.192.com/misc/privacy-policy/",
        email="privacy@192.com",
        required_evidence="Profile URL, name, and address details to remove.",
        expected_response_time="Usually within one calendar month under UK GDPR.",
        notes="People-search and directory listing removal may require manual verification.",
    ),
    Broker(
        name="PeopleLooker",
        country="US",
        opt_out_url="https://www.peoplelooker.com/f/optout/search",
        email=None,
        required_evidence="Listing URL and matching personal details.",
        expected_response_time="Varies by broker.",
        notes="Included as a common opt-out target for non-UK exposure.",
    ),
    Broker(
        name="FastPeopleSearch",
        country="US",
        opt_out_url="https://www.fastpeoplesearch.com/removal",
        email=None,
        required_evidence="Listing URL and email verification.",
        expected_response_time="Several days after verification.",
        notes="Manual browser opt-out is usually required.",
    ),
]


def broker_names() -> list[str]:
    return [broker.name for broker in load_brokers()]


def find_broker(name: str) -> Broker | None:
    needle = name.strip().lower()
    return next((broker for broker in load_brokers() if broker.name.lower() == needle), None)


def load_brokers() -> list[Broker]:
    data_file = Path(__file__).parent / "data" / "data_brokers.yaml"
    if not data_file.exists():
        return BROKERS
    try:
        payload = yaml.safe_load(data_file.read_text(encoding="utf-8")) or []
    except yaml.YAMLError:
        return BROKERS
    brokers: list[Broker] = []
    for item in payload:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        brokers.append(
            Broker(
                name=str(item["name"]),
                country=str(item.get("country") or ""),
                region=str(item.get("region") or ""),
                category=str(item.get("category") or "data broker"),
                homepage_url=str(item.get("homepage_url") or ""),
                search_url_template=str(item.get("search_url_template") or ""),
                opt_out_url=str(item.get("opt_out_url") or ""),
                privacy_url=str(item.get("privacy_url") or "") or None,
                email=str(item.get("contact_email") or "") or None,
                removal_method=str(item.get("removal_method") or "manual"),
                required_evidence=", ".join(str(v) for v in item.get("required_info", []))
                if isinstance(item.get("required_info"), list)
                else str(item.get("required_info") or ""),
                expected_response_time=f"{item.get('expected_response_days', '')} days".strip(),
                supports_gdpr=bool(item.get("supports_gdpr", False)),
                supports_uk_gdpr=bool(item.get("supports_uk_gdpr", False)),
                supports_ccpa=bool(item.get("supports_ccpa", False)),
                requires_id_document=bool(item.get("requires_id_document", False)),
                manual_only=bool(item.get("manual_only", True)),
                enabled_by_default=bool(item.get("enabled_by_default", True)),
                check_method=str(item.get("check_method") or "manual_guidance"),
                risk_level=str(item.get("risk_level") or "medium"),
                notes=str(item.get("notes") or ""),
                risk_notes=str(item.get("risk_notes") or ""),
                removal_notes=str(item.get("removal_notes") or ""),
            )
        )
    return brokers or BROKERS


def render_finding_request(
    profile: Profile,
    finding: Finding,
    legal_name: str | None,
) -> tuple[str, str]:
    subject = f"Removal request for public exposure: {finding.title}"
    body = f"""To whom it may concern,

I am requesting removal, erasure, or correction of personal information associated with me.

Name: {legal_name or profile.slug}
Finding reference: {finding.id}
Source: {finding.source_plugin}
URL: {finding.url or "Not available"}

The information appears to expose or connect personal identifiers in a way I no longer want
to be public. Please remove the content, de-index the profile, anonymise the account, or tell
me the correct process for completing this request.

Please confirm receipt and provide the expected response timeline. If you require additional
identity verification, please request the minimum necessary information.

Generated locally by CleanTrace on {datetime.now(UTC).date().isoformat()}.
"""
    return subject, body


def render_broker_request(
    profile: Profile,
    broker: Broker,
    legal_name: str | None,
) -> tuple[str, str]:
    subject = f"Data broker opt-out request: {broker.name}"
    body = f"""To the {broker.name} privacy team,

I am requesting removal of personal data associated with me from your service.

Name: {legal_name or profile.slug}
Opt-out URL: {broker.opt_out_url}
Relevant rights: UK GDPR / GDPR right to erasure or applicable privacy opt-out rights.

Please remove matching listings and suppress republication where possible. If you require
evidence, please request only the minimum information necessary to identify the listing.

Expected evidence noted by CleanTrace: {broker.required_evidence}
Expected response time: {broker.expected_response_time}

Please confirm receipt and completion status.

Generated locally by CleanTrace on {datetime.now(UTC).date().isoformat()}.
"""
    return subject, body


def breach_response_checklist() -> str:
    return """Breach response checklist:
1. Change the password for the affected service.
2. Change reused passwords anywhere else.
3. Enable MFA on important accounts.
4. Review recovery emails, phone numbers, and sessions.
5. Watch for phishing that references the breached service.
"""

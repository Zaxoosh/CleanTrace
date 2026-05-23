from __future__ import annotations

from cleantrace.models import Profile
from cleantrace.plugins.base import PluginFinding
from cleantrace.plugins.web_discovery.service import discover_public_web
from cleantrace.removal import Broker, load_brokers
from cleantrace.security import CryptoBox, stable_hash


def brokers_for(country: str | None, depth: str) -> list[Broker]:
    brokers = load_brokers()
    if country:
        wanted = country.upper()
        brokers = [
            broker
            for broker in brokers
            if broker.country.upper() in {wanted, "GLOBAL"}
            or broker.country.upper().startswith(wanted)
        ]
    limits = {"quick": 8, "standard": 25, "deep": 80}
    return brokers[: limits.get(depth, 8)]


async def scan_data_brokers(
    profile: Profile,
    crypto: CryptoBox,
    *,
    country: str | None = None,
    depth: str = "quick",
) -> list[PluginFinding]:
    findings: list[PluginFinding] = []
    legal_name = profile.legal_name(crypto) or profile.slug
    location = profile.public_dict(crypto, show_sensitive=True).get("location") or ""
    brokers = brokers_for(country, depth)
    for broker in brokers:
        findings.append(broker_guidance_finding(profile, broker, legal_name, str(location)))
    web_findings = await discover_public_web(
        profile,
        crypto,
        depth=depth,
        query_set="identity",
    )
    for finding in web_findings:
        if "data_broker" in finding.tags:
            findings.append(finding)
    return findings


def broker_guidance_finding(
    profile: Profile,
    broker: Broker,
    legal_name: str,
    location: str,
) -> PluginFinding:
    query = f'{broker.name} "{legal_name}" "{location}"'.strip()
    severity = "medium" if broker.risk_notes else "low"
    return PluginFinding(
        source_plugin="data_brokers",
        input_type="broker_guidance",
        input_value_hash=stable_hash(f"{profile.slug}:{broker.name}"),
        title=f"Broker removal guidance: {broker.name}",
        description=(
            "CleanTrace prepared a broker/manual-check lead. It does not bypass CAPTCHA, "
            "login walls, anti-bot controls, or submit opt-out forms automatically."
        ),
        url=broker.opt_out_url or broker.privacy_url,
        evidence={
            "broker": broker.name,
            "country": broker.country,
            "category": broker.category,
            "check_method": "manual_guidance",
            "search_query": query,
            "required_info": broker.required_evidence,
            "expected_response_time": broker.expected_response_time,
            "requires_id_document": getattr(broker, "requires_id_document", False),
            "manual_only": broker.manual_only,
            "removal_url": broker.opt_out_url,
        },
        confidence=55,
        severity=severity,
        remediation=f"Review {broker.name}, then use the opt-out URL and track removal status.",
        tags=["data_broker", "broker-guidance", "manual_check_required"],
    )


def broker_removal_plan(profile: Profile, crypto: CryptoBox, country: str | None = None) -> str:
    legal_name = profile.legal_name(crypto) or profile.slug
    lines = [
        f"# Broker Removal Plan: {profile.slug}",
        "",
        f"Subject: {legal_name}",
        "",
    ]
    for broker in brokers_for(country, "deep"):
        lines.extend(
            [
                f"## {broker.name}",
                f"- Country: {broker.country}",
                f"- Category: {broker.category}",
                f"- Removal URL: {broker.opt_out_url or 'manual guidance'}",
                f"- Required info: {broker.required_evidence or 'varies'}",
                f"- Expected response: {broker.expected_response_time or 'varies'}",
                f"- Notes: {broker.notes}",
                "",
            ]
        )
    return "\n".join(lines)

from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlmodel import Session, select

from cleantrace.config import get_api_key
from cleantrace.models import Finding, LinkedAccount, Profile, RemovalRequest, build_profile
from cleantrace.phone import dump_phone_metadata, parse_phone_number, phone_search_variants
from cleantrace.plugin_state import plugin_enabled
from cleantrace.plugins.base import PluginFinding, ScanTarget
from cleantrace.plugins.breach_intel import scan_breach_intel as run_breach_intel
from cleantrace.plugins.github import GitHubConnectorPlugin
from cleantrace.plugins.hibp import HIBPEmailPlugin
from cleantrace.plugins.manager import plugins_for_input
from cleantrace.plugins.web_discovery.service import discover_public_web
from cleantrace.security import CryptoBox, stable_hash


def create_profile(
    session: Session,
    crypto: CryptoBox,
    *,
    slug: str,
    legal_name: str | None,
    display_names: list[str],
    usernames: list[str],
    emails: list[str],
    phones: list[str],
    location: str | None,
    domains: list[str],
    social_links: list[str],
    role_notes: str | None,
    risk_sensitivity: str,
    consent: bool,
) -> Profile:
    profile = build_profile(
        slug=slug,
        crypto=crypto,
        legal_name=legal_name,
        display_names=display_names,
        usernames=usernames,
        emails=emails,
        phones=phones,
        location=location,
        domains=domains,
        social_links=social_links,
        role_notes=role_notes,
        risk_sensitivity=risk_sensitivity,
        consent=consent,
    )
    session.add(profile)
    session.commit()
    session.refresh(profile)
    return profile


async def scan_username(
    session: Session,
    *,
    profile: Profile,
    username: str,
    depth: str,
) -> list[Finding]:
    if profile.id is None:
        raise ValueError("Profile must be persisted before scanning.")
    target = ScanTarget(
        profile_id=profile.id,
        input_type="username",
        value=username,
        value_hash=stable_hash(username),
        depth=depth,
    )
    stored: list[Finding] = []
    for plugin in plugins_for_input("username"):
        if not plugin_enabled(plugin.meta.name):
            continue
        for plugin_finding in await plugin.run(target):
            stored.append(upsert_finding(session, profile, plugin_finding))
    session.commit()
    return stored


async def scan_email(
    session: Session,
    *,
    profile: Profile,
    email: str,
    depth: str,
    api_key: str | None = None,
) -> list[Finding]:
    if profile.id is None:
        raise ValueError("Profile must be persisted before scanning.")
    key = api_key or get_api_key("hibp")
    if not key or not plugin_enabled("hibp_email"):
        return []
    target = ScanTarget(
        profile_id=profile.id,
        input_type="email",
        value=email,
        value_hash=stable_hash(email),
        depth=depth,
    )
    plugin = HIBPEmailPlugin(key)
    stored = [upsert_finding(session, profile, finding) for finding in await plugin.run(target)]
    session.commit()
    return stored


async def scan_github_linked(
    session: Session,
    crypto: CryptoBox,
    *,
    profile: Profile,
    include_private: bool = False,
) -> list[Finding]:
    if profile.id is None:
        raise ValueError("Profile must be persisted before scanning.")
    accounts = list_linked_accounts(session, profile, provider="github")
    stored: list[Finding] = []
    if not plugin_enabled("github_connector"):
        return stored
    plugin = GitHubConnectorPlugin()
    seen_accounts: set[str] = set()
    for account in accounts:
        if account.account_id_hash in seen_accounts:
            continue
        seen_accounts.add(account.account_id_hash)
        username = account.username(crypto)
        if not username:
            continue
        token = account.token(crypto)
        target = ScanTarget(
            profile_id=profile.id,
            input_type="github_account",
            value=username,
            value_hash=stable_hash(username),
            options={
                "username": username,
                "token": token,
                "include_private": include_private and not account.public_only,
            },
        )
        for plugin_finding in await plugin.run(target):
            stored.append(upsert_finding(session, profile, plugin_finding))
        account.last_scanned_at = datetime.now(UTC)
        session.add(account)
    session.commit()
    return stored


def add_profile_phone(
    session: Session,
    crypto: CryptoBox,
    *,
    profile: Profile,
    phone: str,
    country: str | None = None,
) -> Profile:
    metadata = profile.phone_metadata(crypto)
    parsed = parse_phone_number(phone, country)
    by_e164 = {item.e164: item for item in metadata}
    by_e164[parsed.e164] = parsed
    ordered = list(by_e164.values())
    profile.phones_enc = crypto.encrypt_text(dump_phone_metadata(ordered)) or ""
    profile.phone_hashes_json = json.dumps([stable_hash(item.e164) for item in ordered])
    session.add(profile)
    session.commit()
    session.refresh(profile)
    return profile


def remove_profile_phone(
    session: Session,
    crypto: CryptoBox,
    *,
    profile: Profile,
    value: str,
) -> int:
    metadata = profile.phone_metadata(crypto)
    normalised = None
    try:
        normalised = parse_phone_number(value).e164
    except ValueError:
        normalised = value.strip()
    kept = [
        item
        for item in metadata
        if item.e164 != normalised and item.national_format != normalised
    ]
    removed = len(metadata) - len(kept)
    if removed:
        profile.phones_enc = crypto.encrypt_text(dump_phone_metadata(kept)) or ""
        profile.phone_hashes_json = json.dumps([stable_hash(item.e164) for item in kept])
        session.add(profile)
        session.commit()
        session.refresh(profile)
    return removed


def scan_phone_profile(
    session: Session,
    crypto: CryptoBox,
    *,
    profile: Profile,
    value: str | None = None,
    country: str | None = None,
) -> list[Finding]:
    if profile.id is None:
        raise ValueError("Profile must be persisted before scanning.")
    numbers = [parse_phone_number(value, country)] if value else profile.phone_metadata(crypto)
    stored: list[Finding] = []
    for number in numbers:
        variants = phone_search_variants(number)
        finding = PluginFinding(
            source_plugin="phone_exposure",
            input_type="phone",
            input_value_hash=stable_hash(number.e164),
            title="Phone number normalised for exposure review",
            description=(
                "CleanTrace validated the phone number locally and generated public-web "
                "search variants. It did not send SMS, place calls, or perform active "
                "phone verification."
            ),
            url=None,
            evidence={
                "e164_hash": stable_hash(number.e164),
                "national_format": number.national_format,
                "international_format": number.international_format,
                "region_code": number.region_code,
                "country_calling_code": number.country_calling_code,
                "is_valid": number.is_valid,
                "search_variants": variants,
            },
            confidence=100 if number.is_valid else 45,
            severity="low" if number.is_valid else "info",
            remediation=(
                "Use public web discovery for these variants and remove unnecessary phone exposure."
            ),
            tags=["phone", "phone-exposure", "public-web-lead"],
        )
        stored.append(upsert_finding(session, profile, finding))
    session.commit()
    return stored


async def scan_web_discovery(
    session: Session,
    crypto: CryptoBox,
    *,
    profile: Profile,
    depth: str = "quick",
    query_set: str = "identity",
    provider_name: str | None = None,
) -> list[Finding]:
    if profile.id is None:
        raise ValueError("Profile must be persisted before scanning.")
    if not plugin_enabled("web_discovery"):
        return []
    findings = await discover_public_web(
        profile,
        crypto,
        depth=depth,
        query_set=query_set,
        provider_name=provider_name,
    )
    stored = [upsert_finding(session, profile, finding) for finding in findings]
    session.commit()
    return stored


async def scan_intel(
    session: Session,
    crypto: CryptoBox,
    *,
    profile: Profile,
    provider: str | None = None,
    depth: str = "quick",
) -> list[Finding]:
    if profile.id is None:
        raise ValueError("Profile must be persisted before scanning.")
    if not plugin_enabled("breach_intel"):
        return []
    findings = await run_breach_intel(profile, crypto, provider=provider, depth=depth)
    stored = [upsert_finding(session, profile, finding) for finding in findings]
    session.commit()
    return stored


def link_account(
    session: Session,
    crypto: CryptoBox,
    *,
    profile: Profile,
    provider: str,
    username: str,
    token: str | None = None,
    display_name: str | None = None,
    public_only: bool = True,
    scopes: list[str] | None = None,
) -> LinkedAccount:
    if profile.id is None:
        raise ValueError("Profile id is required.")
    existing = session.exec(
        select(LinkedAccount).where(
            LinkedAccount.profile_id == profile.id,
            LinkedAccount.provider == provider,
            LinkedAccount.account_id_hash == stable_hash(username),
        )
    ).first()
    if existing:
        existing.username_enc = crypto.encrypt_text(username)
        existing.display_name_enc = crypto.encrypt_text(display_name or username)
        existing.token_enc = crypto.encrypt_text(token)
        existing.public_only = public_only
        existing.scopes_json = json.dumps(scopes or [])
        session.add(existing)
        session.commit()
        session.refresh(existing)
        return existing
    account = LinkedAccount(
        profile_id=profile.id,
        provider=provider,
        account_id_hash=stable_hash(username),
        display_name_enc=crypto.encrypt_text(display_name or username),
        username_enc=crypto.encrypt_text(username),
        token_enc=crypto.encrypt_text(token),
        public_only=public_only,
        scopes_json=json.dumps(scopes or []),
    )
    session.add(account)
    session.commit()
    session.refresh(account)
    return account


def list_linked_accounts(
    session: Session,
    profile: Profile,
    provider: str | None = None,
) -> list[LinkedAccount]:
    if profile.id is None:
        return []
    statement = select(LinkedAccount).where(LinkedAccount.profile_id == profile.id)
    if provider:
        statement = statement.where(LinkedAccount.provider == provider)
    return list(session.exec(statement).all())


def unlink_provider(session: Session, profile: Profile, provider: str) -> int:
    removed = 0
    for account in list_linked_accounts(session, profile, provider=provider):
        session.delete(account)
        removed += 1
    session.commit()
    return removed


def create_removal_request(
    session: Session,
    crypto: CryptoBox,
    *,
    profile: Profile,
    subject: str,
    body: str,
    finding_id: str | None = None,
    broker_name: str | None = None,
    recipient: str | None = None,
    request_type: str = "erasure",
) -> RemovalRequest:
    if profile.id is None:
        raise ValueError("Profile id is required.")
    request = RemovalRequest(
        profile_id=profile.id,
        finding_id=finding_id,
        broker_name=broker_name,
        request_type=request_type,
        recipient=recipient,
        subject=subject,
        body_enc=crypto.encrypt_text(body) or "",
    )
    session.add(request)
    session.commit()
    session.refresh(request)
    return request


def list_removal_requests(session: Session, profile: Profile | None = None) -> list[RemovalRequest]:
    statement = select(RemovalRequest)
    if profile and profile.id is not None:
        statement = statement.where(RemovalRequest.profile_id == profile.id)
    return list(session.exec(statement).all())


def update_removal_status(session: Session, request: RemovalRequest, status: str) -> RemovalRequest:
    request.status = status
    request.updated_at = datetime.now(UTC)
    session.add(request)
    session.commit()
    session.refresh(request)
    return request


def get_finding(session: Session, finding_id: str) -> Finding | None:
    return session.get(Finding, finding_id)


def get_removal_request(session: Session, request_id: str) -> RemovalRequest | None:
    return session.get(RemovalRequest, request_id)


def upsert_finding(session: Session, profile: Profile, plugin_finding: PluginFinding) -> Finding:
    if profile.id is None:
        raise ValueError("Profile id is required.")
    existing = session.exec(
        select(Finding).where(
            Finding.profile_id == profile.id,
            Finding.source_plugin == plugin_finding.source_plugin,
            Finding.input_type == plugin_finding.input_type,
            Finding.input_value_hash == plugin_finding.input_value_hash,
            Finding.title == plugin_finding.title,
            Finding.url == plugin_finding.url,
        )
    ).first()
    now = datetime.now(UTC)
    if existing:
        existing.title = plugin_finding.title
        existing.description = plugin_finding.description
        existing.evidence_json = json.dumps(plugin_finding.evidence, sort_keys=True)
        existing.confidence = plugin_finding.confidence
        existing.severity = plugin_finding.severity
        existing.last_seen = now
        existing.remediation = plugin_finding.remediation
        existing.tags_json = json.dumps(plugin_finding.tags, sort_keys=True)
        session.add(existing)
        return existing
    finding = Finding(
        profile_id=profile.id,
        source_plugin=plugin_finding.source_plugin,
        input_type=plugin_finding.input_type,
        input_value_hash=plugin_finding.input_value_hash,
        title=plugin_finding.title,
        description=plugin_finding.description,
        url=plugin_finding.url,
        evidence_json=json.dumps(plugin_finding.evidence, sort_keys=True),
        confidence=plugin_finding.confidence,
        severity=plugin_finding.severity,
        remediation=plugin_finding.remediation,
        tags_json=json.dumps(plugin_finding.tags, sort_keys=True),
    )
    session.add(finding)
    session.flush()
    return finding

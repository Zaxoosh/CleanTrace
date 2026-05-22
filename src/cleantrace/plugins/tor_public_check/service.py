from __future__ import annotations

import re
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx

from cleantrace.config import config_get
from cleantrace.models import Profile
from cleantrace.plugins.base import PluginFinding
from cleantrace.security import CryptoBox, redact_text, stable_hash

UNSAFE_TERMS = {
    "marketplace",
    "stolen",
    "credential dump",
    "password dump",
    "fullz",
    "carding",
    "csam",
    "child sexual abuse",
    "weapons",
    "drugs",
    "exploit shop",
    "logs for sale",
}
DOWNLOAD_EXTENSIONS = (".zip", ".rar", ".7z", ".tar", ".gz", ".sql", ".db", ".dump")


def is_onion_url(url: str) -> bool:
    parsed = urlsplit(url)
    return (
        parsed.scheme in {"http", "https"}
        and parsed.hostname is not None
        and parsed.hostname.endswith(".onion")
    )


def looks_unsafe(text: str) -> bool:
    lowered = text.lower()
    return any(term in lowered for term in UNSAFE_TERMS)


def extract_title(html: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:160]


def matched_snippets(text: str, identifiers: list[str]) -> list[str]:
    snippets: list[str] = []
    lowered = text.lower()
    for identifier in identifiers:
        if not identifier:
            continue
        index = lowered.find(identifier.lower())
        if index == -1:
            continue
        start = max(0, index - 80)
        end = min(len(text), index + len(identifier) + 80)
        snippets.append(redact_text(re.sub(r"\s+", " ", text[start:end]).strip())[:220])
    return snippets[:5]


def profile_identifiers(profile: Profile, crypto: CryptoBox) -> list[str]:
    values = [
        profile.legal_name(crypto) or "",
        *profile.usernames(crypto),
        *profile.emails(crypto),
        *profile.phones(crypto),
    ]
    return [value for value in values if value]


async def check_tor_urls(
    profile: Profile,
    crypto: CryptoBox,
    urls: list[str],
) -> list[PluginFinding]:
    if not bool(config_get("tor_public_check.enabled", False)):
        return []
    max_urls = int(config_get("tor_public_check.max_urls_per_scan", 10))
    proxy = str(config_get("tor_public_check.socks_proxy", "socks5://127.0.0.1:9050"))
    timeout = float(config_get("tor_public_check.timeout_seconds", 20))
    identifiers = profile_identifiers(profile, crypto)
    findings: list[PluginFinding] = []
    for url in urls[:max_urls]:
        findings.append(await check_one_tor_url(url, identifiers, proxy, timeout))
    return findings


async def check_one_tor_url(
    url: str,
    identifiers: list[str],
    proxy: str,
    timeout: float,
) -> PluginFinding:
    url_hash = stable_hash(url)
    tags = ["tor-public-url", "no-crawl"]
    if not is_onion_url(url):
        return tor_status_finding(
            url_hash,
            "Tor URL rejected",
            "Only explicit http(s) .onion URLs are accepted.",
        )
    if urlsplit(url).path.lower().endswith(DOWNLOAD_EXTENSIONS):
        return tor_status_finding(
            url_hash,
            "Tor URL rejected",
            "CleanTrace does not download files from onion URLs.",
        )
    if looks_unsafe(url):
        return unsafe_tor_finding(url_hash, url)
    try:
        async with httpx.AsyncClient(
            proxy=proxy,
            timeout=timeout,
            follow_redirects=False,
        ) as client:
            response = await client.get(url)
    except httpx.HTTPError as exc:
        return tor_status_finding(url_hash, "Tor URL unreachable", str(exc)[:160])
    content_type = response.headers.get("content-type", "")
    if "text/html" not in content_type and "text/plain" not in content_type:
        return tor_status_finding(
            url_hash,
            "Tor URL skipped",
            "CleanTrace only inspects public text or HTML pages.",
        )
    text = response.text[:200_000]
    title = extract_title(text)
    if looks_unsafe(f"{url} {title} {text[:4000]}"):
        return unsafe_tor_finding(url_hash, url)
    snippets = matched_snippets(text, identifiers)
    severity = "medium" if snippets else "info"
    confidence = 80 if snippets else 30
    if snippets:
        tags.append("tor_public_identifier_match")
    else:
        tags.append("tor_needs_manual_review")
    return PluginFinding(
        source_plugin="tor_public_check",
        input_type="tor_url",
        input_value_hash=url_hash,
        title="Tor public URL identifier match" if snippets else "Tor public URL checked",
        description=(
            "CleanTrace inspected only the explicit user-provided public onion URL. "
            "It did not follow links, download files, log in, or store raw page content."
        ),
        url=None,
        evidence={
            "url_hash": url_hash,
            "http_status": response.status_code,
            "page_title": redact_text(title),
            "snippets": snippets,
            "checked_at": datetime.now(UTC).isoformat(),
            "stored_raw_page_content": False,
        },
        confidence=confidence,
        severity=severity,
        remediation="Manually review the page and avoid accessing unsafe or illegal content.",
        tags=tags,
    )


def tor_status_finding(url_hash: str, title: str, detail: str) -> PluginFinding:
    return PluginFinding(
        source_plugin="tor_public_check",
        input_type="tor_url",
        input_value_hash=url_hash,
        title=title,
        description=detail,
        url=None,
        evidence={"url_hash": url_hash, "detail": detail, "stored_raw_page_content": False},
        confidence=100,
        severity="info",
        remediation="Check the URL and local Tor SOCKS proxy configuration before retrying.",
        tags=["tor-public-url", "no-crawl", "tor_url_unreachable"],
    )


def unsafe_tor_finding(url_hash: str, url: str) -> PluginFinding:
    return PluginFinding(
        source_plugin="tor_public_check",
        input_type="tor_url",
        input_value_hash=url_hash,
        title="Tor URL appears unsafe; content not processed",
        description="URL appears to be unsafe or illegal. CleanTrace did not process content.",
        url=None,
        evidence={
            "url_hash": url_hash,
            "url_was_onion": is_onion_url(url),
            "stored_raw_page_content": False,
        },
        confidence=90,
        severity="high",
        remediation=(
            "Do not use CleanTrace to access illegal marketplaces, stolen-data forums, "
            "or illegal content."
        ),
        tags=["tor-public-url", "tor_possible_sensitive_source", "no-content-stored"],
    )

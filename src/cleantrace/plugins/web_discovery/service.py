from __future__ import annotations

import asyncio

from cleantrace.config import config_get
from cleantrace.models import Profile
from cleantrace.plugins.base import PluginFinding
from cleantrace.plugins.web_discovery.classifier import classify_web_result
from cleantrace.plugins.web_discovery.providers import get_provider
from cleantrace.plugins.web_discovery.query import generate_queries
from cleantrace.plugins.web_discovery.urltools import canonical_url
from cleantrace.security import CryptoBox, stable_hash


def max_results_for_depth(depth: str) -> int:
    fallback = {"quick": 10, "standard": 30}.get(depth, 75)
    return int(config_get(f"web_discovery.max_results_{depth}", fallback))


async def discover_public_web(
    profile: Profile,
    crypto: CryptoBox,
    *,
    depth: str = "quick",
    query_set: str = "identity",
    provider_name: str | None = None,
) -> list[PluginFinding]:
    if not bool(config_get("web_discovery.enabled", False)):
        return []
    provider = get_provider(provider_name)
    queries = generate_queries(profile, crypto, query_set=query_set, depth=depth)
    max_results = max_results_for_depth(depth)
    per_query = max(1, min(10, max_results))
    raw_results = []
    delay = float(config_get("web_discovery.request_delay_seconds", 2))
    for query in queries:
        raw_results.extend(await provider.search(query, per_query))
        if delay:
            await asyncio.sleep(min(delay, 5))
        if len(raw_results) >= max_results:
            break
    seen: set[str] = set()
    findings: list[PluginFinding] = []
    for result in raw_results:
        canonical = canonical_url(result.url)
        if canonical in seen:
            continue
        seen.add(canonical)
        identifiers = next(
            (query.identifiers for query in queries if query.query == result.query),
            [],
        )
        classified = classify_web_result(result, identifiers)
        findings.append(
            PluginFinding(
                source_plugin="web_discovery",
                input_type="web_query",
                input_value_hash=stable_hash(result.query),
                title=f"Public web lead: {result.title[:80]}",
                description=(
                    "A configured search provider returned a public web result that may contain "
                    "one or more profile identifiers. This is a lead, not proof."
                ),
                url=classified.canonical_url,
                evidence={
                    "provider": result.provider,
                    "query_hash": stable_hash(result.query),
                    "query_set": result.query_set,
                    "snippet": result.snippet[:300],
                    "matched_identifiers": classified.matched_identifiers,
                    "classification": classified.classification,
                },
                confidence=classified.confidence,
                severity=classified.severity,
                remediation=classified.remediation,
                tags=classified.tags,
            )
        )
        if len(findings) >= max_results:
            break
    return findings

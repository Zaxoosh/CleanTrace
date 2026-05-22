from __future__ import annotations

from cleantrace.config import config_get
from cleantrace.models import Profile
from cleantrace.plugins.base import PluginFinding, ScanTarget
from cleantrace.plugins.breach_intel.providers import get_intel_provider
from cleantrace.security import CryptoBox, stable_hash


async def scan_breach_intel(
    profile: Profile,
    crypto: CryptoBox,
    *,
    provider: str | None = None,
    depth: str = "quick",
) -> list[PluginFinding]:
    if not bool(config_get("breach_intel.enabled", False)):
        return []
    providers = [provider] if provider else ["hibp", "leakcheck", "dehashed", "intelx"]
    findings: list[PluginFinding] = []
    for email in profile.emails(crypto):
        target = ScanTarget(
            profile_id=profile.id or 0,
            input_type="email",
            value=email,
            value_hash=stable_hash(email),
            depth=depth,
        )
        for name in providers:
            findings.extend(await get_intel_provider(name).query(target))
    return findings

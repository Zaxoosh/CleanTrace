from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class PluginMeta:
    name: str
    description: str
    input_types: list[str]
    risk_level: str = "safe"
    needs_api_key: bool = False
    uses_scraping: bool = False
    enabled_by_default: bool = True
    rate_limit_per_minute: int = 60
    tags: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class PluginFinding:
    source_plugin: str
    input_type: str
    input_value_hash: str
    title: str
    description: str
    url: str | None
    evidence: dict[str, object]
    confidence: int
    severity: str
    remediation: str
    tags: list[str]


@dataclass(frozen=True)
class ScanTarget:
    profile_id: int
    input_type: str
    value: str
    value_hash: str
    depth: str = "quick"
    options: dict[str, object] = field(default_factory=dict)


class CleanTracePlugin(Protocol):
    meta: PluginMeta

    async def run(self, target: ScanTarget) -> list[PluginFinding]:
        ...

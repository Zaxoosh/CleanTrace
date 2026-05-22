from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SearchQuery:
    query: str
    query_set: str
    identifiers: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class WebResult:
    title: str
    url: str
    snippet: str
    provider: str
    query: str
    query_set: str


@dataclass(frozen=True)
class ClassifiedWebResult:
    result: WebResult
    canonical_url: str
    matched_identifiers: list[str]
    classification: str
    confidence: int
    severity: str
    tags: list[str]
    remediation: str

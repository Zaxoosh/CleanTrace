from __future__ import annotations

from dataclasses import dataclass

from cleantrace.plugins.web_discovery.models import SearchQuery, WebResult


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    enabled: bool
    api_key: str | None = None
    base_url: str | None = None
    search_engine_id: str | None = None


class SearchProvider:
    name = "base"

    def __init__(self, config: ProviderConfig) -> None:
        self.config = config

    async def search(self, query: SearchQuery, limit: int) -> list[WebResult]:
        raise NotImplementedError

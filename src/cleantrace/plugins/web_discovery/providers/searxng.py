from __future__ import annotations

import httpx

from cleantrace.plugins.web_discovery.models import SearchQuery, WebResult
from cleantrace.plugins.web_discovery.providers.base import ProviderConfig, SearchProvider


class SearXNGProvider(SearchProvider):
    name = "searxng"

    def __init__(self, config: ProviderConfig, timeout: float = 15.0) -> None:
        super().__init__(config)
        self.timeout = timeout

    async def search(self, query: SearchQuery, limit: int) -> list[WebResult]:
        if not self.config.enabled or not self.config.base_url:
            return []
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(
                self.config.base_url.rstrip("/") + "/search",
                params={"q": query.query, "format": "json", "language": "en"},
            )
        response.raise_for_status()
        payload = response.json()
        results = []
        for item in payload.get("results", [])[:limit]:
            results.append(
                WebResult(
                    title=str(item.get("title") or item.get("url") or "Untitled result"),
                    url=str(item.get("url") or ""),
                    snippet=str(item.get("content") or ""),
                    provider=self.name,
                    query=query.query,
                    query_set=query.query_set,
                )
            )
        return [result for result in results if result.url]

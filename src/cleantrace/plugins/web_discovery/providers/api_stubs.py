from __future__ import annotations

import httpx

from cleantrace.plugins.web_discovery.models import SearchQuery, WebResult
from cleantrace.plugins.web_discovery.providers.base import SearchProvider


class BraveProvider(SearchProvider):
    name = "brave"

    async def search(self, query: SearchQuery, limit: int) -> list[WebResult]:
        if not self.config.enabled or not self.config.api_key:
            return []
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                "https://api.search.brave.com/res/v1/web/search",
                params={"q": query.query, "count": limit},
                headers={"X-Subscription-Token": self.config.api_key},
            )
        response.raise_for_status()
        items = response.json().get("web", {}).get("results", [])
        return [
            WebResult(
                title=str(item.get("title") or "Untitled result"),
                url=str(item.get("url") or ""),
                snippet=str(item.get("description") or ""),
                provider=self.name,
                query=query.query,
                query_set=query.query_set,
            )
            for item in items[:limit]
            if item.get("url")
        ]


class BingProvider(SearchProvider):
    name = "bing"

    async def search(self, query: SearchQuery, limit: int) -> list[WebResult]:
        if not self.config.enabled or not self.config.api_key:
            return []
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                "https://api.bing.microsoft.com/v7.0/search",
                params={"q": query.query, "count": limit},
                headers={"Ocp-Apim-Subscription-Key": self.config.api_key},
            )
        response.raise_for_status()
        items = response.json().get("webPages", {}).get("value", [])
        return [
            WebResult(
                title=str(item.get("name") or "Untitled result"),
                url=str(item.get("url") or ""),
                snippet=str(item.get("snippet") or ""),
                provider=self.name,
                query=query.query,
                query_set=query.query_set,
            )
            for item in items[:limit]
            if item.get("url")
        ]


class GoogleCSEProvider(SearchProvider):
    name = "google_cse"

    async def search(self, query: SearchQuery, limit: int) -> list[WebResult]:
        if not self.config.enabled or not self.config.api_key or not self.config.search_engine_id:
            return []
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                "https://www.googleapis.com/customsearch/v1",
                params={
                    "q": query.query,
                    "key": self.config.api_key,
                    "cx": self.config.search_engine_id,
                    "num": min(limit, 10),
                },
            )
        response.raise_for_status()
        items = response.json().get("items", [])
        return [
            WebResult(
                title=str(item.get("title") or "Untitled result"),
                url=str(item.get("link") or ""),
                snippet=str(item.get("snippet") or ""),
                provider=self.name,
                query=query.query,
                query_set=query.query_set,
            )
            for item in items[:limit]
            if item.get("link")
        ]


class SerpAPIProvider(SearchProvider):
    name = "serpapi"

    async def search(self, query: SearchQuery, limit: int) -> list[WebResult]:
        if not self.config.enabled or not self.config.api_key:
            return []
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                "https://serpapi.com/search.json",
                params={"q": query.query, "api_key": self.config.api_key, "num": limit},
            )
        response.raise_for_status()
        items = response.json().get("organic_results", [])
        return [
            WebResult(
                title=str(item.get("title") or "Untitled result"),
                url=str(item.get("link") or ""),
                snippet=str(item.get("snippet") or ""),
                provider=self.name,
                query=query.query,
                query_set=query.query_set,
            )
            for item in items[:limit]
            if item.get("link")
        ]

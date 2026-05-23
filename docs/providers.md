# Providers

Third-party providers are disabled by default unless you explicitly configure them.

## Public Web Discovery

Recommended local-friendly option:

- SearXNG self-hosted instance

API-backed options:

- Brave Search API
- Bing Web Search API
- Google Custom Search
- SerpAPI

Provider queries may contain identifiers from your consent profile. Use `cleantrace config check`
before scanning to see readiness and privacy impact.

## Breach Intelligence

CleanTrace stores metadata only:

- provider name
- source/breach name
- breach date where available
- exposed data classes where available
- severity and remediation

It does not store leaked records, passwords, hashes, private keys, tokens, or raw provider responses.

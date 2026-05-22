# Privacy

CleanTrace is local-first by default.

## Data Storage

- Raw profile identifiers are encrypted locally.
- Phone numbers are encrypted locally. CleanTrace stores normalised phone metadata only for local
  matching and reporting.
- Findings store hashed scanned identifiers and public evidence metadata.
- Linked account tokens are encrypted locally and can be removed with `cleantrace unlink`.
- No telemetry is sent.
- No cloud backend is used.
- API keys and OAuth tokens are not printed.

## Redaction

Terminal output redacts emails, phones, tokens, and sensitive values by default. Users can opt into full local display with `--show-sensitive` on supported commands.

## Network Requests

Username scanning makes direct HTTP requests to public profile URLs listed in the local site definition database.

HIBP checks use the official Have I Been Pwned API only when an API key is configured. GitHub checks use official GitHub APIs for accounts you explicitly link. CleanTrace does not upload repository contents; public repository files sampled for secret-pattern checks are fetched from GitHub and scanned locally.

Google Takeout imports are parsed from a local ZIP archive only. CleanTrace stores findings derived from risk indicators, not the full Takeout archive.

Public Web Discovery sends generated search queries to the search provider you explicitly enable,
such as SearXNG, Brave, Bing, Google Custom Search, or SerpAPI. Disable it with:

```powershell
cleantrace plugins disable web_discovery
```

Breach & Dark Web Intelligence sends identifiers only to providers you explicitly enable and
configure. CleanTrace stores breach/source name, breach date where available, data classes, provider,
severity, and remediation. It does not store leaked records, passwords, password hashes, tokens,
private keys, or full provider responses.

Disable it with:

```powershell
cleantrace plugins disable breach_intel
```

Tor public URL checks use your local SOCKS proxy and only inspect explicit `.onion` URLs you provide.
They do not crawl, follow links, download files, log in, or store raw page content by default.

Manual evidence import is local-only. Text is redacted before being stored as metadata. Screenshots
are recorded as file metadata only; image analysis is not performed.

## Never Stored

CleanTrace should not store:

- plaintext passwords
- password hashes from leaked datasets
- session tokens
- private keys
- browser cookies
- raw leaked database rows
- full provider raw responses
- raw Tor page content by default

## Wiping Local Data

Delete the SQLite database:

```powershell
cleantrace wipe
```

For a full local reset, also remove the config, key, plugin state, and any reports/evidence files you
created manually.

## AI

AI is disabled by default. CleanTrace supports local Ollama when `ai.provider = "ollama"` is
configured. CleanTrace redacts sensitive values before prompts. Prefer local AI; do not enable any
cloud-compatible provider unless you understand what identifiers may leave the machine.

# Privacy

CleanTrace is local-first by default.

## Data Storage

- Raw profile identifiers are encrypted locally.
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

## AI

AI is disabled by default. Future AI features will prefer local Ollama. Cloud AI providers will require explicit opt-in and redaction by default.

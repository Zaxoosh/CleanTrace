# Privacy

CleanTrace is local-first by default.

## Data Storage

- Raw profile identifiers are encrypted locally.
- Findings store hashed scanned identifiers and public evidence metadata.
- No telemetry is sent.
- No cloud backend is used.
- API keys and OAuth tokens are not printed.

## Redaction

Terminal output redacts emails, phones, tokens, and sensitive values by default. Users can opt into full local display with `--show-sensitive` on supported commands.

## Network Requests

Milestone 1 username scanning makes direct HTTP requests to public profile URLs listed in the local site definition database. Future API-based modules will be optional and disabled unless configured.

## AI

AI is disabled by default. Future AI features will prefer local Ollama. Cloud AI providers will require explicit opt-in and redaction by default.

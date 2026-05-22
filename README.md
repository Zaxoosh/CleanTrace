# CleanTrace

CleanTrace helps you find public exposure, understand risk, generate removal requests, and track cleanup.

It is an open-source, local-first CLI privacy exposure and OSINT self-assessment tool. The current milestone supports explicit consent profiles, encrypted local storage, username discovery, official HIBP email checks when configured, a GitHub connector, local Google Takeout import, a Textual dashboard, local Ollama assistant commands, removal request drafts, stored findings, and Markdown/HTML reports.

## What CleanTrace Does

- Creates local consent profiles for your own identifiers.
- Stores raw profile identifiers encrypted on your machine.
- Checks public username profile URLs using local YAML site definitions.
- Checks email breach exposure with the official Have I Been Pwned API when you provide an API key.
- Checks a password against HIBP Pwned Passwords using k-anonymity without storing it.
- Links your own GitHub account using official GitHub APIs and encrypted local token storage.
- Flags public GitHub profile exposure, linked sites, sensitive config filenames, and safe regex-based secret leads in public repositories.
- Imports Google Takeout ZIP archives locally and flags location history, photo metadata, profile metadata, and shared-link indicators.
- Generates local removal request drafts and tracks cleanup status.
- Opens a local Textual dashboard with profiles, findings, and removal status.
- Uses local Ollama for optional summaries/actions only when explicitly configured.
- Records findings with source, confidence, timestamp, severity, evidence, and remediation advice.
- Produces terminal summaries and Markdown/HTML reports.
- Ends scans with the top five actions to reduce exposure.

## What It Does Not Do

- It does not claim to delete you from the internet.
- It does not search arbitrary targets without a consent profile.
- It does not scrape leaked databases or store raw breach records.
- It does not store passwords or attempt logins.
- It does not steal browser cookies, bypass CAPTCHAs, or spam password reset endpoints.
- It does not upload findings, profile data, API keys, or tokens to a cloud backend.

## Install

```bash
python -m pip install -e ".[dev]"
```

CleanTrace requires Python 3.12 or newer.

## Quick Start

```bash
cleantrace init
cleantrace profile create --wizard
cleantrace scan all --profile default --depth quick
cleantrace findings --profile default
cleantrace link github
cleantrace scan github --profile default
cleantrace removal generate --finding FINDING_ID
cleantrace removal track --request REQUEST_ID --status sent
cleantrace import google-takeout ./takeout.zip --profile default
cleantrace tui
cleantrace report --profile default --format markdown --output cleantrace-report.md
cleantrace report --profile default --format html --output cleantrace-report.html
```

Non-interactive example:

```bash
cleantrace init --yes
cleantrace profile create --slug default --username yourhandle --email you@example.com --consent
cleantrace scan username yourhandle --profile default --depth quick
```

## HIBP Setup

CleanTrace only uses the official Have I Been Pwned API. Set the key in either place:

```bash
set CLEANTRACE_HIBP_API_KEY=your_key_here
```

or in `~/.config/cleantrace/config.toml`:

```toml
[api_keys]
hibp = "your_key_here"
```

Then run:

```bash
cleantrace scan email you@example.com --profile default --hibp
cleantrace scan password
```

CleanTrace stores breach summaries only. It does not store leaked records or passwords. The password check sends only the first five characters of a SHA-1 hash to the HIBP range API.

## GitHub Connector

Link your own GitHub account:

```bash
cleantrace link github --profile default
cleantrace scan github --profile default
```

By default, `link github` tries to reuse the local GitHub CLI authentication token. You can also link public-only by username:

```bash
cleantrace link github --profile default --username yourhandle --no-from-gh
```

Private repository scanning is off by default and requires explicit `--private-scan` opt-in.

## Google Takeout Import

Takeout import is local-only:

```bash
cleantrace import google-takeout ./takeout.zip --profile default
```

CleanTrace does not upload the archive. It looks for risk indicators such as location history files, Google Photos metadata with geolocation-like fields, profile metadata, and Drive/shared-link metadata.

## Textual TUI

```bash
cleantrace tui
```

The dashboard shows profiles, findings, exposure score, and removal request status. Press `r` to refresh and `q` to quit.

## Local AI

AI is disabled by default. To use local Ollama, set:

```toml
[ai]
provider = "ollama"
ollama_url = "http://localhost:11434"
ollama_model = "llama3.1"
```

Then run:

```bash
cleantrace ai summarise --profile default
cleantrace ai actions --profile default
cleantrace ai removal-email --profile default --finding FINDING_ID
```

CleanTrace redacts sensitive values before building prompts. OpenAI-compatible/cloud AI is not implemented in Milestone 3.

## Example Output

Example terminal captures are stored under `docs/screenshots/`.

![CleanTrace Milestone 1 terminal output](docs/screenshots/milestone1-summary.svg)

## Privacy Model

CleanTrace is local-first:

- Config: `~/.config/cleantrace/config.toml`
- Data: `~/.local/share/cleantrace/`
- Database: `~/.local/share/cleantrace/cleantrace.db`
- Encryption key: `~/.local/share/cleantrace/cleantrace.key`
- User site definitions: `~/.config/cleantrace/sites.d/`

Raw profile identifiers are encrypted with Fernet. Findings store searchable hashes for scanned identifiers and avoid storing raw passwords or leaked records. Terminal output redacts sensitive values by default; use `--show-sensitive` only for local review.

## Threat Model

CleanTrace is designed to reduce accidental public exposure for a consenting user. It is not designed to protect against a compromised local machine, malicious plugins, or a hostile operator. Treat the local database and encryption key as sensitive files. Do not install untrusted plugins.

## Plugin System

Built-in scanner modules live under `src/cleantrace/plugins/`. A plugin declares:

- name and description
- supported input types
- risk label
- API key requirement
- scraping flag
- default enabled state
- rate limit guidance
- async `run()` method
- confidence and remediation output

Username discovery uses local YAML site definitions with this shape:

```yaml
name:
url:
check_url:
username_claimed_regex:
username_unclaimed_regex:
expected_status:
tags:
country:
enabled_by_default:
confidence_rules:
notes:
```

## API Keys

Milestone 2 supports optional HIBP checks using the official API when a key is configured in `~/.config/cleantrace/config.toml` or `CLEANTRACE_HIBP_API_KEY`.

## Reports

Reports currently support:

- terminal summary
- Markdown
- HTML

Planned formats include JSON export expansion, CSV, and optional PDF.

## Roadmap

Completed Milestone 1:

- `init`
- `profile create/list/show`
- username scan for initial public sites
- `findings`
- Markdown/HTML report
- local SQLite database
- Rich terminal UI

Completed Milestone 2:

- HIBP integration
- GitHub connector
- removal templates and tracker
- improved risk scoring for breach, credential, and identity-link findings

Future Milestone 2.x:

- safer phone/domain/name modules via configured APIs

Completed Milestone 3:

- Textual TUI
- Google Takeout import
- local plugin enable/disable state
- local Ollama summariser

Future:

- broader third-party plugin marketplace
- safer phone/domain/name modules via configured APIs
- richer report exports and screenshots

## Legal and Ethical Disclaimer

Use CleanTrace only for your own identifiers or for people who have given clear permission. Respect site terms, rate limits, robots.txt where applicable, and local law. CleanTrace findings are leads for manual review, not proof of identity.

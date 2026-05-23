# CleanTrace

CleanTrace is a local-first CLI/TUI privacy exposure self-assessment tool.

It helps you find public exposure, understand risk, generate removal requests, and track cleanup. It does **not** promise to delete you from the internet, and it is not designed for searching arbitrary people.

![CleanTrace terminal output](docs/screenshots/milestone1-summary.svg)

## Table of Contents

- [What CleanTrace Is For](#what-cleantrace-is-for)
- [What It Can Do Today](#what-it-can-do-today)
- [What It Will Not Do](#what-it-will-not-do)
- [Install](#install)
- [First Run](#first-run)
- [Profiles and Consent](#profiles-and-consent)
- [Scanning](#scanning)
- [Advanced Exposure Discovery](#advanced-exposure-discovery)
- [Findings and Reports](#findings-and-reports)
- [Removal Requests](#removal-requests)
- [GitHub Connector](#github-connector)
- [Google Takeout Import](#google-takeout-import)
- [Textual TUI](#textual-tui)
- [Local AI With Ollama](#local-ai-with-ollama)
- [Configuration](#configuration)
- [Local Data and Privacy](#local-data-and-privacy)
- [Plugin System](#plugin-system)
- [Development](#development)
- [Current Limits](#current-limits)

## What CleanTrace Is For

CleanTrace is for reviewing your own online exposure, or helping someone who has clearly asked you to review theirs.

The tool is built around an explicit consent profile. A scan should answer questions like:

- Which public profiles use my current or old usernames?
- Does my email appear in known breach summaries?
- Does my GitHub profile expose a location, email, linked domain, or suspicious public config file?
- Does my Google Takeout archive contain location history, shared-link metadata, or photo location clues?
- What are the highest-priority cleanup actions?
- What removal request should I send, and what is its current status?

CleanTrace is useful without AI. AI is only an optional local assistant layer for summarising findings or drafting cleanup text.

## What It Can Do Today

CleanTrace currently supports:

- Rich CLI output with calm, copyable summaries.
- Encrypted local consent profiles.
- Username checks against local site definitions.
- HIBP email breach checks when you configure an API key.
- HIBP Pwned Passwords k-anonymity checks without storing the password.
- GitHub account linking through official APIs.
- Public GitHub profile and repository exposure checks.
- Google Takeout ZIP import, parsed locally.
- Phone number country-code parsing and safe search variants.
- Public Web Discovery through configured search APIs such as SearXNG, Brave, Bing,
  Google Custom Search, or SerpAPI.
- Metadata-only Breach & Dark Web Intelligence provider layer.
- Explicit user-provided Tor public URL checks with no crawling.
- Manual evidence import for local screenshots, exports, and saved pages.
- Local findings database with confidence, severity, evidence, timestamps, and remediation.
- Markdown and HTML reports.
- Removal request drafting and status tracking.
- Local plugin enable/disable state.
- Textual full-screen dashboard.
- Optional local Ollama summaries and action lists.

## What It Will Not Do

CleanTrace intentionally avoids features that would turn it into a doxxing or account-abuse tool.

It does not:

- Search arbitrary people without a consent profile.
- Claim to remove someone from the internet.
- Scrape leaked databases or store raw breach records.
- Crawl dark-web sites or scrape illegal marketplaces.
- Download credential dumps.
- Store passwords.
- Attempt logins.
- Abuse password reset flows.
- Bypass CAPTCHAs.
- Steal browser cookies.
- Scrape private Discord servers or private communities.
- Upload profile data, findings, Takeout archives, tokens, or API keys to a CleanTrace backend.

## Install

Requirements:

- Python 3.12 or newer.
- Git, if you are working from the repository.
- Optional: GitHub CLI (`gh`) for the easiest GitHub connector setup.
- Optional: Ollama for local AI commands.

From the repository root:

```powershell
python -m pip install -e ".[dev]"
```

Check the installed CLI:

```powershell
cleantrace --version
cleantrace --help
```

## First Run

The easiest entry point is the guided scan:

```powershell
cleantrace scan wizard
```

For guided configuration first:

```powershell
cleantrace config wizard
cleantrace config check
```

1. Initialise local config, database, and encryption key:

```powershell
cleantrace init
```

Use `--yes` for non-interactive setup:

```powershell
cleantrace init --yes
```

2. Create your first consent profile:

```powershell
cleantrace profile create --wizard
```

Or create one non-interactively:

```powershell
cleantrace profile create `
  --slug default `
  --username yourhandle `
  --email you@example.com `
  --consent
```

3. Run a quick username scan:

```powershell
cleantrace scan username yourhandle --profile default --depth quick
```

4. Review findings:

```powershell
cleantrace findings --profile default
```

5. Export a report:

```powershell
cleantrace report --profile default --format markdown --output cleantrace-report.md
cleantrace report --profile default --format html --output cleantrace-report.html
```

## Profiles and Consent

A profile is the local record that says what identifiers CleanTrace is allowed to scan.

Supported profile fields include:

- Legal name.
- Display names.
- Usernames.
- Email addresses.
- Phone numbers.
- Approximate location.
- Known domains.
- Known social links.
- Role notes.
- Risk sensitivity: `normal`, `high`, or `protected-role`.

Useful commands:

```powershell
cleantrace profile list
cleantrace profile show default
cleantrace profile show default --show-sensitive
```

Sensitive values are redacted by default in terminal output. Use `--show-sensitive` only when you are working locally and need to inspect the raw profile values.

### Protected-Role Mode

Use `--risk-sensitivity protected-role` if exposure could create higher personal risk, for example public officials, journalists, emergency workers, stalking/domestic-abuse risk users, or similar cases.

Protected-role scoring gives extra weight to findings that connect identity, location, phone number, work role, family links, or professional presence.

## Scanning

CleanTrace scans are local-first and consent-based.

### Guided Scan Wizard

```powershell
cleantrace scan wizard --profile default
cleantrace scan wizard --advanced
cleantrace scan wizard --resume
```

The wizard walks through profile consent, scan categories, depth, provider readiness, setup prompts,
and final recommended actions. If a selected module needs missing config, CleanTrace explains the
privacy impact and lets you configure, skip, use a fallback, or exit. Scan sessions are stored
locally:

```powershell
cleantrace scan sessions
cleantrace scan resume
cleantrace scan cancel SESSION_ID
```

### Run Everything Configured

```powershell
cleantrace scan all --profile default --depth quick
```

`scan all` runs:

- Username discovery for profile usernames.
- HIBP email checks if an API key is configured and the plugin is enabled.
- Phone validation and search-variant generation.
- Public Web Discovery if enabled and configured.
- Breach & Dark Web Intelligence if enabled and configured.
- Linked GitHub account checks if one is linked and the plugin is enabled.

### Depth Levels

- `quick`: small initial scan, intended for fast feedback.
- `standard`: broader username site set.
- `deep`: reserved for slower/manual-review paths where supported.

Example:

```powershell
cleantrace scan all --profile default --depth standard
```

### Username Scans

```powershell
cleantrace scan username yourhandle --profile default --depth quick
```

The username scanner uses local YAML site definitions under:

```text
src/cleantrace/plugins/sites/username_sites.yaml
```

It records public-profile leads with confidence scores. A username match is a lead for manual review, not proof of identity.

### Social/Profile Site Scan

```powershell
cleantrace scan social --profile default --depth standard
cleantrace scan social --profile default --category gaming
cleantrace scan social --profile default --username yourhandle
```

The social scanner uses `src/cleantrace/data/social_sites.yaml` and checks public profile endpoints
only. It includes mainstream social, developer, gaming, creator, forum, music, and professional
sites. Adult/sensitive categories are disabled by default.

### Broker and People-Search Scan

```powershell
cleantrace scan brokers --profile default --country GB
cleantrace brokers list
cleantrace brokers explain "192.com"
cleantrace brokers removal-plan --profile default --country GB
```

Broker checks produce removal opportunities and manual guidance. CleanTrace does not submit forms,
bypass CAPTCHA, or automate identity-verification flows.

### Email Breach Checks With HIBP

CleanTrace uses the official Have I Been Pwned API only when you provide an API key.

The HIBP email plugin is disabled by default because it calls a third-party API. Enable it locally first:

```powershell
cleantrace plugins enable hibp_email
```

Set the key as an environment variable:

```powershell
$env:CLEANTRACE_HIBP_API_KEY = "your_key_here"
```

Or set it in `config.toml`:

```toml
[api_keys]
hibp = "your_key_here"
```

Then run:

```powershell
cleantrace scan email you@example.com --profile default --hibp
```

CleanTrace stores breach summaries only. It does not store leaked records.

### Password Check

```powershell
cleantrace scan password
```

This uses the HIBP Pwned Passwords k-anonymity range API. CleanTrace sends only the first five characters of the SHA-1 hash prefix and does not store the password.

Avoid passing passwords with `--password` unless you understand shell history risks. The prompt is safer.

## Advanced Exposure Discovery

Advanced Exposure Discovery expands CleanTrace beyond username checks while keeping the same
consent and local-first model. Each scan is tied to a local profile. Third-party providers are
disabled by default and only receive identifiers when you explicitly enable and configure them.

### Phone Numbers

CleanTrace uses `phonenumbers` to parse country codes and formats. It stores phone numbers
encrypted, plus local metadata such as E.164 format, national format, region, calling code, and
validity.

```powershell
cleantrace profile phone add --profile default --country GB "07700 900123"
cleantrace profile phone list --profile default
cleantrace scan phone --profile default
cleantrace scan phone "+14155552671" --country US
```

Supported country input examples include `GB`, `United Kingdom`, `US`, `Germany`, and `+44`.
CleanTrace does not send SMS, place calls, or perform active phone verification.

### Public Web Discovery

Public Web Discovery generates structured search queries from your consent profile, then sends
those queries to a configured search provider. It does not scrape Google result pages directly.

Enable the module and a provider:

```powershell
cleantrace plugins enable web_discovery
cleantrace config set web_discovery.providers.searxng.enabled true
cleantrace config set web_discovery.providers.searxng.base_url http://localhost:8080
cleantrace config set web_discovery.default_provider searxng
```

Run scans:

```powershell
cleantrace scan web --profile default --depth quick
cleantrace scan web --profile default --depth standard --query-set identity
cleantrace scan web --profile default --query-set phone
cleantrace scan web --profile default --query-set username
cleantrace scan web --profile default --query-set email --json
```

Supported provider keys:

- `web_discovery.providers.searxng.base_url`
- `web_discovery.providers.brave.api_key`
- `web_discovery.providers.bing.api_key`
- `web_discovery.providers.google_cse.api_key`
- `web_discovery.providers.google_cse.search_engine_id`
- `web_discovery.providers.serpapi.api_key`

Results are deduplicated by canonical URL, classified, confidence-scored, and stored as leads.
Common classifications include `data_broker`, `social_profile`, `professional_profile`,
`public_document`, `paste_or_dump_reference`, and `needs_manual_review`.

### Breach & Dark Web Intelligence

This layer is metadata-only. It can query lawful breach-intelligence APIs, but CleanTrace does not
store leaked records, passwords, password hashes, tokens, private keys, or provider raw responses.

```powershell
cleantrace plugins enable breach_intel
cleantrace config set breach_intel.providers.hibp.enabled true
cleantrace config set breach_intel.providers.hibp.api_key your_hibp_key
cleantrace scan intel --profile default --provider hibp
```

LeakCheck, DeHashed, and Intelligence X connectors are present as disabled-by-default provider
layers. They require a user-supplied API key, `terms_accepted = true`, and local config enablement
before they will run.

### Tor Public URL Check

Tor support is intentionally narrow. CleanTrace only checks explicit `.onion` URLs you provide. It
does not discover onion sites, crawl, follow links, submit forms, log in, or download files.

You must run your own Tor SOCKS proxy; CleanTrace does not bundle Tor.

```powershell
cleantrace plugins enable tor_public_check
cleantrace config set tor_public_check.socks_proxy socks5://127.0.0.1:9050
cleantrace scan tor-url --profile default --url http://exampleonionaddress.onion --yes
cleantrace scan tor-list --profile default --file onion_urls.txt --yes
```

If a URL or page appears to reference illegal marketplaces, credential dumps, stolen-data trading,
CSAM, weapons trafficking, or drugs, CleanTrace stops processing and stores only a warning finding.

### Manual Evidence Import

Manual evidence import converts local material into redacted metadata findings. Use it for search
exports, saved result pages, breach-provider emails, screenshots, data broker pages, or removal
responses you lawfully obtained.

```powershell
cleantrace import evidence --profile default --file evidence.txt
cleantrace import evidence --profile default --file evidence.html
cleantrace import evidence --profile default --file evidence.json
cleantrace import evidence --profile default --file screenshot.png
```

If imported text looks like it contains passwords, tokens, private keys, hashes, or leaked database
rows, CleanTrace warns and stores only redacted metadata.

### Broad Exposure Scan

`scan exposure` runs the enabled modules that are safe to run without extra user input. It does not
run disabled providers and does not run Tor unless URLs are explicitly supplied through the Tor
commands.

```powershell
cleantrace scan exposure --profile default --depth quick
cleantrace scan exposure --profile default --depth standard
cleantrace scan exposure --profile default --depth deep --json
```

## Findings and Reports

Findings include:

- ID.
- Profile ID.
- Source plugin.
- Input type.
- Hash of the scanned input.
- Title and description.
- URL when available.
- Evidence metadata.
- Confidence from 0 to 100.
- Severity: `info`, `low`, `medium`, `high`, `critical`.
- First seen and last seen timestamps.
- Remediation advice.
- Tags.

List findings:

```powershell
cleantrace findings --profile default
```

Machine-readable output:

```powershell
cleantrace findings --profile default --json
```

Generate reports:

```powershell
cleantrace report --profile default --format markdown --output report.md
cleantrace report --profile default --format html --output report.html
```

Every scan summary ends with the top five recommended actions.

## Removal Requests

CleanTrace can draft local removal requests and track their status. It does not send emails or submit web forms for you.

Generate a request for a finding:

```powershell
cleantrace removal generate --profile default --finding FINDING_ID
```

Generate a data broker opt-out draft:

```powershell
cleantrace removal generate --profile default --broker "192.com"
```

Write the draft to a file:

```powershell
cleantrace removal generate --profile default --finding FINDING_ID --output removal.txt
```

Track status:

```powershell
cleantrace removal track --request REQUEST_ID --status sent
cleantrace removal list --profile default
```

Guided workflow:

```powershell
cleantrace removal wizard --profile default
cleantrace removal plan --profile default --country GB
cleantrace removal mark --finding FINDING_ID --status submitted
cleantrace removal evidence --finding FINDING_ID --file response.eml
cleantrace removal followup --finding FINDING_ID
```

Supported statuses:

- `not started`
- `drafted`
- `sent`
- `waiting`
- `removed`
- `refused`
- `needs manual action`

## GitHub Connector

The GitHub connector uses official GitHub APIs. Tokens are encrypted locally.

The easiest setup uses the GitHub CLI:

```powershell
gh auth login
cleantrace link github --profile default
cleantrace scan github --profile default
```

Public-only username link:

```powershell
cleantrace link github --profile default --username yourhandle --no-from-gh
cleantrace scan github --profile default
```

Private repository scanning is off by default. It requires explicit opt-in:

```powershell
cleantrace link github --profile default --private-scan
cleantrace scan github --profile default --include-private
```

The current GitHub checks look for:

- Public email on the GitHub profile.
- Public location on the GitHub profile.
- Linked website/domain.
- Sensitive config filenames in public repositories.
- Basic safe regex leads for possible public secrets.

CleanTrace does not upload repository contents anywhere.

Disconnect GitHub:

```powershell
cleantrace unlink github --profile default
```

## Google Takeout Import

Google Takeout import is local-only. CleanTrace reads a local ZIP archive and stores risk-indicator findings.

```powershell
cleantrace import google-takeout .\takeout.zip --profile default
```

It currently looks for:

- Location History files.
- Google Photos metadata with geolocation-like fields.
- Profile metadata that may need review.
- Drive/shared-link metadata.

CleanTrace does not upload the archive and does not store the full Takeout contents. Treat Takeout files as highly sensitive and delete old copies when you no longer need them.

## Textual TUI

Open the dashboard:

```powershell
cleantrace tui
```

The TUI shows:

- Profiles.
- Findings.
- Exposure score.
- Setup checklist.
- Provider readiness.
- Social and broker coverage through findings.
- Identity-link graph table.
- Removal request status.

Controls:

- `r`: refresh.
- `q`: quit.

## Local AI With Ollama

AI is disabled by default. The current version supports local Ollama only.

Enable it in `config.toml`:

```toml
[ai]
provider = "ollama"
ollama_url = "http://localhost:11434"
ollama_model = "llama3.1"
```

Then run:

```powershell
cleantrace ai summarise --profile default
cleantrace ai actions --profile default
cleantrace ai removal-email --profile default --finding FINDING_ID
```

CleanTrace redacts emails, phones, and token-like strings before building prompts. The AI output is an assistant layer, not the source of truth. Findings and reports work without AI.

OpenAI-compatible/cloud AI is not implemented in the current version.

## Configuration

Show active paths:

```powershell
cleantrace config
cleantrace config wizard
cleantrace config check
cleantrace config explain
cleantrace config providers
cleantrace config repair
```

Default `config.toml`:

```toml
[storage]
database = "PATH/cleantrace.db"
user_sites_dir = "PATH/sites.d"

[scan]
default_depth = "quick"
redact_output = true
respect_robots_txt = true
default_country = "GB"

[web_discovery]
enabled = false
default_provider = "searxng"
respect_robots_txt = true
max_results_quick = 10
max_results_standard = 30
max_results_deep = 75
request_delay_seconds = 2
cache_ttl_hours = 72

[web_discovery.providers.searxng]
enabled = false
base_url = "http://localhost:8080"

[breach_intel]
enabled = false
metadata_only = true
store_raw_provider_responses = false
redact_output = true

[tor_public_check]
enabled = false
socks_proxy = "socks5://127.0.0.1:9050"
follow_links = false
max_urls_per_scan = 10
store_page_content = false

[social_profiles]
enabled = true
include_sensitive_sites = false

[data_brokers]
enabled = true
default_country = "GB"

[monitoring]
enabled = false

[alerts]
enabled = false
include_sensitive_in_alerts = false

[ai]
provider = "none"
ollama_url = "http://localhost:11434"
ollama_model = "llama3.1"
openai_compatible_url = ""

[api_keys]
# hibp = ""
# brave_search = ""
```

### Important Config Keys

`storage.database`

Path to the local SQLite database.

`storage.user_sites_dir`

Directory reserved for user-provided site definitions.

`scan.default_depth`

Default scan depth used by future commands that read this setting.

`scan.redact_output`

Whether terminal output should redact sensitive values by default.

`web_discovery.enabled`

Module-level switch for Public Web Discovery. `cleantrace plugins enable web_discovery` updates this.

`web_discovery.default_provider`

Search provider to use when `--provider` is not passed. Supported values are `searxng`, `brave`,
`bing`, `google_cse`, and `serpapi`.

`breach_intel.enabled`

Module-level switch for metadata-only Breach & Dark Web Intelligence.

`breach_intel.store_raw_provider_responses`

Must remain `false` for the intended privacy model. CleanTrace stores metadata findings, not raw
provider payloads.

`tor_public_check.socks_proxy`

Local Tor SOCKS proxy URL. Tor must be installed and running separately.

`ai.provider`

Use `none` or `ollama`. Cloud AI is not implemented.

`ai.ollama_url`

Local Ollama server URL.

`ai.ollama_model`

Model name to request from Ollama.

`api_keys.hibp`

Optional HIBP API key. You can also use `CLEANTRACE_HIBP_API_KEY`.

## Local Data and Privacy

CleanTrace stores data locally using platform-specific application directories.

On this Windows environment, `cleantrace config` reports paths like:

```text
C:\Users\<you>\AppData\Local\cleantrace\cleantrace\config.toml
C:\Users\<you>\AppData\Local\cleantrace\cleantrace\cleantrace.db
C:\Users\<you>\AppData\Local\cleantrace\cleantrace\cleantrace.key
```

On Linux/macOS, paths are resolved by `platformdirs` and may look like:

```text
~/.config/cleantrace/config.toml
~/.local/share/cleantrace/cleantrace.db
~/.local/share/cleantrace/cleantrace.key
```

Local files include:

- `config.toml`: app configuration.
- `cleantrace.db`: SQLite database.
- `cleantrace.key`: Fernet encryption key.
- `plugins.json`: local plugin enabled/disabled state.
- `sites.d/`: reserved for user site definitions.

Raw profile identifiers and linked account tokens are encrypted. Findings store hashes and evidence metadata. The database and encryption key should both be treated as sensitive.

Delete the local database:

```powershell
cleantrace wipe
```

`wipe` removes the database, not necessarily every config or key file. Remove config/key files manually if you want a full local reset.

## Plugin System

Built-in plugins live under:

```text
src/cleantrace/plugins/
```

List plugins:

```powershell
cleantrace plugins list
```

Enable or disable a plugin:

```powershell
cleantrace plugins enable username_discovery
cleantrace plugins disable hibp_email
```

Current built-in plugins:

- `username_discovery`
- `hibp_email`
- `github_connector`
- `web_discovery`
- `breach_intel`
- `tor_public_check`
- `manual_evidence`
- `social_profiles`
- `data_brokers`

## Monitoring and Alerts

Monitoring is local. CleanTrace does not create a cloud service.

```powershell
cleantrace monitor enable --profile default
cleantrace monitor run
cleantrace monitor status
cleantrace monitor changes
cleantrace monitor disable
```

Use cron, Windows Task Scheduler, or a systemd user timer to run `cleantrace monitor run`. Alerts are
disabled by default and redacted unless `alerts.include_sensitive_in_alerts = true`.

Plugin state is stored locally in `plugins.json`.

Username site definitions use YAML:

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

## Development

Install development dependencies:

```powershell
python -m pip install -e ".[dev]"
```

Run checks:

```powershell
pytest
ruff check .
mypy
```

Current expected result:

- `pytest`: all tests passing.
- `ruff check .`: all checks passing.
- `mypy`: no issues.

## Current Limits

CleanTrace is usable, but still early.

Known limits:

- Public Web Discovery requires a configured search provider.
- Tor support checks only explicit user-provided public onion URLs.
- Breach intelligence is metadata-only and provider coverage depends on configured API keys.
- Reports support Markdown and HTML only.
- The Textual TUI is a dashboard, not a full replacement for the CLI.
- Google Takeout parsing detects risk indicators, not every possible exposure.
- GitHub secret checks are lightweight regex leads, not a full secret-scanning engine.
- Cloud AI support is not implemented.
- Findings are leads for manual review, not proof that an account belongs to a person.

## Legal and Ethical Disclaimer

Use CleanTrace only for your own identifiers or for people who have given clear permission. Respect site terms, rate limits, and local law. CleanTrace is a self-assessment and cleanup tracker, not a doxxing, stalking, impersonation, phishing, credential attack, or surveillance tool.

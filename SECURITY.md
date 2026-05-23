# Security Policy

## Supported Versions

CleanTrace is pre-1.0 software. Security fixes target the current `main` branch until formal releases exist.

## Reporting a Vulnerability

Open a private security advisory or contact the maintainers without posting exploit details publicly. Include:

- affected version or commit
- operating system
- reproduction steps
- impact
- whether sensitive local data, tokens, or reports are exposed

## Security Boundaries

CleanTrace encrypts raw profile identifiers and linked account tokens locally, but it cannot protect data if the local machine, user account, Python environment, or installed plugins are compromised. The local database and encryption key should both be treated as sensitive.

Google Takeout archives can contain highly sensitive account, location, photo, and sharing data. CleanTrace parses them locally, but users should keep the original archive private and delete it when no longer needed.

Manual evidence files can contain secrets or leaked material. CleanTrace attempts to redact
passwords, token-like strings, private keys, and hash-like values before storing metadata, but users
should avoid importing raw leaked datasets and should delete unsafe source files after review.

Tor public URL checks require a user-managed Tor SOCKS proxy. CleanTrace does not bundle Tor, does
not crawl onion sites, does not follow links, and does not download files. If a URL appears unsafe or
illegal, CleanTrace stores only a warning finding.

Third-party breach-intelligence providers are disabled by default. Non-HIBP providers require a
local API key and explicit terms acceptance. Provider responses must be treated as sensitive and
CleanTrace stores metadata-only findings.

Social/profile and broker modules must use public endpoints, configured search providers, or manual
guidance. They must not bypass CAPTCHA, login walls, paywalls, anti-bot systems, or rate limits.

Monitoring and alerts are local features. SMTP, webhooks, and Discord webhook style alerts must stay
disabled by default and must not include sensitive content unless the user explicitly opts in.

## Non-Goals

CleanTrace will not add features for credential attacks, CAPTCHA bypass, password reset abuse,
hidden scraping, browser cookie theft, leaked database scraping, dark-web marketplace crawling,
illegal-content access, or non-consensual target discovery.

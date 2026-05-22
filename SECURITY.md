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

## Non-Goals

CleanTrace will not add features for credential attacks, CAPTCHA bypass, password reset abuse, hidden scraping, browser cookie theft, leaked database scraping, or non-consensual target discovery.

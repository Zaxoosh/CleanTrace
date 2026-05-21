# Contributing

CleanTrace welcomes contributions that preserve the local-first, consent-based design.

## Development

```bash
python -m pip install -e ".[dev]"
pytest
ruff check .
mypy
```

## Plugin Rules

Plugins must declare risk labels and supported input types. Risky, fragile, sensitive, or scraping-heavy modules must be disabled by default. Plugins must not:

- attempt login
- bypass CAPTCHA
- spam password reset flows
- scrape leaked databases
- store passwords or raw breach records
- upload user data without explicit opt-in

## Pull Requests

Keep changes focused. Include tests for storage, scoring, plugin parsing, report generation, or CLI behaviour when relevant. Update `README.md`, `PRIVACY.md`, or `ETHICS.md` when a change affects user expectations.

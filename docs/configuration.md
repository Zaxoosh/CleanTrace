# CleanTrace Configuration

Start with:

```powershell
cleantrace config wizard
cleantrace config check
```

The wizard explains each area, whether it is required, whether data leaves the device, and the
recommended setting.

Important areas:

- General settings: scan depth, country default, and redaction.
- Storage and encryption: local SQLite database and Fernet key.
- Web discovery providers: SearXNG, Brave, Bing, Google CSE, or SerpAPI.
- Breach intelligence providers: metadata-only provider checks.
- Social-site scanner: public profile endpoint checks.
- Data broker scanner: manual guidance and provider-backed leads.
- AI/Ollama: optional local summaries.
- Monitoring and alerts: local diffs and redacted summaries.

Useful commands:

```powershell
cleantrace config explain
cleantrace config providers
cleantrace config repair
cleantrace config set scan.default_country GB
```

# Monitoring

Monitoring is local. CleanTrace does not run a cloud service.

```powershell
cleantrace monitor enable --profile default
cleantrace monitor run
cleantrace monitor changes
cleantrace monitor status
cleantrace monitor disable
```

Use your operating system scheduler:

- Windows: Task Scheduler runs `cleantrace monitor run`.
- macOS/Linux: cron can run `cleantrace monitor run`.
- Linux: systemd user timers can run the same command.

Monitoring compares local finding snapshots and reports:

- new findings
- changed severity/confidence
- removed findings
- reappeared findings

Alerts are disabled by default and should remain redacted unless you explicitly enable sensitive alert
content.

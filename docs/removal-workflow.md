# Removal Workflow

CleanTrace tracks cleanup locally.

```powershell
cleantrace removal wizard --profile default
cleantrace removal generate --finding FINDING_ID
cleantrace removal mark --finding FINDING_ID --status submitted
cleantrace removal evidence --finding FINDING_ID --file response.eml
cleantrace removal followup --finding FINDING_ID
```

Supported workflow statuses include:

- not_started
- drafted
- submitted
- waiting
- removed
- refused
- needs_manual_action
- reappeared
- followup_due

Removal is not guaranteed. Keep copies of correspondence and avoid sending more verification data
than the provider reasonably needs.

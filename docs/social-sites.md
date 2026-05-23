# Social/Profile Sites

The social scanner reads `src/cleantrace/data/social_sites.yaml`.

Each entry includes:

- name and category
- public profile URL template
- public check URL template
- expected status codes
- claimed/unclaimed indicators
- false-positive rules
- rate-limit delay
- privacy notes

CleanTrace checks public endpoints only. It does not log in, bypass CAPTCHA, scrape private content,
or check adult/sensitive categories by default.

Example:

```powershell
cleantrace scan social --profile default --depth standard
cleantrace scan social --profile default --category developer
```

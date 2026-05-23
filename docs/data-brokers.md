# Data Brokers

The broker registry is `src/cleantrace/data/data_brokers.yaml`.

It prioritises UK/EU guidance and includes major documented US/global opt-out routes. Broker checks
create findings and removal guidance; CleanTrace does not submit forms automatically.

Useful commands:

```powershell
cleantrace scan brokers --profile default --country GB
cleantrace brokers list
cleantrace brokers explain "192.com"
cleantrace brokers removal-plan --profile default --country GB
```

If a broker uses CAPTCHA, login walls, anti-bot controls, or manual verification, CleanTrace marks it
as `manual_check_required`.

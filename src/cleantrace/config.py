from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cleantrace.paths import config_path, database_path, ensure_app_dirs, sites_dir

DEFAULT_CONFIG = """# CleanTrace local configuration
# CleanTrace is local-first. There is no telemetry unless future versions add
# an explicit, opt-in setting.

[storage]
database = "{database}"
user_sites_dir = "{sites}"

[scan]
default_depth = "quick"
redact_output = true
respect_robots_txt = true

[ai]
provider = "none"

[api_keys]
# hibp = ""
# brave_search = ""
"""


@dataclass(frozen=True)
class AppConfig:
    database: Path
    user_sites_dir: Path
    default_depth: str = "quick"
    redact_output: bool = True
    ai_provider: str = "none"


def write_default_config(force: bool = False) -> Path:
    ensure_app_dirs()
    target = config_path()
    if target.exists() and not force:
        return target
    target.write_text(
        DEFAULT_CONFIG.format(database=database_path().as_posix(), sites=sites_dir().as_posix()),
        encoding="utf-8",
    )
    return target


def load_config() -> AppConfig:
    ensure_app_dirs()
    write_default_config(force=False)
    try:
        import tomllib

        raw = tomllib.loads(config_path().read_text(encoding="utf-8"))
    except Exception:
        raw = {}
    storage = raw.get("storage", {})
    scan = raw.get("scan", {})
    ai = raw.get("ai", {})
    return AppConfig(
        database=Path(storage.get("database") or database_path()),
        user_sites_dir=Path(storage.get("user_sites_dir") or sites_dir()),
        default_depth=str(scan.get("default_depth") or "quick"),
        redact_output=bool(scan.get("redact_output", True)),
        ai_provider=str(ai.get("provider") or "none"),
    )


def get_api_key(name: str) -> str | None:
    try:
        import tomllib

        raw = tomllib.loads(config_path().read_text(encoding="utf-8"))
    except Exception:
        return None
    value = raw.get("api_keys", {}).get(name)
    return str(value) if value else None

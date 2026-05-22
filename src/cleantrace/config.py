from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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

[web_discovery]
enabled = false
default_provider = "searxng"
respect_robots_txt = true
max_results_quick = 10
max_results_standard = 30
max_results_deep = 75
request_delay_seconds = 2
cache_ttl_hours = 72

[web_discovery.page_fetch]
enabled = false
max_pages_per_scan = 10
respect_robots_txt = true
user_agent = "CleanTrace privacy self-assessment bot"
timeout_seconds = 10
store_page_content = false

[web_discovery.providers.brave]
enabled = false
api_key = ""

[web_discovery.providers.bing]
enabled = false
api_key = ""

[web_discovery.providers.google_cse]
enabled = false
api_key = ""
search_engine_id = ""

[web_discovery.providers.serpapi]
enabled = false
api_key = ""

[web_discovery.providers.searxng]
enabled = false
base_url = "http://localhost:8080"

[breach_intel]
enabled = false
metadata_only = true
store_raw_provider_responses = false
redact_output = true

[breach_intel.providers.hibp]
enabled = false
api_key = ""

[breach_intel.providers.leakcheck]
enabled = false
api_key = ""
terms_accepted = false

[breach_intel.providers.dehashed]
enabled = false
api_key = ""
terms_accepted = false

[breach_intel.providers.intelx]
enabled = false
api_key = ""
terms_accepted = false

[tor_public_check]
enabled = false
socks_proxy = "socks5://127.0.0.1:9050"
follow_links = false
max_urls_per_scan = 10
timeout_seconds = 20
store_page_content = false
redact_output = true

[ai]
provider = "none"
ollama_url = "http://localhost:11434"
ollama_model = "llama3.1"
openai_compatible_url = ""

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
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"
    openai_compatible_url: str = ""
    raw: dict[str, Any] | None = None


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
        ollama_url=str(ai.get("ollama_url") or "http://localhost:11434"),
        ollama_model=str(ai.get("ollama_model") or "llama3.1"),
        openai_compatible_url=str(ai.get("openai_compatible_url") or ""),
        raw=raw,
    )


def load_raw_config() -> dict[str, Any]:
    return load_config().raw or {}


def config_get(path: str, default: Any = None) -> Any:
    value: Any = load_raw_config()
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return default
        value = value[part]
    return value


def parse_config_value(value: str) -> Any:
    lowered = value.strip().lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    try:
        return int(value)
    except ValueError:
        return value


def config_set(path: str, value: str) -> Path:
    """Set a simple config key, preserving comments is intentionally out of scope."""
    ensure_app_dirs()
    raw = load_raw_config()
    target: dict[str, Any] = raw
    parts = path.split(".")
    for part in parts[:-1]:
        nested = target.get(part)
        if not isinstance(nested, dict):
            nested = {}
            target[part] = nested
        target = nested
    target[parts[-1]] = parse_config_value(value)
    write_toml(config_path(), raw)
    return config_path()


def write_toml(path: Path, data: dict[str, Any]) -> None:
    lines: list[str] = ["# CleanTrace local configuration", ""]

    def emit_table(prefix: str, table: dict[str, Any]) -> None:
        scalars = {k: v for k, v in table.items() if not isinstance(v, dict)}
        nested = {k: v for k, v in table.items() if isinstance(v, dict)}
        if prefix:
            lines.append(f"[{prefix}]")
        for key, item in scalars.items():
            lines.append(f"{key} = {format_toml_value(item)}")
        if scalars:
            lines.append("")
        for key, item in nested.items():
            emit_table(f"{prefix}.{key}" if prefix else key, item)

    emit_table("", data)
    path.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")


def format_toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def get_api_key(name: str) -> str | None:
    env_value = os.getenv(f"CLEANTRACE_{name.upper()}_API_KEY") or os.getenv(
        f"{name.upper()}_API_KEY"
    )
    if env_value:
        return env_value
    try:
        import tomllib

        raw = tomllib.loads(config_path().read_text(encoding="utf-8"))
    except Exception:
        return None
    value = raw.get("api_keys", {}).get(name)
    return str(value) if value else None

from __future__ import annotations

import json
from dataclasses import dataclass

from cleantrace.paths import ensure_app_dirs, plugin_state_path
from cleantrace.plugins.manager import built_in_plugin_metadata


@dataclass(frozen=True)
class PluginState:
    name: str
    enabled: bool
    default_enabled: bool


def _default_state() -> dict[str, bool]:
    return {meta.name: meta.enabled_by_default for meta in built_in_plugin_metadata()}


def load_plugin_states() -> dict[str, bool]:
    ensure_app_dirs()
    defaults = _default_state()
    path = plugin_state_path()
    if not path.exists():
        save_plugin_states(defaults)
        return defaults
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        raw = {}
    states = defaults | {str(key): bool(value) for key, value in raw.items()}
    save_plugin_states(states)
    return states


def save_plugin_states(states: dict[str, bool]) -> None:
    ensure_app_dirs()
    plugin_state_path().write_text(json.dumps(states, indent=2, sort_keys=True), encoding="utf-8")


def set_plugin_enabled(name: str, enabled: bool) -> None:
    known = {meta.name for meta in built_in_plugin_metadata()}
    if name not in known:
        raise ValueError(f"Unknown plugin: {name}")
    states = load_plugin_states()
    states[name] = enabled
    save_plugin_states(states)


def plugin_enabled(name: str) -> bool:
    return load_plugin_states().get(name, False)

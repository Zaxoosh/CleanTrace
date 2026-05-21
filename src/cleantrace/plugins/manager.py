from __future__ import annotations

from cleantrace.plugins.base import CleanTracePlugin
from cleantrace.plugins.username import UsernameDiscoveryPlugin


def built_in_plugins() -> list[CleanTracePlugin]:
    return [UsernameDiscoveryPlugin()]


def plugins_for_input(input_type: str) -> list[CleanTracePlugin]:
    return [plugin for plugin in built_in_plugins() if input_type in plugin.meta.input_types]

from cleantrace.paths import plugin_state_path
from cleantrace.plugin_state import load_plugin_states, plugin_enabled, set_plugin_enabled


def test_plugin_state_round_trip(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    path = plugin_state_path()
    if path.exists():
        path.unlink()

    states = load_plugin_states()
    assert states["username_discovery"] is True

    set_plugin_enabled("username_discovery", False)

    assert plugin_enabled("username_discovery") is False

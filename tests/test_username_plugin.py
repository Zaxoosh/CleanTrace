from pathlib import Path

from cleantrace.plugins.username import UsernameDiscoveryPlugin, extract_title


def test_extract_title_normalises_whitespace() -> None:
    assert extract_title("<title> Hello\n CleanTrace </title>") == "Hello CleanTrace"


def test_load_quick_username_sites() -> None:
    plugin = UsernameDiscoveryPlugin()
    sites = plugin.load_sites("quick")

    assert len(sites) == 10
    assert sites[0].name == "GitHub"
    assert all(site.enabled_by_default for site in sites)


def test_site_definition_file_is_packaged() -> None:
    path = (
        Path(__file__).parents[1]
        / "src"
        / "cleantrace"
        / "plugins"
        / "sites"
        / "username_sites.yaml"
    )
    assert path.exists()

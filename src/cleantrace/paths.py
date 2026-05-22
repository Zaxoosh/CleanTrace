from __future__ import annotations

from pathlib import Path

from platformdirs import user_config_dir, user_data_dir

from cleantrace.constants import APP_NAME, CONFIG_FILE_NAME, DATABASE_FILE_NAME, KEY_FILE_NAME


def config_dir() -> Path:
    return Path(user_config_dir(APP_NAME))


def data_dir() -> Path:
    return Path(user_data_dir(APP_NAME))


def sites_dir() -> Path:
    return config_dir() / "sites.d"


def config_path() -> Path:
    return config_dir() / CONFIG_FILE_NAME


def plugin_state_path() -> Path:
    return config_dir() / "plugins.json"


def database_path() -> Path:
    return data_dir() / DATABASE_FILE_NAME


def key_path() -> Path:
    return data_dir() / KEY_FILE_NAME


def ensure_app_dirs() -> None:
    config_dir().mkdir(parents=True, exist_ok=True)
    data_dir().mkdir(parents=True, exist_ok=True)
    sites_dir().mkdir(parents=True, exist_ok=True)

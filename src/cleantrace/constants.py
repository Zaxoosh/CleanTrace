"""Shared constants for CleanTrace."""

APP_NAME = "cleantrace"
CONFIG_FILE_NAME = "config.toml"
DATABASE_FILE_NAME = "cleantrace.db"
KEY_FILE_NAME = "cleantrace.key"

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_COLOURS = {
    "info": "cyan",
    "low": "green",
    "medium": "yellow",
    "high": "orange1",
    "critical": "red",
}

RISK_BANDS = [
    (20, "low", "green"),
    (50, "moderate", "yellow"),
    (75, "high", "orange1"),
    (100, "critical", "red"),
]

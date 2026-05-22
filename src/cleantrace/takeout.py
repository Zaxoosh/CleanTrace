from __future__ import annotations

import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cleantrace.plugins.base import PluginFinding
from cleantrace.security import stable_hash

TAKEOUT_SOURCE = "google_takeout"


@dataclass(frozen=True)
class TakeoutImportSummary:
    archive: Path
    files_seen: int
    findings: list[PluginFinding]


def analyse_google_takeout(path: Path, profile_id: int) -> TakeoutImportSummary:
    if not path.exists():
        raise FileNotFoundError(path)
    if not zipfile.is_zipfile(path):
        raise ValueError("Google Takeout import expects a .zip archive.")
    findings: list[PluginFinding] = []
    files_seen = 0
    archive_hash = stable_hash(str(path.resolve()))
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        files_seen = len(names)
        findings.extend(_location_findings(names, archive_hash))
        findings.extend(_profile_findings(archive, names, archive_hash))
        findings.extend(_photos_findings(archive, names, archive_hash))
        findings.extend(_shared_link_findings(archive, names, archive_hash))
    return TakeoutImportSummary(archive=path, files_seen=files_seen, findings=findings)


def _location_findings(names: list[str], archive_hash: str) -> list[PluginFinding]:
    location_names = [
        name
        for name in names
        if "location history" in name.lower() or "semantic location history" in name.lower()
    ]
    if not location_names:
        return []
    return [
        _finding(
            archive_hash,
            "Google Takeout contains location history files",
            (
                "The Takeout archive includes location history data. CleanTrace did not parse "
                "precise locations, but the presence of these files is a sensitive-data warning."
            ),
            {"matching_files": location_names[:20], "count": len(location_names)},
            "high",
            92,
            (
                "Review Google location history settings, delete old history if not needed, "
                "and avoid sharing this Takeout archive."
            ),
            ["google", "takeout", "location"],
        )
    ]


def _profile_findings(
    archive: zipfile.ZipFile,
    names: list[str],
    archive_hash: str,
) -> list[PluginFinding]:
    profile_names = [
        name
        for name in names
        if "profile" in name.lower() and name.lower().endswith((".json", ".html", ".txt"))
    ]
    findings: list[PluginFinding] = []
    for name in profile_names[:10]:
        text = _read_text(archive, name)
        if not text:
            continue
        hints = []
        if re.search(r"\b(public|visible|profile|about me|gender|birthday)\b", text, re.I):
            hints.append("profile metadata")
        if re.search(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", text, re.I):
            hints.append("email-like value")
        if hints:
            findings.append(
                _finding(
                    archive_hash,
                    "Google Takeout profile metadata needs review",
                    "A profile-related Takeout file contains account metadata that may be public.",
                    {"file": name, "hints": hints},
                    "medium",
                    74,
                    (
                        "Review the corresponding Google profile settings and remove "
                        "stale public fields."
                    ),
                    ["google", "takeout", "profile"],
                )
            )
            break
    return findings


def _photos_findings(
    archive: zipfile.ZipFile,
    names: list[str],
    archive_hash: str,
) -> list[PluginFinding]:
    metadata_files = [
        name
        for name in names
        if ("google photos" in name.lower() or "photos" in name.lower())
        and name.lower().endswith(".json")
    ]
    geo_hits: list[str] = []
    for name in metadata_files[:500]:
        raw = _read_json(archive, name)
        if not raw:
            continue
        if _has_geo(raw):
            geo_hits.append(name)
            if len(geo_hits) >= 20:
                break
    if not geo_hits:
        return []
    return [
        _finding(
            archive_hash,
            "Google Photos metadata may contain location clues",
            "Photo metadata sidecar files in the Takeout archive include geolocation-like fields.",
            {"sample_files": geo_hits, "sample_count": len(geo_hits)},
            "high",
            86,
            (
                "Review shared albums and public images. Strip metadata before posting images "
                "where location privacy matters."
            ),
            ["google", "takeout", "photos", "location", "images"],
        )
    ]


def _shared_link_findings(
    archive: zipfile.ZipFile,
    names: list[str],
    archive_hash: str,
) -> list[PluginFinding]:
    candidate_names = [
        name
        for name in names
        if ("drive" in name.lower() or "shared" in name.lower())
        and name.lower().endswith((".json", ".html", ".csv", ".txt"))
    ]
    hits: list[str] = []
    for name in candidate_names[:250]:
        text = _read_text(archive, name)
        if "anyone with the link" in text.lower() or "shared" in text.lower():
            hits.append(name)
            if len(hits) >= 20:
                break
    if not hits:
        return []
    return [
        _finding(
            archive_hash,
            "Google Takeout includes shared-link metadata",
            "Drive or shared-content metadata suggests there may be public or link-shared files.",
            {"sample_files": hits, "sample_count": len(hits)},
            "medium",
            78,
            (
                "Review Google Drive sharing settings and revoke public links that are "
                "no longer needed."
            ),
            ["google", "takeout", "shared-links"],
        )
    ]


def _finding(
    archive_hash: str,
    title: str,
    description: str,
    evidence: dict[str, object],
    severity: str,
    confidence: int,
    remediation: str,
    tags: list[str],
) -> PluginFinding:
    return PluginFinding(
        source_plugin=TAKEOUT_SOURCE,
        input_type="google_takeout",
        input_value_hash=archive_hash,
        title=title,
        description=description,
        url=None,
        evidence=evidence,
        confidence=confidence,
        severity=severity,
        remediation=remediation,
        tags=tags,
    )


def _read_text(archive: zipfile.ZipFile, name: str, limit: int = 500_000) -> str:
    try:
        with archive.open(name) as handle:
            return handle.read(limit).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _read_json(archive: zipfile.ZipFile, name: str) -> Any:
    text = _read_text(archive, name)
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _has_geo(value: Any) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            key_lower = str(key).lower()
            if key_lower in {"geodata", "geodataexif", "latitude", "longitude"}:
                return True
            if _has_geo(nested):
                return True
    if isinstance(value, list):
        return any(_has_geo(item) for item in value[:50])
    return False

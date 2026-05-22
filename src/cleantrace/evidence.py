from __future__ import annotations

import json
import re
from pathlib import Path

from cleantrace.models import Profile
from cleantrace.plugins.base import PluginFinding
from cleantrace.security import CryptoBox, redact_text, stable_hash

SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\bpassword\s*[:=]\s*\S+"),
    re.compile(r"(?i)\b(?:api[_-]?key|token|secret)\s*[:=]\s*[A-Za-z0-9_.=-]{8,}"),
    re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}"),
    re.compile(r"\b[a-f0-9]{32,128}\b", re.IGNORECASE),
]


def import_evidence_file(
    profile: Profile,
    crypto: CryptoBox,
    path: Path,
    *,
    status: str = "needs review",
    attach_finding: str | None = None,
) -> PluginFinding:
    if not path.exists():
        raise FileNotFoundError(path)
    suffix = path.suffix.lower()
    if suffix in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
        return image_evidence_finding(profile, path, status, attach_finding)
    text = path.read_text(encoding="utf-8", errors="replace")[:1_000_000]
    if suffix == ".json":
        text = normalise_json_text(text)
    return text_evidence_finding(profile, crypto, path, text, status, attach_finding)


def normalise_json_text(text: str) -> str:
    try:
        return json.dumps(json.loads(text), indent=2, sort_keys=True)
    except json.JSONDecodeError:
        return text


def contains_sensitive_dump(text: str) -> bool:
    return any(pattern.search(text) for pattern in SECRET_PATTERNS)


def redact_import_text(text: str) -> str:
    redacted = redact_text(text)
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub("[redacted-sensitive-value]", redacted)
    return redacted


def text_evidence_finding(
    profile: Profile,
    crypto: CryptoBox,
    path: Path,
    text: str,
    status: str,
    attach_finding: str | None,
) -> PluginFinding:
    identifiers = [
        profile.legal_name(crypto) or "",
        *profile.usernames(crypto),
        *profile.emails(crypto),
        *profile.phones(crypto),
    ]
    matches = [value for value in identifiers if value and value.lower() in text.lower()]
    sensitive_dump = contains_sensitive_dump(text)
    snippet_source = redact_import_text(text[:1000])
    return PluginFinding(
        source_plugin="manual_evidence",
        input_type="evidence_import",
        input_value_hash=stable_hash(str(path.resolve())),
        title=f"Manual evidence imported: {path.name}",
        description=(
            "User-provided evidence was converted into local metadata. "
            "CleanTrace does not store passwords, tokens, private keys, or raw leaked rows."
        ),
        url=None,
        evidence={
            "file_name": path.name,
            "file_type": path.suffix.lower().lstrip(".") or "text",
            "status": status,
            "attached_to": attach_finding or "",
            "matched_identifiers": [stable_hash(value) for value in matches],
            "redacted_snippet": snippet_source[:500],
            "sensitive_values_detected": sensitive_dump,
            "raw_sensitive_values_stored": False,
        },
        confidence=80 if matches else 50,
        severity="medium" if sensitive_dump else "low",
        remediation=(
            "Review this evidence manually. If it contains leaked records or secrets, "
            "remove the raw file from local storage and act on account hardening steps "
            "without importing the secret values."
        ),
        tags=["manual-evidence", status.replace(" ", "-"), "metadata-only"],
    )


def image_evidence_finding(
    profile: Profile,
    path: Path,
    status: str,
    attach_finding: str | None,
) -> PluginFinding:
    return PluginFinding(
        source_plugin="manual_evidence",
        input_type="evidence_import",
        input_value_hash=stable_hash(str(path.resolve())),
        title=f"Manual screenshot evidence imported: {path.name}",
        description=(
            "Screenshot evidence is recorded as local metadata only; "
            "image analysis is not performed."
        ),
        url=None,
        evidence={
            "profile_slug": profile.slug,
            "file_name": path.name,
            "file_type": path.suffix.lower().lstrip("."),
            "status": status,
            "attached_to": attach_finding or "",
            "raw_sensitive_values_stored": False,
        },
        confidence=40,
        severity="info",
        remediation="Review the screenshot manually and attach cleanup/removal status as needed.",
        tags=["manual-evidence", status.replace(" ", "-"), "metadata-only"],
    )

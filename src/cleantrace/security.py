from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from typing import Any

from cryptography.fernet import Fernet

from cleantrace.paths import ensure_app_dirs, key_path

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d\s().-]{7,}\d)(?!\w)")
TOKEN_RE = re.compile(r"(?i)\b(?:gh[pousr]_|xox[baprs]-|sk-|ya29\.|token=)[A-Za-z0-9_.=-]{8,}")


def normalise_identifier(value: str) -> str:
    return " ".join(value.strip().lower().split())


def stable_hash(value: str) -> str:
    return hashlib.sha256(normalise_identifier(value).encode("utf-8")).hexdigest()


def fingerprint(value: str) -> str:
    digest = stable_hash(value)
    return f"{digest[:8]}...{digest[-6:]}"


def redact(value: str | None, show_sensitive: bool = False) -> str:
    if value is None:
        return ""
    if show_sensitive:
        return value
    if "@" in value:
        local, _, domain = value.partition("@")
        return f"{local[:2]}***@{domain[:2]}***" if domain else "***"
    digits = re.sub(r"\D", "", value)
    if len(digits) >= 8:
        return f"***{digits[-4:]}"
    if len(value) <= 3:
        return "***"
    return f"{value[:2]}***{value[-1:]}"


def redact_text(text: str, show_sensitive: bool = False) -> str:
    if show_sensitive:
        return text
    text = EMAIL_RE.sub("[redacted-email]", text)
    text = PHONE_RE.sub("[redacted-phone]", text)
    return TOKEN_RE.sub("[redacted-token]", text)


class CryptoBox:
    def __init__(self, key: bytes | None = None) -> None:
        self._fernet = Fernet(key or load_or_create_key())

    def encrypt_text(self, value: str | None) -> str | None:
        if value is None:
            return None
        return self._fernet.encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt_text(self, value: str | None) -> str | None:
        if not value:
            return None
        return self._fernet.decrypt(value.encode("ascii")).decode("utf-8")

    def encrypt_json(self, value: Any) -> str:
        return self.encrypt_text(json.dumps(value, sort_keys=True)) or ""

    def decrypt_json(self, value: str | None, default: Any) -> Any:
        if not value:
            return default
        try:
            raw = self.decrypt_text(value)
            return json.loads(raw or "")
        except Exception:
            return default


def load_or_create_key() -> bytes:
    ensure_app_dirs()
    target = key_path()
    if target.exists():
        return target.read_bytes().strip()
    key = Fernet.generate_key()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    fd = os.open(target, flags, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(key)
    return key


def derive_test_key(seed: str = "cleantrace-test-key") -> bytes:
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)

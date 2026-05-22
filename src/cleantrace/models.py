from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any, cast

from sqlmodel import Field, SQLModel

from cleantrace.phone import load_phone_metadata
from cleantrace.security import CryptoBox, stable_hash


def utc_now() -> datetime:
    return datetime.now(UTC)


class Profile(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    slug: str = Field(index=True, unique=True)
    legal_name_enc: str | None = None
    display_names_enc: str = ""
    usernames_enc: str = ""
    emails_enc: str = ""
    phones_enc: str = ""
    location_enc: str | None = None
    domains_enc: str = ""
    social_links_enc: str = ""
    role_notes_enc: str | None = None
    username_hashes_json: str = "[]"
    email_hashes_json: str = "[]"
    phone_hashes_json: str = "[]"
    risk_sensitivity: str = "normal"
    consent: bool = False
    consent_timestamp: datetime | None = None
    created_at: datetime = Field(default_factory=utc_now)

    def public_dict(self, crypto: CryptoBox, show_sensitive: bool = False) -> dict[str, Any]:
        from cleantrace.security import redact

        legal_name = crypto.decrypt_text(self.legal_name_enc)
        display_names = crypto.decrypt_json(self.display_names_enc, [])
        usernames = crypto.decrypt_json(self.usernames_enc, [])
        emails = crypto.decrypt_json(self.emails_enc, [])
        phones = load_phone_metadata(crypto, self.phones_enc)
        location = crypto.decrypt_text(self.location_enc)
        domains = crypto.decrypt_json(self.domains_enc, [])
        return {
            "id": self.id,
            "slug": self.slug,
            "legal_name": redact(legal_name, show_sensitive),
            "display_names": [redact(v, show_sensitive) for v in display_names],
            "usernames": [redact(v, show_sensitive) for v in usernames],
            "emails": [redact(v, show_sensitive) for v in emails],
            "phones": [redact(phone.e164, show_sensitive) for phone in phones],
            "location": redact(location, show_sensitive),
            "domains": [redact(v, show_sensitive) for v in domains],
            "risk_sensitivity": self.risk_sensitivity,
            "consent": self.consent,
            "consent_timestamp": self.consent_timestamp,
        }

    def usernames(self, crypto: CryptoBox) -> list[str]:
        return list(crypto.decrypt_json(self.usernames_enc, []))

    def emails(self, crypto: CryptoBox) -> list[str]:
        return list(crypto.decrypt_json(self.emails_enc, []))

    def phones(self, crypto: CryptoBox) -> list[str]:
        return [phone.e164 for phone in load_phone_metadata(crypto, self.phones_enc)]

    def phone_metadata(self, crypto: CryptoBox) -> list[Any]:
        return load_phone_metadata(crypto, self.phones_enc)

    def domains(self, crypto: CryptoBox) -> list[str]:
        return list(crypto.decrypt_json(self.domains_enc, []))

    def legal_name(self, crypto: CryptoBox) -> str | None:
        return crypto.decrypt_text(self.legal_name_enc)


def build_profile(
    *,
    slug: str,
    crypto: CryptoBox,
    legal_name: str | None = None,
    display_names: list[str] | None = None,
    usernames: list[str] | None = None,
    emails: list[str] | None = None,
    phones: list[str] | None = None,
    location: str | None = None,
    domains: list[str] | None = None,
    social_links: list[str] | None = None,
    role_notes: str | None = None,
    risk_sensitivity: str = "normal",
    consent: bool = False,
) -> Profile:
    from cleantrace.phone import dump_phone_metadata, parse_phone_number

    usernames = usernames or []
    emails = emails or []
    phones = phones or []
    phone_metadata = []
    for phone in phones:
        try:
            phone_metadata.append(parse_phone_number(phone))
        except Exception:
            continue
    return Profile(
        slug=slug,
        legal_name_enc=crypto.encrypt_text(legal_name),
        display_names_enc=crypto.encrypt_json(display_names or []),
        usernames_enc=crypto.encrypt_json(usernames),
        emails_enc=crypto.encrypt_json(emails),
        phones_enc=crypto.encrypt_text(dump_phone_metadata(phone_metadata)) or "",
        location_enc=crypto.encrypt_text(location),
        domains_enc=crypto.encrypt_json(domains or []),
        social_links_enc=crypto.encrypt_json(social_links or []),
        role_notes_enc=crypto.encrypt_text(role_notes),
        username_hashes_json=json.dumps([stable_hash(v) for v in usernames]),
        email_hashes_json=json.dumps([stable_hash(v) for v in emails]),
        phone_hashes_json=json.dumps([stable_hash(v.e164) for v in phone_metadata]),
        risk_sensitivity=risk_sensitivity,
        consent=consent,
        consent_timestamp=utc_now() if consent else None,
    )


class Finding(SQLModel, table=True):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex, primary_key=True)
    profile_id: int = Field(index=True)
    source_plugin: str = Field(index=True)
    input_type: str = Field(index=True)
    input_value_hash: str = Field(index=True)
    title: str
    description: str
    url: str | None = None
    evidence_json: str = "{}"
    confidence: int = Field(default=0, ge=0, le=100)
    severity: str = "info"
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    remediation: str
    false_positive: bool = False
    tags_json: str = "[]"

    @property
    def evidence(self) -> dict[str, Any]:
        return cast("dict[str, Any]", json.loads(self.evidence_json or "{}"))

    @property
    def tags(self) -> list[str]:
        return list(json.loads(self.tags_json or "[]"))


class LinkedAccount(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    profile_id: int = Field(index=True)
    provider: str = Field(index=True)
    account_id_hash: str = Field(index=True)
    display_name_enc: str | None = None
    username_enc: str | None = None
    token_enc: str | None = None
    public_only: bool = True
    scopes_json: str = "[]"
    linked_at: datetime = Field(default_factory=utc_now)
    last_scanned_at: datetime | None = None

    def username(self, crypto: CryptoBox) -> str | None:
        return crypto.decrypt_text(self.username_enc)

    def token(self, crypto: CryptoBox) -> str | None:
        return crypto.decrypt_text(self.token_enc)

    @property
    def scopes(self) -> list[str]:
        return list(json.loads(self.scopes_json or "[]"))


class RemovalRequest(SQLModel, table=True):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex, primary_key=True)
    profile_id: int = Field(index=True)
    finding_id: str | None = Field(default=None, index=True)
    broker_name: str | None = Field(default=None, index=True)
    request_type: str = "erasure"
    status: str = Field(default="drafted", index=True)
    recipient: str | None = None
    subject: str
    body_enc: str
    notes: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    def body(self, crypto: CryptoBox) -> str:
        return crypto.decrypt_text(self.body_enc) or ""

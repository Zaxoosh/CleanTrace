from __future__ import annotations

import json
from dataclasses import asdict, dataclass

import phonenumbers
from phonenumbers import PhoneNumberFormat, region_code_for_country_code

from cleantrace.security import CryptoBox, stable_hash

DEFAULT_REGION = "GB"


@dataclass(frozen=True)
class PhoneMetadata:
    e164: str
    national: str
    international: str
    region_code: str
    country_calling_code: int
    is_valid: bool
    raw_hash: str

    @property
    def national_format(self) -> str:
        return self.national

    @property
    def international_format(self) -> str:
        return self.international


def resolve_region(country: str | None) -> str:
    if not country:
        return DEFAULT_REGION
    value = country.strip()
    if not value:
        return DEFAULT_REGION
    if value.startswith("+"):
        try:
            region = region_code_for_country_code(int(value[1:]))
        except ValueError:
            region = None
        return region or DEFAULT_REGION
    upper = value.upper()
    if len(upper) == 2 and upper.isalpha():
        return upper
    common = {
        "united kingdom": "GB",
        "uk": "GB",
        "great britain": "GB",
        "united states": "US",
        "usa": "US",
        "america": "US",
        "germany": "DE",
        "france": "FR",
        "spain": "ES",
        "australia": "AU",
        "canada": "CA",
    }
    return common.get(value.lower(), DEFAULT_REGION)


def parse_phone_number(value: str, country: str | None = None) -> PhoneMetadata:
    region = resolve_region(country)
    try:
        parsed = phonenumbers.parse(value, region)
    except phonenumbers.NumberParseException as exc:
        raise ValueError(f"Could not parse phone number for region {region}: {value}") from exc
    detected_region = phonenumbers.region_code_for_number(parsed) or region
    return PhoneMetadata(
        e164=phonenumbers.format_number(parsed, PhoneNumberFormat.E164),
        national=phonenumbers.format_number(parsed, PhoneNumberFormat.NATIONAL),
        international=phonenumbers.format_number(parsed, PhoneNumberFormat.INTERNATIONAL),
        region_code=detected_region,
        country_calling_code=int(parsed.country_code or 0),
        is_valid=phonenumbers.is_valid_number(parsed),
        raw_hash=stable_hash(value),
    )


def phone_search_variants(metadata: PhoneMetadata) -> list[str]:
    no_space_national = "".join(ch for ch in metadata.national if ch.isdigit())
    compact_e164 = metadata.e164
    variants = [
        compact_e164,
        metadata.national,
        no_space_national,
        metadata.international,
        metadata.international.replace(" ", ""),
    ]
    deduped: list[str] = []
    for variant in variants:
        if variant and variant not in deduped:
            deduped.append(variant)
    return deduped


def load_phone_metadata(crypto: CryptoBox, encrypted: str) -> list[PhoneMetadata]:
    raw = crypto.decrypt_json(encrypted, [])
    results: list[PhoneMetadata] = []
    for item in raw:
        if isinstance(item, dict) and item.get("e164"):
            results.append(
                PhoneMetadata(
                    e164=str(item["e164"]),
                    national=str(item.get("national") or item["e164"]),
                    international=str(item.get("international") or item["e164"]),
                    region_code=str(item.get("region_code") or DEFAULT_REGION),
                    country_calling_code=int(item.get("country_calling_code") or 0),
                    is_valid=bool(item.get("is_valid", False)),
                    raw_hash=str(item.get("raw_hash") or stable_hash(str(item["e164"]))),
                )
            )
        elif isinstance(item, str):
            try:
                results.append(parse_phone_number(item))
            except Exception:
                continue
    return results


def dump_phone_metadata(items: list[PhoneMetadata]) -> str:
    return json.dumps([asdict(item) for item in items], sort_keys=True)

from __future__ import annotations

import hashlib

import httpx

PWNED_PASSWORDS_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
USER_AGENT = "CleanTrace/0.2 local-first self-assessment"


def sha1_password_parts(password: str) -> tuple[str, str]:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


def parse_range_count(body: str, suffix: str) -> int:
    suffix = suffix.upper()
    for line in body.splitlines():
        candidate, _, count = line.partition(":")
        if candidate.upper() == suffix:
            return int(count)
    return 0


async def check_pwned_password(password: str) -> int:
    prefix, suffix = sha1_password_parts(password)
    async with httpx.AsyncClient(timeout=10.0, headers={"User-Agent": USER_AGENT}) as client:
        response = await client.get(PWNED_PASSWORDS_RANGE_URL.format(prefix=prefix))
    response.raise_for_status()
    return parse_range_count(response.text, suffix)

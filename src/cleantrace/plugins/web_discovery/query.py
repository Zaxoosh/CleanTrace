from __future__ import annotations

from cleantrace.models import Profile
from cleantrace.phone import phone_search_variants
from cleantrace.plugins.web_discovery.models import SearchQuery
from cleantrace.security import CryptoBox


def generate_queries(
    profile: Profile,
    crypto: CryptoBox,
    *,
    query_set: str = "identity",
    depth: str = "quick",
) -> list[SearchQuery]:
    legal_name = profile.legal_name(crypto)
    public = profile.public_dict(crypto, show_sensitive=True)
    display_names = [str(item) for item in public.get("display_names", [])]
    usernames = profile.usernames(crypto)
    emails = profile.emails(crypto)
    phones = profile.phone_metadata(crypto)
    domains = profile.domains(crypto)
    location = str(public.get("location") or "")
    role_notes = str(crypto.decrypt_text(profile.role_notes_enc) or "")
    social_links = [str(item) for item in crypto.decrypt_json(profile.social_links_enc, [])]
    queries: list[SearchQuery] = []

    def add(query: str, kind: str, identifiers: list[str]) -> None:
        query = " ".join(query.split())
        if query and query not in {item.query for item in queries}:
            queries.append(SearchQuery(query=query, query_set=kind, identifiers=identifiers))

    names = [item for item in [legal_name, *display_names] if item]
    if query_set in {"identity", "all"}:
        for name in names:
            add(f'"{name}"', "identity", [name])
            if location:
                add(f'"{name}" "{location}"', "identity", [name, location])
            if role_notes:
                add(f'"{name}" "{role_notes}"', "identity", [name, role_notes])
            for domain in domains[:3]:
                add(f'"{domain}" "{name}"', "identity", [domain, name])
    if query_set in {"username", "all", "identity"}:
        for username in usernames:
            add(f'"{username}"', "username", [username])
            if legal_name:
                add(f'"{username}" "{legal_name}"', "username", [username, legal_name])
            add(f'site:reddit.com "{username}"', "username", [username])
            add(f'site:github.com "{username}"', "username", [username])
    if query_set in {"email", "all"}:
        for email in emails:
            add(f'"{email}"', "email", [email])
            add(f'site:github.com "{email}"', "email", [email])
            add(f'site:pastebin.com "{email}"', "email", [email])
    if query_set in {"phone", "all"}:
        for phone in phones:
            for variant in phone_search_variants(phone):
                add(f'"{variant}"', "phone", [variant])
    if query_set in {"identity", "all"}:
        for link in social_links[:5]:
            add(f'"{link}"', "identity", [link])

    limits = {"quick": 8, "standard": 25, "deep": 60}
    return queries[: limits.get(depth, 8)]

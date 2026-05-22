from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Any

import httpx

from cleantrace.plugins.base import PluginFinding, PluginMeta, ScanTarget
from cleantrace.security import stable_hash

GITHUB_API = "https://api.github.com"
GITHUB_USER_AGENT = "CleanTrace/0.2 local-first self-assessment"
SECRET_PATTERNS = {
    "generic_api_key": re.compile(
        r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"][A-Za-z0-9_.=-]{16,}"
    ),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
}


@dataclass(frozen=True)
class GitHubAccountInput:
    username: str
    token: str | None = None
    include_private: bool = False


class GitHubConnectorPlugin:
    meta = PluginMeta(
        name="github_connector",
        description="Scans a linked GitHub account through official GitHub APIs.",
        input_types=["github_account"],
        risk_level="API",
        needs_api_key=False,
        uses_scraping=False,
        enabled_by_default=True,
        rate_limit_per_minute=30,
        tags=["github", "dev", "professional"],
    )

    def __init__(self, timeout: float = 15.0) -> None:
        self.timeout = timeout

    async def run(self, target: ScanTarget) -> list[PluginFinding]:
        token_value = target.options.get("token")
        account = GitHubAccountInput(
            username=str(target.options.get("username") or target.value),
            token=token_value if isinstance(token_value, str) else None,
            include_private=bool(target.options.get("include_private", False)),
        )
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": GITHUB_USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if account.token:
            headers["Authorization"] = f"Bearer {account.token}"
        async with httpx.AsyncClient(timeout=self.timeout, headers=headers) as client:
            findings = await self._profile_findings(client, target, account)
            repos = await self._fetch_repos(client, account)
            findings.extend(await self._repo_findings(client, target, account, repos))
            return findings

    async def _profile_findings(
        self,
        client: httpx.AsyncClient,
        target: ScanTarget,
        account: GitHubAccountInput,
    ) -> list[PluginFinding]:
        response = await client.get(f"{GITHUB_API}/users/{account.username}")
        response.raise_for_status()
        profile = response.json()
        findings: list[PluginFinding] = []
        if profile.get("email"):
            findings.append(
                github_finding(
                    target,
                    "Public email on GitHub profile",
                    "The linked GitHub public profile exposes an email address.",
                    str(profile.get("html_url") or ""),
                    {"field": "email", "email_hash": stable_hash(str(profile["email"]))},
                    "medium",
                    92,
                    (
                        "Remove the public email from the GitHub profile or use a "
                        "privacy-preserving alias."
                    ),
                    ["github", "email", "professional"],
                )
            )
        if profile.get("location"):
            findings.append(
                github_finding(
                    target,
                    "Public location on GitHub profile",
                    "The linked GitHub public profile exposes a location field.",
                    str(profile.get("html_url") or ""),
                    {"field": "location", "value_hash": stable_hash(str(profile["location"]))},
                    "medium",
                    88,
                    (
                        "Consider removing precise location details from GitHub "
                        "if they raise your risk."
                    ),
                    ["github", "location", "professional"],
                )
            )
        if profile.get("blog"):
            findings.append(
                github_finding(
                    target,
                    "Linked website on GitHub profile",
                    (
                        "The GitHub profile links to an external website, "
                        "which may connect identities."
                    ),
                    str(profile.get("html_url") or ""),
                    {"field": "blog", "url": str(profile["blog"])},
                    "low",
                    84,
                    (
                        "Review whether the linked website reveals personal identifiers "
                        "or home location."
                    ),
                    ["github", "domain", "identity-link"],
                )
            )
        return findings

    async def _fetch_repos(
        self,
        client: httpx.AsyncClient,
        account: GitHubAccountInput,
    ) -> list[dict[str, Any]]:
        if account.token and account.include_private:
            response = await client.get(
                f"{GITHUB_API}/user/repos",
                params={"per_page": 50, "sort": "updated", "affiliation": "owner"},
            )
        else:
            response = await client.get(
                f"{GITHUB_API}/users/{account.username}/repos",
                params={"per_page": 50, "sort": "updated", "type": "owner"},
            )
        response.raise_for_status()
        return list(response.json())

    async def _repo_findings(
        self,
        client: httpx.AsyncClient,
        target: ScanTarget,
        account: GitHubAccountInput,
        repos: list[dict[str, Any]],
    ) -> list[PluginFinding]:
        findings: list[PluginFinding] = []
        for repo in repos[:25]:
            if repo.get("fork"):
                continue
            repo_url = str(repo.get("html_url") or "")
            if repo.get("private"):
                continue
            if not repo.get("archived") and repo.get("pushed_at") is None:
                continue
            repo_name = str(repo.get("name") or "")
            findings.extend(
                await self._contents_findings(client, target, account, repo_name, repo_url)
            )
        return findings

    async def _contents_findings(
        self,
        client: httpx.AsyncClient,
        target: ScanTarget,
        account: GitHubAccountInput,
        repo_name: str,
        repo_url: str,
    ) -> list[PluginFinding]:
        findings: list[PluginFinding] = []
        response = await client.get(f"{GITHUB_API}/repos/{account.username}/{repo_name}/contents")
        if response.status_code in {403, 404}:
            return findings
        response.raise_for_status()
        for item in response.json()[:40]:
            name = str(item.get("name") or "")
            download_url = item.get("download_url")
            if name.lower() in {".env", "config.json", "settings.py", "credentials.json"}:
                findings.append(
                    github_finding(
                        target,
                        f"Potentially sensitive config file in {repo_name}",
                        "A public repository contains a filename commonly associated with secrets.",
                        str(item.get("html_url") or repo_url),
                        {"repo": repo_name, "file": name},
                        "high" if name.lower() in {".env", "credentials.json"} else "medium",
                        72,
                        (
                            "Review the file locally. Rotate any exposed secrets and remove "
                            "sensitive files from history."
                        ),
                        ["github", "secret", "config"],
                    )
                )
            if not isinstance(download_url, str) or not should_sample_file(name):
                continue
            file_response = await client.get(download_url)
            if file_response.status_code != 200:
                continue
            text = decode_content(file_response.content)
            for pattern_name, pattern in SECRET_PATTERNS.items():
                if pattern.search(text):
                    findings.append(
                        github_finding(
                            target,
                            f"Possible secret pattern in {repo_name}",
                            (
                                "A safe local regex check found a possible secret in a "
                                "public repository."
                            ),
                            str(item.get("html_url") or repo_url),
                            {"repo": repo_name, "file": name, "pattern": pattern_name},
                            "critical",
                            78,
                            (
                                "Review the file locally, revoke exposed credentials, "
                                "and remove secrets from history."
                            ),
                            ["github", "secret", "credential"],
                        )
                    )
                    break
        return findings


def should_sample_file(name: str) -> bool:
    lower = name.lower()
    return lower in {".env", "config.json", "settings.py", "credentials.json"} or lower.endswith(
        (".yml", ".yaml", ".toml", ".ini")
    )


def decode_content(raw: bytes) -> str:
    try:
        return raw.decode("utf-8", errors="ignore")[:200_000]
    except Exception:
        return base64.b64encode(raw[:512]).decode("ascii")


def github_finding(
    target: ScanTarget,
    title: str,
    description: str,
    url: str | None,
    evidence: dict[str, object],
    severity: str,
    confidence: int,
    remediation: str,
    tags: list[str],
) -> PluginFinding:
    return PluginFinding(
        source_plugin="github_connector",
        input_type=target.input_type,
        input_value_hash=target.value_hash,
        title=title,
        description=description,
        url=url,
        evidence=evidence,
        confidence=confidence,
        severity=severity,
        remediation=remediation,
        tags=tags,
    )

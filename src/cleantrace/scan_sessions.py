from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

from cleantrace.paths import ensure_app_dirs, scan_sessions_path


@dataclass
class ScanSession:
    scan_session_id: str
    profile_id: int
    requested_modules: list[str]
    completed_modules: list[str] = field(default_factory=list)
    skipped_modules: list[str] = field(default_factory=list)
    pending_setup_modules: list[str] = field(default_factory=list)
    start_time: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    resume_token: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    depth: str = "quick"
    status: str = "active"


def load_sessions() -> list[ScanSession]:
    ensure_app_dirs()
    path = scan_sessions_path()
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    sessions: list[ScanSession] = []
    for item in payload:
        if isinstance(item, dict) and item.get("scan_session_id"):
            sessions.append(ScanSession(**item))
    return sessions


def save_sessions(sessions: list[ScanSession]) -> None:
    ensure_app_dirs()
    scan_sessions_path().write_text(
        json.dumps([asdict(session) for session in sessions], indent=2, sort_keys=True),
        encoding="utf-8",
    )


def create_session(profile_id: int, modules: list[str], depth: str) -> ScanSession:
    session = ScanSession(
        scan_session_id=uuid.uuid4().hex,
        profile_id=profile_id,
        requested_modules=modules,
        depth=depth,
    )
    sessions = load_sessions()
    sessions.append(session)
    save_sessions(sessions)
    return session


def update_session(session: ScanSession) -> None:
    sessions = load_sessions()
    replaced = False
    for index, existing in enumerate(sessions):
        if existing.scan_session_id == session.scan_session_id:
            sessions[index] = session
            replaced = True
            break
    if not replaced:
        sessions.append(session)
    save_sessions(sessions)


def latest_resumable_session() -> ScanSession | None:
    sessions = [session for session in load_sessions() if session.status == "active"]
    return sessions[-1] if sessions else None


def get_session(session_id: str) -> ScanSession | None:
    for session in load_sessions():
        if session.scan_session_id.startswith(session_id) or session.resume_token == session_id:
            return session
    return None


def cancel_session(session_id: str) -> bool:
    session = get_session(session_id)
    if not session:
        return False
    session.status = "cancelled"
    update_session(session)
    return True
